/**
 * CipherPolAgent — autonomous agent with private x402 payments
 *
 * The correct privacy-preserving payment flow:
 *
 *   1. Agent pre-deposits funds into Ekubo Privacy Pool
 *      → gets a Note (secret, nullifier, commitment)
 *      → commitment is recorded on-chain, depositor address is visible
 *
 *   2. Agent waits for deposit confirmation (~30-90s on Starknet)
 *      → calls findNoteInTree() to resolve the note's leaf index
 *
 *   3. When making an x402 payment, agent generates ZK proof CLIENT-SIDE:
 *      → fetches pool state (all Deposit events) to rebuild Merkle tree
 *      → builds Merkle proof for its deposit (leaf at known index)
 *      → calls snarkjs.groth16.fullProve() with:
 *           private: (secret, nullifier, pathElements, pathIndices)
 *           public:  recipient = API server address, amount, root
 *      → sends ONLY { zkProof, nullifierHash, publicInputs } — NO txHash, NO secret
 *
 *   4. Server validates public inputs, tracks nullifierHash, submits withdrawal
 *      → server NEVER sees (secret, nullifier) or which deposit this corresponds to
 *
 * Privacy properties (honest assessment):
 *   - Depositor's address IS visible when deposit() is called on-chain
 *   - The deposit → withdrawal LINK is hidden by the ZK proof
 *   - Meaningful privacy requires an anonymity set of dozens+ of deposits
 *   - Don't withdraw immediately after depositing (trivial to correlate)
 *
 * See docs/THREAT_MODEL.md for the complete analysis.
 */

import { Account } from 'starknet';
import {
  CipherPolConfig,
  Note,
  PaymentIntent,
  PrivacyScore,
  X402PaymentProof,
} from './types.js';
import { IPrivacyAdapter } from './types.js';
import { PrivacyPoolsAdapter } from './adapters/privacy-pools.js';
import { STRK20Adapter } from './adapters/strk20.js';
import {
  parseChallenge,
  buildPaymentHeader,
  X402_SCHEME,
} from './x402.js';
import type { ProverArtifacts } from './prover.js';
import {
  createAgentManifest,
  manifestToDataURI,
  generatePaymentReceipt,
  type AgentReceipt,
} from './erc8004.js';

export class CipherPolAgent {
  private readonly adapter: IPrivacyAdapter;
  private readonly config: Required<CipherPolConfig>;

  constructor(config: CipherPolConfig, account?: Account) {
    this.config = {
      starknetRpcUrl: 'https://starknet-mainnet.public.blastapi.io',
      litNetwork: 'datil',
      storachaEmail: '',
      settlementFeeBps: 10,
      ...config,
    } as Required<CipherPolConfig>;

    if (config.adapter === 'strk20') {
      this.adapter = new STRK20Adapter();
    } else {
      if (!account) throw new Error('PrivacyPoolsAdapter requires an Account instance');
      this.adapter = new PrivacyPoolsAdapter(
        account,
        undefined,
        this.config.starknetRpcUrl
      );
    }
  }

  /**
   * Deposit funds into the privacy pool.
   *
   * Returns a Note with leafIndex=-1. Call findNoteInTree() after the deposit
   * is confirmed on-chain (~30-90s) before using the note for payments.
   *
   * The Note MUST be stored securely. Without it, deposited funds are lost.
   * Do NOT send the Note to any server — the (secret, nullifier) are private.
   */
  async deposit(amount: bigint, token: string): Promise<{ txHash: string; note: Note }> {
    return this.adapter.deposit(amount, token);
  }

  /**
   * Wait for a deposit to appear in the pool and resolve its leaf index.
   *
   * Polls the pool's Deposit events until the note's commitment appears.
   * Returns the updated note with leafIndex set.
   *
   * @param note       The note from deposit()
   * @param maxWaitMs  Max wait time (default: 120s)
   * @param pollMs     Poll interval (default: 5s)
   */
  async findNoteInTree(
    note: Note,
    maxWaitMs = 120_000,
    pollMs = 5_000
  ): Promise<Note> {
    if (!(this.adapter instanceof PrivacyPoolsAdapter)) {
      throw new Error('findNoteInTree is only available for PrivacyPoolsAdapter');
    }

    const deadline = Date.now() + maxWaitMs;

    while (Date.now() < deadline) {
      const leafIndex = await this.adapter.findNoteInTree(note);
      if (leafIndex !== -1) {
        return { ...note, leafIndex };
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }

    throw new Error(
      `Deposit not found in pool after ${maxWaitMs}ms. ` +
      `depositTxHash=${note.depositTxHash}. ` +
      `Either the transaction is still pending, or the pool address is wrong.`
    );
  }

  /**
   * Pay an x402 API endpoint using a pre-deposited note.
   *
   * This is the privacy-correct flow:
   * 1. Probe the endpoint — expect 402 challenge
   * 2. Generate Groth16 ZK proof client-side using the note
   * 3. Send only { zkProof, nullifierHash, publicInputs } — no txHash, no secret
   * 4. Retry with X-Payment-Proof header
   *
   * Requires:
   * - note.leafIndex must be resolved (call findNoteInTree() first)
   * - Circuit artifacts (.wasm and .zkey) from the trusted setup
   *   Run: cd circuits && npm run setup
   *
   * Privacy guarantee:
   * - Server learns: amount + nullifierHash (public signals)
   * - Server does NOT learn: depositor address, which deposit, secret, nullifier
   *
   * @param url       The API endpoint URL
   * @param note      Pre-deposited note (leafIndex must be != -1)
   * @param amount    Amount to pay (must be <= note.amount)
   * @param artifacts Paths to circuit .wasm and .zkey files
   * @param init      Optional fetch init (headers, body, etc.)
   */
  async pay(
    url: string,
    note: Note,
    amount: bigint,
    artifacts: ProverArtifacts,
    init?: RequestInit
  ): Promise<Response> {
    if (note.leafIndex === -1) {
      throw new Error(
        'Note has not been resolved yet (leafIndex=-1). ' +
        'Call findNoteInTree() after the deposit is confirmed on-chain.'
      );
    }

    if (note.spent) {
      throw new Error('Note is already spent. Each note can only be used once.');
    }

    // 1. Probe the endpoint — should return 402.
    //
    // NOTE: the probe sends the full body (if any) once before proof generation,
    // and again with the payment header. Two consequences:
    //   a) The server receives the body on the 402 response path — most servers
    //      ignore it, but it is sent. If the body is privacy-sensitive, consider
    //      using a separate probe request (no body) first.
    //   b) If init.body is a ReadableStream (consumed-once), the second fetch
    //      will send an empty body. Use a Buffer, string, or JSON string body
    //      if the body must be sent on the paid request.
    const probe = await fetch(url, init);

    if (probe.status !== 402) {
      // Not payment-gated; return as-is
      return probe;
    }

    const challenge = parseChallenge(probe);
    if (!challenge) {
      throw new Error(`402 response missing valid Cipher Pol payment challenge from ${url}`);
    }

    // 2. Generate Groth16 proof CLIENT-SIDE
    // The proof commits to: recipient = challenge.payTo (API server address)
    // The proof reveals: nullifierHash, amount, root — nothing else
    const paymentProof = await (this.adapter as PrivacyPoolsAdapter).generatePaymentProof(
      note,
      challenge.payTo,
      amount,
      artifacts
    );

    // Attach ERC-8004 agent identity to proof (if configured).
    //
    // PRIVACY WARNING: if ERC8004Config includes starknetAddress, that address
    // is embedded in the agentURI data-URI and sent to the server in the
    // X-Payment-Proof header. The server will learn which Starknet address made
    // this payment — defeating the ZK unlinking. Only set starknetAddress if
    // you are intentionally sacrificing payment privacy for agent identity.
    if (this.config.erc8004) {
      const manifest = createAgentManifest(
        this.config.erc8004,
        this.config.adapter,
        this.adapter.getPrivacyScore().guarantee
      );
      paymentProof.agentURI = manifestToDataURI(manifest);
      paymentProof.agentId = this.config.erc8004.agentId?.toString();
    }

    // 3. Retry with the payment proof
    // The proof contains ONLY zkProof + publicInputs — no txHash, no litCiphertext
    const paymentHeader = buildPaymentHeader(paymentProof);
    const result = await fetch(url, {
      ...init,
      headers: {
        ...(init?.headers ?? {}),
        'X-Payment-Proof': paymentHeader,
        'X-Payment-Scheme': X402_SCHEME,
      },
    });

    // Mark the note as spent after a successful payment so the caller
    // doesn't accidentally try to reuse it. The server will also reject
    // a replay (NullifierSet), but flagging it client-side prevents
    // wasted proof generation time on the second attempt.
    if (result.ok) {
      note.spent = true;
    }

    return result;
  }

  /**
   * Pay and return both the API response and an ERC-8004 receipt.
   *
   * The receipt follows the ERC-8004 off-chain feedback format and can be
   * submitted to the Reputation Registry to build the agent's reputation.
   *
   * PRIVACY NOTE: the receipt uses the nullifierHash (a public ZK signal) as
   * the payment identifier — NOT the deposit txHash. The deposit txHash is an
   * on-chain record that reveals which deposit funded this payment. Including it
   * in a published receipt defeats the ZK unlinking. The nullifierHash is already
   * public (it appears in the proof public inputs), so including it here adds no
   * new information to an observer, but proves "I made a payment" without revealing
   * "and here is my deposit."
   */
  async payWithReceipt(
    url: string,
    note: Note,
    amount: bigint,
    artifacts: ProverArtifacts,
    init?: RequestInit
  ): Promise<{ response: Response; receipt: AgentReceipt }> {
    if (note.leafIndex === -1) {
      throw new Error(
        'Note has not been resolved yet (leafIndex=-1). ' +
        'Call findNoteInTree() after the deposit is confirmed on-chain.'
      );
    }
    if (note.spent) {
      throw new Error('Note is already spent. Each note can only be used once.');
    }

    // Probe
    const probe = await fetch(url, init);
    let nullifierHash = '';

    if (probe.status !== 402) {
      const receipt = generatePaymentReceipt('', 'starknet-mainnet', '', url, amount, note.token, this.config.erc8004);
      return { response: probe, receipt };
    }

    const challenge = parseChallenge(probe);
    if (!challenge) {
      throw new Error(`402 response missing valid Cipher Pol payment challenge from ${url}`);
    }

    // Generate proof and capture nullifierHash for the receipt
    const paymentProof = await (this.adapter as PrivacyPoolsAdapter).generatePaymentProof(
      note,
      challenge.payTo,
      amount,
      artifacts
    );
    nullifierHash = paymentProof.nullifierHash;

    // PRIVACY WARNING: starknetAddress in ERC8004Config leaks payer identity to server.
    // See pay() for the full warning.
    if (this.config.erc8004) {
      const manifest = createAgentManifest(
        this.config.erc8004,
        this.config.adapter,
        this.adapter.getPrivacyScore().guarantee
      );
      paymentProof.agentURI = manifestToDataURI(manifest);
      paymentProof.agentId = this.config.erc8004.agentId?.toString();
    }

    const paymentHeader = buildPaymentHeader(paymentProof);
    const response = await fetch(url, {
      ...init,
      headers: {
        ...(init?.headers ?? {}),
        'X-Payment-Proof': paymentHeader,
        'X-Payment-Scheme': X402_SCHEME,
      },
    });

    if (response.ok) {
      note.spent = true;
    }

    // Receipt uses nullifierHash as payment identifier (NOT deposit txHash).
    // The nullifierHash is already public (in proof public inputs) so this
    // adds no new information. The deposit txHash would reveal which on-chain
    // deposit funded this payment — a complete deanonymization.
    const receipt = generatePaymentReceipt(
      nullifierHash,
      'starknet-mainnet',
      '',
      url,
      amount,
      note.token,
      this.config.erc8004
    );

    return { response, receipt };
  }

  /**
   * Return the ERC-8004 agent manifest for this agent.
   *
   * The manifest can be hosted at HTTPS or on IPFS, then registered on the
   * Ethereum ERC-8004 Identity Registry via:
   *   identityRegistry.register(agentURI)
   *
   * Returns null if no erc8004 config was provided.
   */
  getAgentManifest(): { manifest: ReturnType<typeof createAgentManifest>; uri: string } | null {
    if (!this.config.erc8004) return null;
    const manifest = createAgentManifest(
      this.config.erc8004,
      this.config.adapter,
      this.adapter.getPrivacyScore().guarantee
    );
    return { manifest, uri: manifestToDataURI(manifest) };
  }

  /**
   * Honest privacy score for the current adapter.
   * Print this to users so they know what privacy they actually have.
   */
  getPrivacyScore(): PrivacyScore {
    return this.adapter.getPrivacyScore();
  }

  get adapterName(): string {
    return this.adapter.name;
  }
}
