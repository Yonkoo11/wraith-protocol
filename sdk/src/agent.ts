/**
 * WraithAgent — autonomous agent with private x402 payments
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
  WraithConfig,
  Note,
  PaymentIntent,
  PrivacyScore,
  X402PaymentProof,
} from './types.js';
import { IPrivacyAdapter } from './types.js';
import { PrivacyPoolsAdapter } from './adapters/privacy-pools.js';
import { STRK20Adapter } from './adapters/strk20.js';
import { PaymentBatcher } from './batcher.js';
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

export class WraithAgent {
  private readonly adapter: IPrivacyAdapter;
  private readonly batcher: PaymentBatcher;
  private readonly config: Required<WraithConfig>;

  constructor(config: WraithConfig, account?: Account) {
    this.config = {
      starknetRpcUrl: 'https://starknet-mainnet.public.blastapi.io',
      litNetwork: 'datil',
      storachaEmail: '',
      settlementFeeBps: 10,
      ...config,
    } as Required<WraithConfig>;

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

    this.batcher = new PaymentBatcher();
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

    // 1. Probe the endpoint — should return 402
    const probe = await fetch(url, init);

    if (probe.status !== 402) {
      // Not payment-gated; return as-is
      return probe;
    }

    const challenge = parseChallenge(probe);
    if (!challenge) {
      throw new Error(`402 response missing valid Wraith payment challenge from ${url}`);
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

    // Attach ERC-8004 agent identity to proof (if configured)
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

    return result;
  }

  /**
   * Pay and return both the API response and an ERC-8004 receipt.
   *
   * The receipt follows the ERC-8004 off-chain feedback format and can be
   * submitted to the Reputation Registry to build the agent's reputation.
   */
  async payWithReceipt(
    url: string,
    note: Note,
    amount: bigint,
    artifacts: ProverArtifacts,
    init?: RequestInit
  ): Promise<{ response: Response; receipt: AgentReceipt }> {
    const response = await this.pay(url, note, amount, artifacts, init);

    const receipt = generatePaymentReceipt(
      note.depositTxHash ?? '',
      'starknet-mainnet',
      '',   // pool address not exposed here; caller can access via note or adapter
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
