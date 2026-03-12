/**
 * x402 payment protocol for Wraith Protocol.
 *
 * The x402 flow:
 *   1. Agent GETs/POSTs an API endpoint
 *   2. Server returns 402 with WWW-Authenticate payment challenge
 *   3. Agent deposits into the Ekubo privacy pool on Starknet (on-chain tx)
 *   4. Agent generates a Groth16 ZK proof CLIENT-SIDE:
 *        - proves knowledge of a commitment in the pool's Merkle tree
 *        - commits to recipient = API server's Starknet address
 *        - reveals only nullifierHash (to prevent double-spend) + amount + root
 *   5. Agent retries with X-Payment-Proof header containing the ZK proof
 *   6. Server verifies the proof, tracks nullifierHash, submits withdrawal
 *
 * Privacy guarantee:
 * - Server sees: a ZK proof that "someone with a valid deposit in this pool
 *   authorizes payment to my address". Server does NOT see which deposit,
 *   and does NOT see the depositor's Starknet address.
 * - Chain observers see: a deposit with a commitment hash (no depositor link
 *   to this specific payment), and a withdrawal to the server address.
 * - The ZK proof cryptographically unlinks deposit from withdrawal.
 *
 * What the server DOES learn (honest threat model):
 * - The fact that someone paid at this timestamp (traffic analysis possible)
 * - The payment amount
 * - Nothing about the depositor's identity
 *
 * HONEST CAVEAT (v1):
 * - Depositor's address IS visible when they call pool.deposit() on-chain.
 *   Privacy is one-sided: observers CAN see "Alice deposited", they CANNOT see
 *   "Alice paid API_server for service X at time T".
 * - With a small anonymity set (few deposits in the pool), chain analysis can
 *   narrow down candidates. Run the pool for a while before using it for privacy.
 *
 * See docs/THREAT_MODEL.md for the complete analysis.
 */

import { X402Challenge, X402PaymentProof, PaymentIntent } from './types.js';

export const X402_SCHEME = 'wraith-starknet-v1';

/**
 * Parse a 402 response and extract the payment challenge.
 *
 * Format: Wraith-Starknet-v1 network="starknet-mainnet",token="STRK",amount="1000",payTo="0x...",poolAddress="0x..."
 */
export function parseChallenge(response: Response): X402Challenge | null {
  if (response.status !== 402) return null;

  const auth = response.headers.get('WWW-Authenticate');
  if (!auth?.startsWith('Wraith-Starknet')) return null;

  const params: Record<string, string> = {};
  for (const match of auth.matchAll(/(\w+)="([^"]+)"/g)) {
    params[match[1]] = match[2];
  }

  return {
    scheme: X402_SCHEME,
    network: params.network ?? 'starknet-mainnet',
    token: params.token ?? 'STRK',
    amount: params.amount ?? '0',
    payTo: params.payTo ?? '',
    poolAddress: params.poolAddress,
    memo: params.memo,
  };
}

/**
 * Build a PaymentIntent from a parsed challenge.
 */
export function challengeToIntent(
  challenge: X402Challenge,
  maxLatencyMs?: number
): PaymentIntent {
  return {
    url: challenge.payTo,
    amount: BigInt(challenge.amount),
    token: challenge.token,
    maxLatencyMs,
  };
}

/**
 * Encode a payment proof for the X-Payment-Proof header.
 *
 * The proof contains only the ZK proof felts and nullifier hash.
 * It does NOT contain txHash or secret/nullifier — those stay with the agent.
 */
export function buildPaymentHeader(proof: X402PaymentProof): string {
  return Buffer.from(JSON.stringify(proof)).toString('base64');
}

/**
 * Decode an X-Payment-Proof header value.
 */
export function parsePaymentHeader(header: string): X402PaymentProof {
  return JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
}

/**
 * Verify a payment proof on the server side.
 *
 * Checks:
 * 1. Scheme matches
 * 2. zkProof is present and non-empty
 * 3. nullifierHash is present
 * 4. amount matches the challenge
 * 5. recipient in proof matches server's address (via public signals)
 *
 * The server does NOT need to run Groth16 verification locally —
 * the pool contract verifies the proof when withdrawal is submitted.
 * Double-spend protection comes from tracking nullifierHashes locally
 * and on-chain (pool stores spent nullifiers).
 *
 * For higher assurance before accepting payment: submit the proof to the
 * pool contract first and wait for confirmation.
 */
export function verifyPaymentProofFields(
  proof: X402PaymentProof,
  expectedAmount: bigint,
  serverStarknetAddress: string,
): { valid: boolean; reason?: string } {
  if (proof.scheme !== X402_SCHEME) {
    return { valid: false, reason: `Unknown scheme: ${proof.scheme}` };
  }

  if (!proof.zkProof || proof.zkProof.length === 0) {
    return { valid: false, reason: 'Missing zkProof' };
  }

  if (!proof.nullifierHash) {
    return { valid: false, reason: 'Missing nullifierHash' };
  }

  if (!proof.publicInputs) {
    return { valid: false, reason: 'Missing publicInputs' };
  }

  // Public input layout (matches pool.circom component main public signals):
  // [root, nullifierHash, recipient, fee, amount, refundCommitmentHash, associatedSetRoot]
  const { root, nullifierHash, recipient, fee, amount } = proof.publicInputs;

  // Amount must be >= required (agent may overpay)
  if (BigInt(amount) < expectedAmount) {
    return {
      valid: false,
      reason: `Proof amount ${amount} < required ${expectedAmount}`,
    };
  }

  // Recipient must match our address
  // The recipient is a Starknet felt252 (a bigint)
  const proofRecipient = BigInt(recipient);
  const expectedRecipient = BigInt(serverStarknetAddress);
  if (proofRecipient !== expectedRecipient) {
    return {
      valid: false,
      reason: `Proof recipient ${recipient} != server address ${serverStarknetAddress}`,
    };
  }

  // nullifierHash in proof must match the announced nullifierHash
  if (BigInt(nullifierHash) !== BigInt(proof.nullifierHash)) {
    return {
      valid: false,
      reason: 'nullifierHash mismatch between proof and announcement',
    };
  }

  return { valid: true };
}

/**
 * Extract public inputs from a serialized proof felt array.
 *
 * The felt array format (from serializeProofToFelts):
 *   [pi_a (4 felts), pi_b (8 felts), pi_c (4 felts), public_signals (14 felts as u256 pairs)]
 *
 * Public signals in pool.circom r1cs order (snarkjs output):
 *   root, nullifierHash, recipient, fee, refundCommitmentHash, amount, associatedSetRoot
 *
 * NOTE: The circuit's main component declares [root, nullifierHash, recipient, fee, amount,
 * refundCommitmentHash, associatedSetRoot], but snarkjs orders them by the signal's
 * definition position in the component body, where refundCommitmentHash is declared
 * before amount. Verified: publicSignals[5] = amount (confirmed experimentally).
 */
export function extractPublicInputs(zkProof: string[]): PublicInputs {
  // Proof element layout:
  //   pi_a:  4 felts  (G1 point: x_low, x_high, y_low, y_high)
  //   pi_b:  8 felts  (G2 point: x0_low, x0_high, x1_low, x1_high, y0_low, y0_high, y1_low, y1_high)
  //   pi_c:  4 felts  (G1 point: x_low, x_high, y_low, y_high)
  //   signals: 7 public signals × 2 felts each (u256 as low + high) = 14 felts
  const PROOF_FELTS = 16;
  const SIGNAL_COUNT = 7;
  const EXPECTED_LENGTH = PROOF_FELTS + SIGNAL_COUNT * 2; // 30

  if (zkProof.length < EXPECTED_LENGTH) {
    throw new Error(
      `extractPublicInputs: zkProof has ${zkProof.length} elements but requires at least ` +
      `${EXPECTED_LENGTH} (${PROOF_FELTS} proof felts + ${SIGNAL_COUNT}×2 signal felts). ` +
      `This likely means proof generation failed or the proof format has changed.`
    );
  }

  const signalOffset = PROOF_FELTS;

  function readU256(idx: number): bigint {
    const low = BigInt(zkProof[signalOffset + idx * 2]);
    const high = BigInt(zkProof[signalOffset + idx * 2 + 1]);
    return low + (high << 128n);
  }

  return {
    root: readU256(0).toString(),
    nullifierHash: readU256(1).toString(),
    recipient: readU256(2).toString(),
    fee: readU256(3).toString(),
    refundCommitmentHash: readU256(4).toString(),
    amount: readU256(5).toString(),
    associatedSetRoot: readU256(6).toString(),
  };
}

export interface PublicInputs {
  root: string;
  nullifierHash: string;
  recipient: string;
  fee: string;
  amount: string;
  refundCommitmentHash: string;
  associatedSetRoot: string;
}

/**
 * Reconstruct a snarkjs-format proof object and public signals array
 * from the 30-felt HTTP transport encoding.
 *
 * This is the inverse of serializeProofToFelts() used by the agent.
 * Used by the server's WithdrawalQueue to generate garaga calldata.
 *
 * Felt layout (16 proof + 14 signal felts):
 *   pi_a  [0..3]:    G1 x (low,high), G1 y (low,high)
 *   pi_b  [4..11]:   G2 x0 (low,high), x1 (low,high), y0 (low,high), y1 (low,high)
 *   pi_c  [12..15]:  G1 x (low,high), G1 y (low,high)
 *   signals [16..29]: 7 × u256 (low,high each)
 *
 * Output matches the snarkjs proof JSON format that garaga expects.
 */
export function deserializeProofFromFelts(zkProof: string[]): {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
} {
  const PROOF_FELTS = 16;
  const SIGNAL_COUNT = 7;
  const EXPECTED = PROOF_FELTS + SIGNAL_COUNT * 2;

  if (zkProof.length < EXPECTED) {
    throw new Error(
      `deserializeProofFromFelts: need ${EXPECTED} felts, got ${zkProof.length}`
    );
  }

  function readU256At(feltIdx: number): string {
    const low  = BigInt(zkProof[feltIdx]);
    const high = BigInt(zkProof[feltIdx + 1]);
    return (low + (high << 128n)).toString();
  }

  const pi_a = [readU256At(0), readU256At(2), '1'];

  // pi_b is a G2 point: x = [x0, x1], y = [y0, y1] (Fq2 elements)
  const pi_b = [
    [readU256At(4),  readU256At(6)],
    [readU256At(8),  readU256At(10)],
    ['1', '0'],
  ];

  const pi_c = [readU256At(12), readU256At(14), '1'];

  const publicSignals: string[] = [];
  for (let i = 0; i < SIGNAL_COUNT; i++) {
    publicSignals.push(readU256At(PROOF_FELTS + i * 2));
  }

  return {
    proof: { pi_a, pi_b, pi_c, protocol: 'groth16', curve: 'bn128' },
    publicSignals,
  };
}
