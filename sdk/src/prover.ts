/**
 * Groth16 Prover for Ekubo Privacy Pool withdrawals
 *
 * This generates the zero-knowledge proof required to call pool.withdraw().
 *
 * Circuit: EkuboProtocol/privacy-pools/circuits/pool.circom
 * Proof system: Groth16 over BN254
 *
 * Public inputs (7):
 *   root, nullifierHash, recipient, fee, refundCommitmentHash, amount, associatedSetRoot
 *
 * Private inputs (witness):
 *   secret, nullifier, refund, commitmentAmount,
 *   pathElements[24], pathIndices[24],            ← main Merkle proof
 *   associatedSetPathElements[24], associatedSetPathIndices[24]  ← association set proof
 *
 * TRUSTED SETUP:
 * Before using this module, run:
 *   cd circuits && npm run setup
 *   (generates target/pool_final.zkey + target/pool.wasm)
 * The .zkey file encodes the proving key from a local Powers of Tau ceremony.
 * For production: use Hermez Phase 1 ptau (https://github.com/iden3/snarkjs#7-prepare-phase-2).
 *
 * For the hackathon demo: the local trusted setup is fine.
 * The verifier contract on Starknet was deployed with matching verification key.
 * Our proving key must match that verifier key — so we must either:
 *   a) Use Ekubo's exact .zkey (if they publish it), or
 *   b) Re-deploy a verifier contract with our freshly-generated key.
 * For the hackathon, option (b) is the path: deploy our own pool instance.
 */

import { poseidonHash, computeNullifierHash } from './crypto/poseidon.js';

export interface ProverArtifacts {
  /** Path to pool.wasm (compiled circuit) */
  wasmPath: string;
  /** Path to pool_final.zkey (proving key from trusted setup) */
  zkeyPath: string;
}

export interface WithdrawWitness {
  /** Deposit secret */
  secret: bigint;
  /** Deposit nullifier */
  nullifier: bigint;
  /** Amount to withdraw (must match deposit) */
  amount: bigint;
  /** Recipient Starknet address */
  recipient: string;
  /** Fee for relayer (0 if withdrawing directly) */
  fee: bigint;
  /** Refund amount if deposit > withdrawal amount (0 typically) */
  refund: bigint;
  /** commitmentAmount = amount if no refund */
  commitmentAmount: bigint;
  /** Merkle proof for deposit in main pool tree (24 siblings) */
  pathElements: bigint[];
  /** Merkle path direction bits (0=left, 1=right) for each level */
  pathIndices: number[];
  /** Current Merkle root of pool */
  root: bigint;
  /** Associated set root (for compliance proofs — use 0 for simple withdrawal) */
  associatedSetRoot: bigint;
  /** Merkle proof for deposit in association set (24 siblings, zeros if not in set) */
  associatedSetPathElements: bigint[];
  associatedSetPathIndices: number[];
}

export interface ProofResult {
  /** Serialized proof as felt252 array — pass directly to pool.withdraw() */
  proofFelts: bigint[];
  /** The nullifier hash — used to prevent double-spend */
  nullifierHash: bigint;
  /** Refund commitment hash (0 if no refund) */
  refundCommitmentHash: bigint;
}

/**
 * Generate a Groth16 withdrawal proof.
 *
 * @param witness - All private and public inputs for the proof
 * @param artifacts - Paths to .wasm and .zkey files from trusted setup
 */
export async function generateWithdrawProof(
  witness: WithdrawWitness,
  artifacts: ProverArtifacts
): Promise<ProofResult> {
  // Dynamic import — snarkjs is large and optional
  const snarkjs = await import('snarkjs');

  const nullifierHash = computeNullifierHash(witness.nullifier);
  const refundCommitmentHash = witness.refund > 0n
    ? poseidonHash(witness.nullifier, witness.refund)
    : 0n;

  // Validate path lengths
  const TREE_DEPTH = 24;
  if (witness.pathElements.length !== TREE_DEPTH) {
    throw new Error(`pathElements must have ${TREE_DEPTH} elements, got ${witness.pathElements.length}`);
  }
  if (witness.associatedSetPathElements.length !== TREE_DEPTH) {
    throw new Error(`associatedSetPathElements must have ${TREE_DEPTH} elements`);
  }

  // Build input signals for the circuit
  // Names must match exactly what pool.circom declares
  const input = {
    // Public inputs
    root: witness.root.toString(),
    nullifierHash: nullifierHash.toString(),
    recipient: BigInt(witness.recipient).toString(),
    fee: witness.fee.toString(),
    refundCommitmentHash: refundCommitmentHash.toString(),
    amount: witness.amount.toString(),
    associatedSetRoot: witness.associatedSetRoot.toString(),

    // Private inputs
    secret: witness.secret.toString(),
    nullifier: witness.nullifier.toString(),
    refund: witness.refund.toString(),
    commitmentAmount: witness.commitmentAmount.toString(),
    pathElements: witness.pathElements.map(String),
    pathIndices: witness.pathIndices,
    associatedSetPathElements: witness.associatedSetPathElements.map(String),
    associatedSetPathIndices: witness.associatedSetPathIndices,
  };

  // Generate the Groth16 proof (~2-5s with snarkjs WASM, ~100ms with RapidSnark)
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    artifacts.wasmPath,
    artifacts.zkeyPath
  );

  // Serialize to felt252 format for Starknet
  // The Starknet verifier expects [pi_a (2 felts), pi_b (4 felts), pi_c (2 felts), public_inputs (7 felts)]
  const proofFelts = serializeProofToFelts(proof, publicSignals);

  return {
    proofFelts,
    nullifierHash,
    refundCommitmentHash,
  };
}

/**
 * Serialize a Groth16 proof + public signals to a felt252 array.
 *
 * The Starknet verifier (garaga-generated) expects proof elements as u256 pairs (low, high).
 * Format: [a.x.low, a.x.high, a.y.low, a.y.high,
 *          b.x0.low, b.x0.high, b.x1.low, b.x1.high,
 *          b.y0.low, b.y0.high, b.y1.low, b.y1.high,
 *          c.x.low, c.x.high, c.y.low, c.y.high,
 *          ...public_inputs as u256 pairs...]
 *
 * NOTE: This format must match exactly what Ekubo's verifier contract expects.
 * The verifier is generated by garaga (https://github.com/keep-starknet-strange/garaga).
 * If the format doesn't match, verify_groth16_proof_bn254 will return false.
 */
function serializeProofToFelts(
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
  },
  publicSignals: string[]
): bigint[] {
  const U256_MAX = (1n << 256n) - 1n;

  function toBigInt(hex: string): bigint {
    return BigInt(hex.startsWith('0x') ? hex : '0x' + hex);
  }

  function u256ToFelts(value: bigint): [bigint, bigint] {
    const low = value & ((1n << 128n) - 1n);
    const high = value >> 128n;
    return [low, high];
  }

  const felts: bigint[] = [];

  // pi_a: G1 point (x, y)
  for (const coord of [proof.pi_a[0], proof.pi_a[1]]) {
    felts.push(...u256ToFelts(toBigInt(coord)));
  }

  // pi_b: G2 point (x0, x1, y0, y1) — note G2 coords are Fq2 elements
  for (const pair of [proof.pi_b[0], proof.pi_b[1]]) {
    for (const coord of pair) {
      felts.push(...u256ToFelts(toBigInt(coord)));
    }
  }

  // pi_c: G1 point (x, y)
  for (const coord of [proof.pi_c[0], proof.pi_c[1]]) {
    felts.push(...u256ToFelts(toBigInt(coord)));
  }

  // Public signals (7 values for pool.circom)
  for (const signal of publicSignals) {
    felts.push(...u256ToFelts(BigInt(signal)));
  }

  return felts;
}

/**
 * Build a simple Merkle proof for a leaf at a given index in a tree.
 * Uses zero values for all siblings (appropriate when the tree has only one deposit).
 *
 * For a real implementation with multiple deposits, you need to track the full Merkle tree.
 * This simplified version works for single-deposit demos.
 */
export function buildSingleDepositMerkleProof(
  leafHash: bigint,
  depth: number = 24
): { pathElements: bigint[]; pathIndices: number[]; root: bigint } {
  // Zero leaf value at each level (poseidon(0, 0))
  const ZERO_LEAF = poseidonHash(0n, 0n);

  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];

  // For a single deposit at index 0, all path elements are zero-value nodes
  // and all indices are 0 (left)
  let currentHash = leafHash;
  for (let level = 0; level < depth; level++) {
    pathElements.push(ZERO_LEAF);
    pathIndices.push(0); // leaf is always left child at each level
    currentHash = poseidonHash(currentHash, ZERO_LEAF);
  }

  return { pathElements, pathIndices, root: currentHash };
}
