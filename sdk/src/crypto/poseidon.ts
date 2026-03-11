/**
 * Poseidon hash matching Ekubo Privacy Pool's hash(a, b) function.
 *
 * VERIFIED COMPATIBLE:
 * - Ekubo uses Poseidon over BN254 Fr (= Grumpkin base field), t=3, nRoundsF=8, nRoundsP=57
 * - poseidon-lite poseidon2() uses the identical parameters
 * - Confirmed: poseidon2([0n, 0n]) === 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864
 *   which matches Ekubo's merkle.cairo zero-value constant.
 *
 * Source: pool/src/lib.cairo hash(a, b) = run_poseidon_grumpkin_circuit(a, b)
 * Circuit: circuits/hash.circom Poseidon(2) — iden3 circomlib parameter set
 */
import { poseidon2 } from 'poseidon-lite';
export function poseidonHash(a: bigint, b: bigint): bigint {
  return poseidon2([a, b]);
}

/**
 * Commitment hash matching CommitmentHasher in association.circom.
 *
 * CommitmentHasher circuit:
 *   temp       = Hash([secret, nullifier])   = poseidon2([secret, nullifier])
 *   commitment = Hash([temp, amount])        = poseidon2([temp, amount])
 *
 * This is the leaf value stored in the Merkle tree.
 * The pool.cairo deposit() call takes this commitment as secret_and_nullifier_hash.
 */
export function computeCommitment(secret: bigint, nullifier: bigint, amount: bigint): bigint {
  const temp = poseidonHash(secret, nullifier);
  return poseidonHash(temp, amount);
}

/**
 * Nullifier hash matching HashOne() in hash.circom.
 *
 * HashOne circuit: out = Hash([in, in]) = poseidon2([nullifier, nullifier])
 * Used to mark deposits as spent without revealing which deposit.
 */
export function computeNullifierHash(nullifier: bigint): bigint {
  return poseidonHash(nullifier, nullifier);
}
