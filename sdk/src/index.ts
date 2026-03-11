// Wraith Protocol — Agent SDK for private AI payments on Starknet
export { WraithAgent } from './agent.js';
export { PrivacyPoolsAdapter } from './adapters/privacy-pools.js';
export { STRK20Adapter } from './adapters/strk20.js';
export { PaymentBatcher } from './batcher.js';

// x402 protocol utilities
export {
  parseChallenge,
  buildPaymentHeader,
  parsePaymentHeader,
  verifyPaymentProofFields,
  extractPublicInputs,
  X402_SCHEME,
} from './x402.js';
export type { PublicInputs } from './x402.js';

// ERC-8004 (Trustless Agents) identity and receipts
export {
  createAgentManifest,
  manifestToDataURI,
  generatePaymentReceipt,
  validateReceipt,
} from './erc8004.js';
export type {
  AgentManifest,
  AgentReceipt,
  ERC8004Config,
  ServiceEntry,
} from './erc8004.js';

// Incremental Merkle tree (for building pool state client-side)
export {
  IncrementalMerkleTree,
  buildTreeFromCommitments,
  computeRootFromProof,
  TREE_DEPTH,
  ZERO_VALUES,
} from './crypto/merkle-tree.js';
export type { MerkleProof } from './crypto/merkle-tree.js';

// Prover types (for passing circuit artifacts to pay())
export type { ProverArtifacts, WithdrawWitness, ProofResult } from './prover.js';

// Core types
export type {
  WraithConfig,
  Note,
  PaymentIntent,
  PaymentReceipt,
  PrivacyScore,
  AuditProof,
  X402Challenge,
  X402PaymentProof,
  IPrivacyAdapter,
} from './types.js';

// Lit Protocol (optional — for note storage/vault, NOT for payment proofs)
// These are kept for agent-side note encryption. Do NOT use on the server.
export { encryptNoteForAPI, decryptNoteFromAgent } from './lit.js';
export type { EncryptedNote, DecryptedNote } from './lit.js';
