# Hackathon Submission — Cipher Pol

Format mirrors agentguard/ai/karma-submission.md.
Fill in platform-specific fields (deadline, tracks, bounty labels) before submitting.

---

## Name

Cipher Pol

## Tagline

ZK-native private payments for AI agents on Starknet.

## Description

Cipher Pol lets an AI agent pay for API access without the API server learning which
on-chain identity made the payment. The agent deposits into a shared pool, generates
a Groth16 zero-knowledge proof locally, and pays via the x402 HTTP payment protocol.
The server verifies the proof cryptographically. It does not learn the depositor address.

## Problem

AI agents make API calls that require payment. Every payment today links the agent's
on-chain identity to its activity. An observer watching the chain can reconstruct what
the agent did, which services it used, and when.

x402 solves the payment rail. Cipher Pol solves the identity problem: the API server
gets paid but cannot trace which on-chain address paid it.

## Solution

The payment flow has three properties:

1. **Cryptographic unlinking.** The agent deposits into a shared pool (Ekubo Privacy
   Pools on Starknet). Later, it generates a Groth16 zero-knowledge proof that proves
   "I own a note in this pool" without revealing which deposit. The proof is verified
   by a garaga 0.15.3 verifier deployed on Starknet.

2. **Standard payment rail.** The proof is attached to an x402 HTTP header. Any
   Express server can add one middleware line to accept private payments. No changes
   to the agent's HTTP client beyond `agent.pay()`.

3. **Double-spend prevention.** The server stores a nullifier hash in memory and on-chain.
   The same deposit cannot be used twice.

What the server learns: payment amount, timestamp, nullifierHash. Not: depositor address,
deposit transaction hash, or which of the pool's deposits funded this payment.

## Technical Details

- **Circuit**: Circom 2 + Groth16/BN254 + Poseidon2, 14,282 constraints, 24-level Merkle tree
- **On-chain verifier**: garaga 0.15.3 (Starknet), ~2918 felts calldata per proof
- **Proof generation**: snarkjs WASM, 4-6 seconds per proof
- **Payment protocol**: x402 (HTTP 402 challenge/response)
- **Chain**: Starknet (Cairo contracts, devnet verified)
- **Lit Protocol / ReceiptVault**: The ReceiptVault contract (Cairo) encrypts payment receipts
  via Storacha + Lit Protocol, allowing agents to recover notes cross-session using their ETH key.
  The encryption path and SIWE session flow are verified against live Datil network (steps 1-3 pass).
  The decrypt path is written and tested against the Datil API but cannot be fully verified live:
  Datil requires capacity credits (Chronicle Yellowstone faucet non-functional) and sunsets
  2026-04-01. Migration to Lit v3 Chipotle is the next step. Frame this for David Sneider:
  the architecture is correct and the decrypt code is there — the gap is infrastructure, not design.

## What's Been Verified

Tested against starknet-devnet 0.7.2 (seed 42):

- **8/8** on-chain tests — deposit → Groth16 proof → garaga calldata → pool.withdraw()
- **13/13** server middleware tests
- **26/26** SDK integration tests — circuit, Merkle tree, proof generation, serialization
- **28/28** HTTP x402 end-to-end tests — full 402 challenge → ZK proof → 200 flow
- **7/7** WithdrawalQueue phases — garaga calldata (2918 felts), on-chain withdrawal, nullifier stored

## Honest Limits

1. 1-party trusted setup — local Powers of Tau. MPC ceremony needed for production.
2. In-memory nullifier set — lost on server restart. Redis needed for production.
3. Depositor address visible at deposit time — link-private, not identity-private.
4. Anonymity set = pool size — small pool = weak privacy. Demo pool has few deposits.
5. BN254 is not quantum-resistant. v2 path: STARK proofs on Starknet's native hash.
6. Proof generation is 4-6s (snarkjs WASM). RapidSnark would be ~100ms (not integrated).
7. Lit Protocol decrypt unverified against live network — Datil sunsets 2026-04-01,
   migration to Chipotle v3 required.

Full analysis: https://github.com/Yonkoo11/cipher-pol/blob/main/docs/THREAT_MODEL.md

## Project Stage

Devnet prototype. All core flows verified. Not deployed to testnet or mainnet.

---

## Social / Links

- GitHub: https://github.com/Yonkoo11/cipher-pol
- Landing page: https://yonkoo11.github.io/cipher-pol/
- Twitter: @soligxbt
- Demo video: (not recorded yet)

## Tracks / Bounties

[FILL IN — depends on hackathon platform]

Examples if Starknet hackathon:
- Privacy / ZK track
- AI agents track
- x402 integration bounty (if offered)
- Lit Protocol bounty (if offered)

---

## X Post Draft

Built Cipher Pol for [HACKATHON NAME].

AI agents make millions of API calls. Every payment reveals which on-chain identity
paid, which API, and when. Cipher Pol fixes this with ZK proofs.

The agent deposits into a shared pool. Later it pays via x402 using a Groth16 proof —
without revealing which deposit funded the payment.

82 tests passing on Starknet devnet.

Demo: https://yonkoo11.github.io/cipher-pol/
Code: https://github.com/Yonkoo11/cipher-pol

---

## Milestones (if funding form)

### Milestone 1 — Lit v3 Chipotle migration
Migrate from Datil to Chipotle for full note storage verification.
Steps 4-5 of lit.test.mjs currently skipped due to Datil sunset April 1.
End date: April 15, 2026. Priority: High.

### Milestone 2 — STRK20Adapter
Implement the STRK20Adapter once the Starkware repo ships (announced 2026-03-10).
v2: identity-private payments with STARK proofs, no anonymity set requirement.
End date: May 15, 2026. Priority: High.

### Milestone 3 — Production hardening
Redis-backed nullifier set (prevent double-spend across restarts).
MPC trusted setup ceremony.
Testnet deployment.
End date: May 31, 2026. Priority: Medium.

### Milestone 4 — RapidSnark integration
Replace snarkjs WASM (4-6s) with RapidSnark (~100ms).
End date: April 30, 2026. Priority: Medium.

### Milestone 5 — npm publishing
Publish cipher-pol-agent and cipher-pol-server to npm.
End date: April 30, 2026. Priority: Low.
