# Wraith Protocol — Progress

## Status: E2E VERIFIED + COMMITTED (2026-03-12)

## What's Done

### TypeScript SDK — COMPILED CLEAN, VERIFIED
- `tsc --noEmit` passes clean
- Types, PrivacyPoolsAdapter, STRK20Adapter (stub), PaymentBatcher, x402 middleware, WraithAgent
- Lit Protocol v7 integration: encryptNoteForAPI(), decryptNoteFromAgent()
- Poseidon hash VERIFIED: poseidon-lite == Ekubo's circuit (same parameters, confirmed numerically)

### Cairo Contracts — SCARB BUILD PASSES
- `scarb build` produces WraithAgent.contract_class.json + ReceiptVault.contract_class.json
- Cairo target: cairo/target/dev/

### Circuit Trusted Setup — COMPLETE
- circom v2.2.3 installed at ~/bin/circom
- pool.circom COMPILED: 14282 constraints, 29138 wires, 24-level Merkle tree
- Hermez Phase 1 ptau downloaded (72MB, n=16, trusted ceremony)
- pool_final.zkey generated (12MB)
- verification_key.json exported (7 public inputs, groth16/bn128)

### Proof Generation — VERIFIED WORKING
- Groth16 proof generates in ~4-6s (snarkjs WASM)
- Proof verifies locally against verification_key.json
- generateWithdrawProof() now verifies inline via snarkjs.zKey.exportVerificationKey() (1.15s overhead)
- Correct witness computation confirmed:
  - commitment = poseidon2([poseidon2([secret, nullifier]), amount])
  - nullifierHash = poseidon2([nullifier, nullifier])  ← HashOne(x) = Hash([x, x])

### Bug Fixes This Session (2026-03-12)
1. CRITICAL: deposit() calldata — was passing full commitment H(H(s,n), amount);
   pool.deposit() takes H(s,n). Pool computes H(H(s,n), amount) internally.
   Fixed: poseidonHash(secret, nullifier) passed as secret_and_nullifier_hash.

2. CRITICAL: fetchAllDeposits() misread Deposit event.
   Event emits secret_and_nullifier_hash in keys[2..3], NOT the Merkle leaf.
   Pool stores hash(snhash, amount) in tree. Fixed: reconstruct leaf from event data.

3. HIGH: extractPublicInputs() — silent ?? '0' on out-of-bounds zkProof array.
   Now throws with descriptive error if zkProof.length < 30.

4. MEDIUM: generateWithdrawProof() — no local proof verification.
   Added snarkjs.groth16.verify() after fullProve(). Fails fast on zkey/circuit mismatch.

5. COMMENT: poseidon.ts claimed "pool.cairo deposit() takes commitment" — wrong.
   Corrected to say pool takes H(s,n).

### On-Chain Tests — 8/8 PASSED (post-bugfix)
Tests: tests/onchain.test.mjs — 8/8 PASSED with deposit fix
- pool.deploy() + verifier.deploy() via devnet seed 42
- deposit() accepted (correct H(s,n) calldata), Merkle root updated on-chain
- Groth16 proof computed in 4-6s, verifies locally
- garaga 0.15.3 calldata (2918 felts) generated correctly
- withdraw() accepted on-chain, tokens transferred

### Bug Fixes (2nd session, 2026-03-12)
6. CRITICAL: extractPublicInputs() — wrong signal index for amount vs refundCommitmentHash.
   snarkjs orders public signals by definition position in component body, NOT the main
   public [] declaration. In pool.circom, refundCommitmentHash is defined before amount.
   Correct indices: refundCommitmentHash=4, amount=5 (was reversed: amount=4, rch=5).
   This caused "Proof amount 0 < required X" on every real proof submission.
   Fixed in sdk/src/x402.ts + comment updated with explanation.

### E2E HTTP Payment Test — 28/28 PASSED (2026-03-12)
Tests: tests/e2e.test.mjs — 28/28 PASSED (COMMITTED)
- Real devnet deposit (ETH approve + pool.deposit with correct H(s,n))
- Real Groth16 proof generation via snarkjs (~6s), verified locally
- Real HTTP wraithPaywall middleware (Express server)
- 402 challenge: correct scheme, payTo, poolAddress
- 200 response: server accepted real ZK proof, served protected resource
- Privacy invariants: no depositor address, txHash, or secret in withdrawal queue
- Replay prevention: same nullifier on retry → 402
Run: node scripts/rpc-proxy.mjs & && node tests/e2e.test.mjs

### Frontend — BUILT (not deployed)
- docs/index.html: GitHub Pages static site
- Sections: hero (animated terminal), how-it-works (5-step flow), privacy matrix,
  proof system table, TypeScript code examples, v1/v2 upgrade cards, honest limits
- Design: dark theme, monospace, technical — no generic AI slop
- docs/THREAT_MODEL.md: updated with verified test results

## File Map
```
sdk/src/             — COMPILED TO dist/
  types.ts, agent.ts, batcher.ts, x402.ts, lit.ts
  adapters/privacy-pools.ts (deposit bug fixed), adapters/strk20.ts (stub)
  crypto/poseidon.ts (comment fixed), prover.ts (local verify added), index.ts
  types/snarkjs.d.ts
server/src/          — WRITTEN, NOT COMPILED (no server tsconfig)
  middleware.ts, withdrawal-queue.ts, demo-server.ts
cairo/src/           — SCARB BUILD PASSES
  lib.cairo, interfaces.cairo, wraith_agent.cairo, receipt_vault.cairo
circuits/
  pool.circom + all deps (circomlib/ + association/hash/merkle)
  target/pool.r1cs, pool_js/pool.wasm, pool_final.zkey, verification_key.json
docs/
  index.html (GitHub Pages frontend)
  THREAT_MODEL.md (updated)
scripts/rpc-proxy.mjs
```

## Infrastructure
- scripts/rpc-proxy.mjs rewrites l2_gas_consumed→gas_consumed for starknet.js 6.24.1 compat
- Run: `node scripts/rpc-proxy.mjs &` then `node tests/onchain.test.mjs`

## What's NOT Done (remaining gaps)
1. **Server-side Lit session signatures** — getLitSessionSigs() still throws stub error
2. **On-chain withdrawal from HTTP queue** — e2e test queues proof but doesn't call pool.withdraw() with garaga calldata (that path verified separately in onchain.test.mjs)
3. **No testnet/mainnet deployment** — devnet only
4. **STRK20Adapter is a stub** — STRK20 not yet publicly deployed (announced 2026-03-10)
5. **1-party trusted setup** — not production-ready (need MPC ceremony)
6. **Redis-backed nullifier set** — in-memory only (server restart = replay window)
7. **RapidSnark** — snarkjs WASM is 4-6s; RapidSnark would be ~100ms

## STRK20 Context
Starkware announced STRK20 on 2026-03-10. Technical deep dive coming in "a few days".
STRK20Adapter stub is ready to fill in. Monitor: https://strk20.starknet.io/

## Confidence Level
- TypeScript compilation: compiles clean.
- Proof generation: VERIFIED WORKING. ~4-6s per proof.
- Poseidon hash: VERIFIED matches Ekubo circuit.
- On-chain end-to-end (deposit → prove → garaga calldata → withdraw): VERIFIED, 8/8.
- HTTP x402 end-to-end (deposit → real ZK proof → HTTP paywall): VERIFIED, 28/28.
- Privacy invariants (no depositor info leaks to server): VERIFIED in e2e tests.
- Replay prevention: VERIFIED in e2e tests.
- Frontend: written, not deployed (no remote configured).
- Lit encryption: written, not tested against real Lit network.

## Test Summary
| Test file | Count | Status |
|-----------|-------|--------|
| tests/onchain.test.mjs | 8/8 | PASS |
| tests/server.test.mjs | 13/13 | PASS |
| tests/integration.test.mjs | 26/26 | PASS |
| tests/e2e.test.mjs | 28/28 | PASS (NEW) |
