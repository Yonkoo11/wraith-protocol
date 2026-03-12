# Wraith Protocol — Project Rules

## Privacy Critique Enforcement

**Every change touching payment flow, proof serialization, middleware, or logging
MUST be reviewed against this checklist before declaring done.**

This is what a senior privacy builder (Mert Mumtaz, Barry WhiteHat, Aztec team)
would ask. It is not aspirational. It is a gate.

### P1 — What does the server learn from this change?

For every new field, log, header, or parameter added to the HTTP path:
- List exactly what information the server receives
- State whether it can be correlated with on-chain data
- If yes: is there a mitigation, and is it implemented?

If you cannot answer "the server learns X and only X" — the change is not done.

### P2 — What does a chain observer learn from this change?

For every on-chain action (deposit, withdraw, call):
- List what is public on-chain (address, amount, timestamp, event topics)
- State whether a new correlation is created between deposit and withdrawal
- Timing: is the on-chain action triggered within seconds of an HTTP request?
  If yes: flushIntervalMs=0 warning MUST be in the code comment

### P3 — Anonymity set assumption

Before every withdrawal:
- What is the minimum pool size for this to provide any privacy?
- Is that assumption documented in the code/test?
- Withdrawing into a pool of 1 = no privacy. State this.

### P4 — Proof serialization correctness

When touching serializeProofToFelts / deserializeProofFromFelts / garaga calldata:
- MUST verify: snarkjs returns coordinates as DECIMAL strings (F.toObject → o.toString(10))
- MUST NOT: prepend "0x" to proof coordinates (BigInt("0x" + decimal) = wrong value)
- MUST: check garaga calldata length is ~2918 felts, not 30
- Lesson: toBigInt() bug caused G1 points off BN254 curve, silently accepted by HTTP middleware
  but rejected by garaga's `is_on_curve` check. This was invisible until withdrawal.test.mjs.

### P5 — Log and header hygiene

When touching Express middleware, logging, or request handling:
- X-Payment-Proof MUST be deleted before next() (header stripping enforced in middleware.ts)
- nullifierHash MUST NOT appear in access logs
- If adding a new header/field: check if it creates a timing oracle

### P6 — Nullifier gap analysis

When touching NullifierSet or proof acceptance:
- In-memory NullifierSet: lost on restart = double-spend window. State this explicitly.
- If changing to persistent: verify Redis connection is tested, not just written
- The gap between "accept proof" and "on-chain confirmation" is an economic risk window.
  For each change to this window: quantify the loss exposure.

### P7 — Trusted setup scope

When discussing proof system security:
- NEVER say "secure" without stating: "1-party trusted setup, not production-ready"
- ALWAYS note: Groth16/BN254 is NOT quantum resistant
- Circuit changes REQUIRE: re-run `cd circuits && npm run setup`; old .zkey is wrong

---

## Required test matrix for any PR

| Path changed | Must pass |
|---|---|
| sdk/src/prover.ts | tests/withdrawal.test.mjs (Phases 1-7) |
| sdk/src/x402.ts | tests/e2e.test.mjs (28/28) |
| server/src/middleware.ts | tests/server.test.mjs + tests/e2e.test.mjs |
| server/src/withdrawal-queue.ts | tests/withdrawal.test.mjs (Phase 6 specifically) |
| circuits/ | tests/onchain.test.mjs (8/8) + re-run trusted setup |

---

## Known architectural gaps (not bugs, honest limits)

1. **1-party trusted setup** — local Powers of Tau. Not production. Need MPC ceremony.
2. **In-memory NullifierSet** — lost on restart. Need Redis backing for production.
3. **Timing oracle at flushIntervalMs=0** — documented in THREAT_MODEL.md.
4. **Anonymity set = pool size** — small pool = trivial deanonymization.
5. **Depositor address visible on-chain** — Wraith is link-private, not identity-private.
6. **BN254 is not quantum-resistant** — v2 STRK20Adapter with STARK proofs is the path.

---

## Runbook

```bash
# Full dev setup
node scripts/rpc-proxy.mjs &   # proxy for starknet.js compat
starknet-devnet --seed 42      # devnet

# Tests (in order)
node tests/onchain.test.mjs     # 8 tests — on-chain deposit/prove/withdraw
node tests/server.test.mjs      # 13 tests — middleware
node tests/integration.test.mjs # 26 tests — SDK integration
node tests/e2e.test.mjs         # 28 tests — HTTP x402 end-to-end
node tests/withdrawal.test.mjs  # 7 phases — WithdrawalQueue + garaga

# Circuit (if pool.circom changed)
cd circuits && npm run setup    # re-generates pool_final.zkey + pool.wasm
```
