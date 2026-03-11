# Wraith Protocol — Threat Model

Version: v1 (Groth16 / Ekubo Privacy Pools)
Date: March 2026
Status: **Demo / research implementation.** The ZK proof circuit requires a
trusted setup. The Lit Protocol integration is optional and not on the critical
payment path.

---

## What Wraith Does

Wraith enables an AI agent to pay for API access without the API server learning
which on-chain identity made the payment. The agent deposits into a shared pool,
waits for other deposits to grow the anonymity set, and then generates a
zero-knowledge proof linking it to the deposited funds — without revealing which
deposit is theirs.

The core mechanism is the same as Tornado Cash v2 applied to HTTP payments
(x402 protocol).

---

## The Payment Flow

```
1. DEPOSIT (on-chain, public)
   Agent -> pool.deposit(commitment, amount)
   commitment = poseidon2(poseidon2(secret, nullifier), amount)

   On-chain after deposit:
   - Agent's Starknet address is visible (emitted in Deposit event)
   - commitment is visible (it's a hash, not secret/nullifier)
   - amount is visible

2. WAIT (off-chain, private timing decision)
   Agent stores (secret, nullifier) securely.
   The longer you wait + more deposits arrive = better anonymity set.
   Withdrawing immediately after depositing = no privacy.

3. GENERATE PROOF (client-side, private)
   Agent fetches all Deposit events to rebuild the Merkle tree.
   Agent generates Groth16 proof:
     Private inputs: secret, nullifier, pathElements[24], pathIndices[24]
     Public inputs:  root, nullifierHash, recipient (= API server address), amount

   The proof proves: "I know a (secret, nullifier) whose commitment is a leaf
   in the pool's Merkle tree, and I authorize payment to recipient."

4. SEND PROOF (x402, private)
   Agent sends X-Payment-Proof header containing ONLY:
     { zkProof, nullifierHash, publicInputs }

   NOT sent: txHash, depositor address, secret, nullifier, litCiphertext

5. SERVER VERIFICATION (server-side, fast)
   Server checks:
   - publicInputs.recipient == server's Starknet address
   - publicInputs.amount >= required amount
   - nullifierHash not in spent set (replay prevention)

   Server does NOT: verify the Groth16 proof cryptographically (that happens on-chain).
   Server does NOT: look up any on-chain data during this step.

6. WITHDRAWAL (on-chain, public)
   Server calls pool.withdraw(zkProof).
   Pool contract verifies the Groth16 proof via garaga verifier (BN254).
   If valid: server receives funds, nullifier stored permanently on-chain.
   Recipient (server address) is visible on-chain.
```

---

## What the Server Learns

| Information | Server Learns? | Notes |
|-------------|----------------|-------|
| Payment amount | YES | Public input in proof |
| Payment timestamp | YES | HTTP request metadata |
| Depositor's Starknet address | NO | Not in proof; Merkle proof hides leaf index |
| Which deposit funded this payment | NO | ZK proof unlinking core property |
| Agent's secret/nullifier | NO | Private circuit inputs, never sent |
| Deposit transaction hash | NO | Removed from v1 design (was a flaw in prior design) |
| nullifierHash | YES | Required for double-spend prevention |

---

## What Chain Observers Learn

| Information | Chain Observer Learns? | Notes |
|-------------|----------------------|-------|
| Depositor's address | YES | deposit() caller visible in Deposit event |
| Deposit commitment | YES | On-chain, but is a hash |
| Deposit amount | YES | On-chain |
| Recipient of withdrawal | YES | pool.withdraw() recipient is visible |
| Link between deposit and withdrawal | NO | This is what the ZK proof hides |

---

## Privacy Guarantees (Graded)

### What IS Hidden
- The link between a specific deposit and a specific withdrawal. A chain observer
  sees "Alice deposited" and "server S received payment" but cannot prove Alice
  paid S (vs any of the other depositors in the pool).

### What is NOT Hidden

**Depositor identity at deposit time:**
The depositor's Starknet address appears in the `Deposit` event. Anyone watching
the chain knows Alice (or any address) deposited into the pool. This is analogous
to Tornado Cash v1 — the deposit itself is public.

**Small anonymity sets:**
If the pool has 3 deposits total, a chain observer can narrow candidates to 3
addresses. With 1000 deposits, the observer only knows "it was one of 1000".
**Do not use Wraith for private payments when the pool has fewer than ~50
deposits that you didn't make yourself.**

**Timing correlation:**
If you deposit and withdraw within seconds, timing analysis trivially links them.
The pool is most private when used like a mixer: deposit at time T, withdraw
at time T+N (hours, days) with many deposits between.

**Amount correlation:**
If you deposit exactly 3000 USDC and the API costs exactly 3000 USDC, and yours
is the only deposit of that amount, the withdrawal amount narrows candidates.
Wraith's PaymentBatcher rounds amounts to standard buckets to mitigate this.

**Traffic analysis:**
The API server sees that *someone* called the API at timestamp T. Combined with
chain data, a server with both views (HTTP + chain) can correlate timing with
deposits.

---

## Proof System Properties

| Property | Value |
|----------|-------|
| Proof system | Groth16 |
| Elliptic curve | BN254 (alt_bn128) |
| Hash function | Poseidon2 over BN254 Fr field |
| Tree depth | 24 (supports 16M+ deposits) |
| Quantum resistant | NO — BN254 pairings are vulnerable to quantum computers |
| Proof size | ~256 bytes (8 G1/G2 points) |
| Proof generation time | 2-5 seconds (snarkjs WASM), ~100ms (RapidSnark) |

**Groth16 is NOT quantum-resistant.** A sufficiently large quantum computer
running Shor's algorithm could break BN254 elliptic curve discrete log and
forge proofs. This is not an immediate practical threat (no such quantum
computer exists today), but it should disqualify Groth16 from long-lived,
high-value privacy systems.

**Trusted setup:**
Groth16 requires a per-circuit Powers of Tau ceremony. If the toxic waste from
the ceremony is not destroyed, the holder can forge proofs. For production use:
use a multi-party ceremony (like Hermez Phase 1 ptau). For the hackathon demo,
a local 1-party setup is used.

---

## The Server's Economic Risk

The server accepts payment proof before verifying on-chain (to keep latency low).
The actual Groth16 verification happens when `pool.withdraw()` is submitted.

This creates a window where:
1. Server accepts proof → serves request
2. `pool.withdraw()` is submitted → might revert (invalid proof, already spent)

If the proof is invalid: the server served a request that yields no funds. The
economic loss equals one API call. For high-value APIs (>$0.01 per call):
submit the proof synchronously before serving (set `flushIntervalMs: 0`).

**Double-spend protection:**
- In-memory `NullifierSet` prevents replay within a server session
- On-chain nullifier storage (pool contract) prevents replay after withdrawal
- Gap vulnerability: server restart between proof acceptance and on-chain
  confirmation. Mitigate with Redis-backed nullifier set in production.

---

## What Lit Protocol Does (Optional)

Lit Protocol is used ONLY for **note storage** — not for payment proofs.

Optional use cases:
- Encrypting the (secret, nullifier) Note so it can be stored off-device and
  decrypted later using the agent's key (cross-session note recovery)
- Encrypted audit logs for compliance

What Lit does NOT do in Wraith v1:
- Does NOT gate proof generation
- Does NOT decrypt on the server
- Is NOT on the critical payment path

The previous design (pre-v1) used Lit to send (secret, nullifier) to the server
so the server could generate the ZK proof. This was a fundamental privacy flaw:
the server learned both deposit and withdrawal, defeating the ZK unlinking.
That design has been removed.

---

## Comparison to Tornado Cash

| Property | Tornado Cash v1 | Wraith v1 |
|----------|----------------|-----------|
| Deposit visible | YES | YES |
| Withdrawal receiver visible | YES | YES |
| Deposit/withdrawal link | Hidden | Hidden |
| Proof system | Groth16 (Circom) | Groth16 (Circom) |
| Trusted setup | Multi-party | Local (hackathon) |
| Application | Token mixing | x402 API payments |
| Payment recipients | User-specified address | API servers |

Wraith is Tornado Cash applied to HTTP API payments. The privacy properties
are the same. The implementation uses the same Circom circuit patterns.

---

## Upgrade Path

**v2: STRK20Adapter (planned)**
- Native Starknet privacy using STARK proofs (no BN254, no trusted setup)
- Quantum-resistant (STARKs are hash-based, not pairing-based)
- Depositor identity also hidden (identity-private, not just link-private)
- Requires Starknet ecosystem support for STRK20 standard

**For now:** Groth16 + Ekubo Privacy Pools provides meaningful link-privacy
with honest caveats about depositor visibility and quantum resistance.

---

## Honest Assessment

This is a **demo/research implementation** with real privacy properties:
- The ZK proof cryptographically unlinks deposit from withdrawal
- The server sees no depositor information in the correct implementation
- Circuit, hash function, and Merkle tree are correctly implemented
- Tests verify privacy invariants (no txHash in server queue, etc.)

What has NOT been done:
- Production trusted setup (multi-party ceremony)
- Audit of the Circom circuit against Ekubo's deployed verifier
- On-chain end-to-end test with actual Groth16 proof verification
- Load/performance testing of the proof generation flow
- Production nullifier set (Redis-backed)
- RapidSnark integration for fast proof generation

0 end-to-end tests with real ZK proofs have been run. The proof generation
code matches the circuit structure and compiles, but has not been exercised
against a deployed pool contract with real funds.
