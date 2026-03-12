# Wraith Protocol - Architecture Memory

## What We Are Building
Agent SDK for private AI payments on Starknet. NOT a new privacy pool.
npm package: `wraith-agent` | pip package: `wraith-agent`

## Adapter Pattern
```
wraith-agent
├── STRK20Adapter       PRIMARY — stub until repo ships (3-5 days)
├── PrivacyPoolsAdapter DEMO — Ekubo pool (live), Groth16, depositor visible
├── AgentIdentity       Starknet AA, custom validation
├── PaymentBatcher      60s windows, amount bucketing
├── ComplianceEngine    STRK20 viewing keys / association set proofs
├── ReceiptVault        Storacha/Filecoin + Lit Protocol
└── Integrations        x402, LangChain, AutoGen
```

## Ekubo Privacy Pool (LIVE) — github.com/EkuboProtocol/privacy-pools
Exact interface confirmed from Cairo source:
```cairo
fn deposit(secret_and_nullifier_hash: u256, amount: u256) -> bool
fn withdraw(proof: Span<felt252>) -> bool  // Groth16
fn current_root() -> u256
// Events
Deposit(caller, secret_and_nullifier_hash, amount)  // caller IS visible
Withdrawal(caller, recipient, amount, associated_set_root)
```

## Privacy Guarantees (HONEST)
v1 (Ekubo pool):
- Depositor address IS VISIBLE
- Link deposit→withdrawal is hidden via ZK (Groth16, NOT quantum-resistant)
- Near-zero Starknet anonymity set (demo-grade only)

v2 (STRK20, when repo ships):
- ZK-native, no anonymity floor required
- Stwo STARKs = quantum-resistant
- Compliance via viewing keys

## x402 Payment Flow (v1)
1. Agent generates (secret, nullifier) locally
2. deposit(hash(secret, nullifier), amount) — agent address visible on-chain
3. Wraith sends (secret, nullifier) to API via Lit-encrypted channel
4. API verifies Deposit event (instant, no latency issue)
5. API grants access
6. API batches withdrawal proofs later (no realtime pressure)

## Competitors
- Cloak (Karnot): agent orchestration + private x402 via Tongo. One on-chain tx per payment.
- Wraith diff: payment channels (off-chain throughput) + libp2p network privacy + agent SDK first

## Economic Model
- 0.1% settlement fee on withdrawals
- Pool backend is free (we route through existing pools)

## STRK20 Note Discovery
- UNRESOLVED until repo ships
- Contingency: if slow, route x402 through Ekubo commitment scheme; use STRK20 for non-realtime
- Monitor: github.com/starkware-libs + starknet.io/blog

## Judges / Partners
- David Sneider (Lit Protocol co-founder) = judge → prioritize ReceiptVault integration
- 0xbow open to SDK integration
- Mist.cash open to partnership

## Build Order
1. PrivacyPoolsAdapter (Cairo interface wrapper)
2. TypeScript SDK shell (adapter pattern)
3. x402 middleware
4. PaymentBatcher
5. STRK20Adapter stub
6. ReceiptVault (Storacha + Lit)
7. LangChain/AutoGen plugins
