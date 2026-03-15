# Hackathon Submission — Cipher Pol
# PL_Genesis: Frontiers of Collaboration (DevSpot)
# Deadline: March 31, 2026

---

## Submission Category: Existing Code
(Code was built before the hackathon start; submit under Existing Code track)

---

## Challenges to Submit To (with rationale)

### 1. Protocol Labs — Existing Code ($5,000, top 10)
The repo predates the hackathon. Qualifying as Existing Code with substantial new bounty
integrations added during the event:
- Lit Protocol encryption integration (encryptNoteForAPI, getLitSessionSigs)
- Starknet garaga verifier deployment (on-chain ZK proof verification)
- x402 HTTP payment protocol integration

### 2. Infrastructure & Digital Rights track ($3,000 1st / $2,000 2nd / $1,000 3rd)
Primary track. Cipher Pol is a privacy-preserving ZK payment system — exact category
description: "privacy-preserving technologies, cryptography, censorship-resistant."

### 3. AI & Robotics track ($3,000 1st / $2,000 2nd / $1,000 3rd)
The challenge description explicitly names x402: "new standards for machine payments (x402),
agent identity (ERC-8004), and inter-agent protocols." Cipher Pol IS that infrastructure.

### 4. Starknet ($1,000 × up to 5 winners)
Built on Starknet. Garaga verifier deployed on devnet. "Private payment app leveraging
Starknet infrastructure" is literally in their example list.

### 5. Lit Protocol: NextGen AI Apps ($500 1st / $300 2nd / $200 3rd)
Uses Lit Protocol V1 (Naga) SDK for:
- `encryptString` — wraps (secret, nullifier) notes with EVM access control condition
- `getSessionSigs` — SIWE flow verified against live Datil network (steps 1-3 pass)
Honest caveat: decrypt path written but unverified live (Datil capacity credits blocked;
faucet non-functional; Datil sunsets April 1). Code is correct — this is infrastructure.
Required tech: `lit-protocol-v1-naga-sdk` — our SDK is `@lit-protocol/lit-node-client@^7.4`.

### 6. Community Vote Bounty ($1,000)
Just a tweet. Compatible with all other submissions.
Post with @PL__Genesis @protocollabs and #PLGenesis.

---

## Categories Reserved for Second Project (DO NOT submit Cipher Pol here)

| Category | Prize | Notes |
|----------|-------|-------|
| Fresh Code | $5,000 | Second project is fresh code |
| Agents With Receipts 8004 | $4,000 | Highest unclaimed prize — second project should do real ERC-8004 on-chain registration |
| Agent Only: Let the agent cook | $4,000 | If second project is truly autonomous |
| Crypto track | $3,000 | Available |
| Filecoin | $1,250 | Available if second project uses Filecoin calibnet |
| Storacha | $200 | Available |
| NEAR | $500 | Available |

---

## Demo Video Requirements

**Unified spec: ≤ 3 minutes, YouTube** (Protocol Labs is the most restrictive at 3 min; Starknet
wants 3-5 min; Lit wants 2-5 min — 3 min satisfies all)

Structure:
1. Problem (30s): AI agents leak on-chain identity on every API payment
2. Live demo (90s):
   - Start devnet + rpc-proxy
   - Agent deposits into Ekubo pool (H(s,n) calldata)
   - Groth16 proof generates (~4-6s)
   - x402 402 challenge → proof in X-Payment-Proof header → 200 response
   - WithdrawalQueue batches proof, garaga calldata generated, pool.withdraw() accepted
3. Bounty integrations (30s): Starknet garaga verifier, Lit encryption, x402 protocol
4. Honest limits (30s): devnet only, 1-party trusted setup, anonymity set = pool size

Upload to YouTube, include link in all submission forms.

---

## What Is NOT Submittable (honest)

- **Agents With Receipts 8004**: erc8004.ts generates manifests but makes zero on-chain
  registration calls. The identityRegistry.register() call exists only in a code comment.
  Cannot submit without actual on-chain ERC-8004 registration.
- **Storacha**: @web3-storage/w3up-client is in package.json but never imported or called.
  ReceiptVault Cairo contract accepts a CID pointer but no upload implementation exists.
- **Filecoin**: No calibnet deployment, no actual Filecoin storage.
- **Fresh Code**: Repo predates hackathon.
- **Agent Only**: Cipher Pol is a payment system, not an autonomous agent.

---

## Submission Form Fields

### Name
Cipher Pol

### Tagline
ZK-native private payments for AI agents on Starknet.

### Problem
AI agents make millions of API calls. Every payment today links the agent's on-chain
identity to its activity. An observer watching the chain can reconstruct what the agent
did, which services it used, and when. x402 solves the payment rail. Cipher Pol solves
the identity problem.

### Solution
Three properties working together:

1. **Cryptographic unlinking.** The agent deposits into a shared pool (Ekubo Privacy Pools
   on Starknet). Later, it generates a Groth16 zero-knowledge proof that proves "I own a
   note in this pool" without revealing which deposit. Verified by a garaga 0.15.3 verifier
   on Starknet.

2. **Standard payment rail.** The proof travels via x402 HTTP header. One middleware line
   protects any Express endpoint. No changes to the agent's HTTP client beyond agent.pay().

3. **Double-spend prevention.** Nullifier hash stored in memory and on-chain. Same deposit
   cannot be used twice.

What the server learns: amount, timestamp, nullifierHash. Not the depositor address.

### What's Been Verified
Tested against starknet-devnet 0.7.2 (seed 42):
- 8/8 on-chain tests — deposit → Groth16 proof → garaga calldata → pool.withdraw()
- 13/13 server middleware tests
- 26/26 SDK integration tests — circuit, Merkle tree, proof generation, serialization
- 28/28 HTTP x402 end-to-end tests — full 402 challenge → ZK proof → 200 flow
- 7/7 WithdrawalQueue phases — garaga calldata 2918 felts, on-chain withdrawal, nullifier stored
- Lit Protocol encryption + SIWE session: verified against live Datil network (steps 1-3)

### Honest Limits
1. 1-party trusted setup — local Powers of Tau. MPC ceremony needed for production.
2. In-memory nullifier set — lost on restart. Redis needed.
3. Depositor address visible at deposit time — link-private, not identity-private.
4. Anonymity set = pool size — tiny on devnet (demo-grade).
5. BN254 is not quantum-resistant. v2: STARK proofs on Starknet.
6. Proof generation 4-6s (snarkjs WASM). RapidSnark would be ~100ms.
7. Lit Protocol decrypt unverified live — Datil capacity credits blocked, Chipotle migration needed.
Full analysis: docs/THREAT_MODEL.md

### Project Stage
Devnet prototype. All core flows verified. Not deployed to testnet or mainnet.

### Sponsor Bounty Integrations
- Lit Protocol V1 (Naga) SDK — encryption + SIWE session for note storage
- Starknet — garaga 0.15.3 ZK verifier, Cairo contracts, on-chain nullifier storage
- x402 — HTTP 402 payment protocol (primary payment rail)

### Track
Infrastructure & Digital Rights + AI & Robotics (can submit to both per rules)

### Code Type
Existing Code

### Links
- GitHub: https://github.com/Yonkoo11/cipher-pol
- Landing page: https://yonkoo11.github.io/cipher-pol/
- Demo video: [RECORD AND ADD YOUTUBE LINK]
- Twitter: @soligxbt

---

## Community Vote Tweet Draft

Built Cipher Pol for #PLGenesis.

AI agents make millions of API calls. Every payment reveals which on-chain identity paid,
which API, and when.

Cipher Pol uses Groth16 ZK proofs + x402 + Starknet to unlink deposit from payment.
The server gets paid. It cannot trace who paid.

82 tests passing on Starknet devnet.

Demo: https://yonkoo11.github.io/cipher-pol/
Code: https://github.com/Yonkoo11/cipher-pol

@PL__Genesis @protocollabs @StarkWareLtd @LitProtocol

---

## Second Project Planning Notes

Highest-value unclaimed categories:
1. Fresh Code + Agents With Receipts 8004 ($5,000 + $4,000) — real ERC-8004 on-chain
   registration is a small implementation step; the big value is building something that
   autonomously reads/writes ERC-8004 trust signals
2. Agent Only ($4,000) — truly autonomous agent with discover→plan→execute→verify→submit loop
3. Crypto track ($3,000) — onchain economics, programmable assets

Avoid: Infrastructure & Digital Rights, AI & Robotics, Starknet, Lit Protocol, Existing Code
(all claimed by Cipher Pol — one project per challenge category rule).
