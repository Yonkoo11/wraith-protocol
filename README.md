# Wraith Protocol

Private AI agent payments on Starknet using ZK proofs.

Pay for API calls without linking your identity to your on-chain activity. One deposit into a shared pool. Withdraw to any address. The server only learns the payment happened — not who paid.

## Packages

| Package | Description |
|---------|-------------|
| `wraith-agent` | SDK for AI agents to generate and send ZK payment proofs |
| `wraith-server` | Express middleware for APIs to accept Wraith payments |

## Quick start — Agent side

```bash
npm install wraith-agent
```

```ts
import { WraithAgent } from 'wraith-agent';

const agent = new WraithAgent({
  poolAddress: '0x...',
  providerUrl: 'https://starknet-mainnet.infura.io/v3/...',
});

// Agent automatically handles x402 challenges and pays with ZK proofs
const response = await agent.fetch('https://api.example.com/v1/chat', {
  method: 'POST',
  body: JSON.stringify({ prompt: 'Hello' }),
});
```

## Quick start — Server side

```bash
npm install wraith-server
```

```ts
import express from 'express';
import { wraithPaywall } from 'wraith-server';
import { Account, RpcProvider } from 'starknet';

const app = express();
const provider = new RpcProvider({ nodeUrl: process.env.STARKNET_RPC });
const account = new Account(provider, process.env.SERVER_ADDRESS, process.env.SERVER_KEY);

app.post('/v1/chat/completions',
  wraithPaywall({
    amount: 3000n,          // 0.003 USDC (6 decimals)
    token: 'USDC',
    poolAddress: '0x...',
    account,
    provider,
  }),
  (req, res) => {
    res.json({ message: 'Paid access granted' });
  }
);
```

## Architecture

```
Agent                          Server
  │                              │
  │── GET /api ─────────────────>│
  │<── 402 { challenge } ────────│
  │                              │
  │  [generate ZK proof ~4s]     │
  │                              │
  │── POST /api ────────────────>│
  │   X-Payment-Proof: <proof>   │── verify proof
  │                              │── check nullifier (no double-spend)
  │<── 200 { response } ─────────│── queue withdrawal to pool
```

The proof proves the agent controls a note in the pool without revealing which deposit it came from.

## Privacy model

- **Link-private**: deposit and withdrawal addresses are not linked on-chain
- **Not identity-private**: the depositor address is visible at deposit time
- **Anonymity set**: privacy depends on pool size. Small pool = weaker privacy
- **Trusted setup**: 1-party (local Powers of Tau). Not production-ready; MPC ceremony needed
- **Quantum**: BN254/Groth16 is not quantum-resistant

See `THREAT_MODEL.md` for the full analysis.

## Known limits

1. 1-party trusted setup — local Powers of Tau only
2. In-memory nullifier set — lost on restart, needs Redis for production
3. Proof generation ~4-6s with snarkjs WASM (RapidSnark would be ~100ms)
4. Small pool = trivial deanonymization

## License

MIT
