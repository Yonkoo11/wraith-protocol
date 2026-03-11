/**
 * Demo API server with Wraith x402 paywall (correct privacy-preserving flow)
 *
 * This server accepts payments where the agent generates the ZK proof CLIENT-SIDE.
 * The server:
 *   1. Issues a 402 challenge with payment details (amount, token, serverAddress, poolAddress)
 *   2. Receives X-Payment-Proof containing { zkProof, nullifierHash, publicInputs }
 *   3. Validates public inputs (recipient = serverAddress, amount >= required)
 *   4. Tracks nullifierHash to prevent replay
 *   5. Queues the pre-generated ZK proof for async Starknet submission
 *
 * What this server does NOT do (vs old design):
 *   - Does NOT receive txHash or litCiphertext
 *   - Does NOT call Lit Protocol to decrypt secrets
 *   - Does NOT generate ZK proofs server-side
 *   - Does NOT look up depositor addresses
 *
 * Run:
 *   export API_STARKNET_ADDRESS=0x...
 *   export API_STARKNET_PRIVATE_KEY=0x...
 *   export POOL_ADDRESS=0x...
 *   tsx server/src/demo-server.ts
 */

import express, { type Request, type Response } from 'express';
import { Account, RpcProvider } from 'starknet';
import { wraithPaywall } from './middleware.js';
import { WithdrawalQueue } from './withdrawal-queue.js';

const app = express();
app.use(express.json());

const STARKNET_RPC = process.env.STARKNET_RPC_URL          ?? 'http://127.0.0.1:5050';
const API_ADDRESS  = process.env.API_STARKNET_ADDRESS      ?? '';
const API_PK       = process.env.API_STARKNET_PRIVATE_KEY  ?? '';
const POOL_ADDRESS = process.env.POOL_ADDRESS              ?? '';

if (!API_ADDRESS || !API_PK || !POOL_ADDRESS) {
  console.error(
    'Missing required env vars: API_STARKNET_ADDRESS, API_STARKNET_PRIVATE_KEY, POOL_ADDRESS'
  );
  process.exit(1);
}

const provider = new RpcProvider({ nodeUrl: STARKNET_RPC });
const account  = new Account(provider, API_ADDRESS, API_PK);

// Withdrawal queue — submits pre-generated proofs to Starknet every 5 minutes
const withdrawalQueue = new WithdrawalQueue({
  account,
  poolAddress: POOL_ADDRESS,
  rpcUrl:      STARKNET_RPC,
});
withdrawalQueue.start();

// ── Paid endpoint ──────────────────────────────────────────────────────────

const REQUIRED_AMOUNT = 3000n;  // 0.003 USDC (6 decimals)

app.post(
  '/v1/chat/completions',
  wraithPaywall({
    amount:        REQUIRED_AMOUNT,
    token:         'USDC',
    serverAddress: API_ADDRESS,
    poolAddress:   POOL_ADDRESS,
    onVerified: (proof) => {
      // withdrawalQueue.enqueue() is called automatically by the middleware
      // if withdrawal config is provided. For manual control:
      if (proof.zkProof && proof.zkProof.length > 0) {
        withdrawalQueue.enqueue(proof.zkProof, proof.nullifierHash, REQUIRED_AMOUNT);
      }
    },
  }),
  (req: Request, res: Response) => {
    const messages = (req.body.messages ?? []) as Array<{ role: string; content: string }>;
    const lastMessage = messages[messages.length - 1]?.content ?? '';

    res.json({
      id: `wraith-demo-${Date.now()}`,
      object: 'chat.completion',
      model: 'wraith-demo-v1',
      choices: [
        {
          index: 0,
          message: {
            role: 'assistant',
            content: `[Demo response to: "${lastMessage.slice(0, 50)}"]`,
          },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
    });
  }
);

// ── Health check ───────────────────────────────────────────────────────────

app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    pendingWithdrawals: withdrawalQueue.pendingCount,
    serverAddress: API_ADDRESS,
    poolAddress: POOL_ADDRESS,
  });
});

// ── Start ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? '3000');
app.listen(PORT, () => {
  console.log(`Wraith demo server on port ${PORT}`);
  console.log(`POST /v1/chat/completions — requires 0.003 USDC Wraith payment`);
  console.log(`GET  /health — server status`);
});

export { app };
