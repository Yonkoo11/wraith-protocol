/**
 * Wraith x402 Server Middleware
 *
 * Drop-in Express middleware for APIs that accept private Wraith payments.
 *
 * Usage:
 * ```ts
 * import express from 'express';
 * import { wraithPaywall } from 'wraith-agent/server';
 *
 * const app = express();
 *
 * app.post('/api/completion', wraithPaywall({
 *   amount: 3000n,
 *   token: 'USDC',
 *   serverAddress: process.env.STARKNET_ADDRESS!,
 *   poolAddress: process.env.POOL_ADDRESS,
 * }), yourHandler);
 * ```
 *
 * x402 flow (correct privacy-preserving version):
 * 1. Client GETs/POSTs endpoint
 * 2. Server returns 402 with challenge (amount, token, payTo = serverAddress, poolAddress)
 * 3. Client generates Groth16 ZK proof CLIENT-SIDE with recipient = serverAddress
 * 4. Client retries with X-Payment-Proof header containing { zkProof, nullifierHash, publicInputs }
 * 5. Middleware validates public inputs WITHOUT decrypting anything
 * 6. Middleware checks nullifierHash against in-memory spent set (replay prevention)
 * 7. Middleware queues the pre-generated proof for async Starknet submission
 * 8. Handler is called immediately; client gets response without waiting for on-chain confirmation
 *
 * Privacy properties:
 * - Server sees: a ZK proof that someone committed to paying me a specific amount
 * - Server does NOT see: txHash, depositor address, secret, nullifier
 * - Groth16 proof is verified by the pool contract when withdrawal is submitted
 * - If the proof is invalid, pool.withdraw() reverts — server served in good faith
 *
 * Security model:
 * - Nullifier tracking (NullifierSet) prevents proof replay within a server session
 * - On-chain nullifier storage prevents replay after withdrawal is confirmed
 * - Gap between acceptance and on-chain confirmation: mitigated by NullifierSet
 *
 * What can go wrong:
 * - Server restart before withdrawal confirms → in-memory NullifierSet is lost →
 *   same proof could be replayed. Use Redis for production.
 * - Client sends a proof with invalid Groth16 → pool.withdraw() reverts →
 *   server served a request that yields no funds. Acceptable for low-value APIs.
 */

import type { Request, Response, NextFunction } from 'express';
import {
  verifyPaymentProofFields,
  parsePaymentHeader,
  X402_SCHEME,
} from '../../dist/x402.js';
import type { X402PaymentProof } from '../../dist/types.js';
import { NullifierSet } from './nullifier-set.js';
import type { INullifierSet } from './nullifier-set.js';
import { WithdrawalQueue } from './withdrawal-queue.js';
import type { WithdrawalQueueConfig } from './withdrawal-queue.js';
import type { Account } from 'starknet';

export interface PaywallConfig {
  /** Required payment amount (in base units, e.g. 3000 = 0.003 USDC at 6 decimals) */
  amount: bigint;
  /** Token symbol ('USDC', 'STRK', etc.) — included in challenge, not verified on-chain */
  token: string;
  /**
   * Server's Starknet address (felt252 as 0x string).
   * The agent sets recipient = this address in its ZK proof.
   * Middleware rejects proofs where recipient != this address.
   */
  serverAddress: string;
  /** Pool address — included in the challenge so client knows where to deposit */
  poolAddress?: string;
  network?: string;
  /**
   * Optional withdrawal queue config.
   * If provided, accepted proofs are automatically submitted to Starknet.
   * If omitted, caller must handle submission via onVerified callback.
   */
  withdrawal?: Omit<WithdrawalQueueConfig, 'poolAddress'> & { poolAddress: string };
  /**
   * Optional nullifier set. Defaults to in-memory NullifierSet.
   * Pass a RedisNullifierSet for production (survives restarts, shared across replicas).
   */
  nullifierSet?: INullifierSet;
  /** Called after successful proof verification (before next()) */
  onVerified?: (proof: X402PaymentProof, req: Request) => void;
}

export interface WraithRequest extends Request {
  wraith?: {
    paid: true;
    amount: bigint;
    token: string;
    nullifierHash: string;
    /** ERC-8004 agent ID, if provided in the proof */
    agentId?: string;
    /** ERC-8004 agent registration URI, if provided in the proof */
    agentURI?: string;
  };
}

/**
 * Create an Express middleware that requires a valid Wraith ZK payment proof.
 *
 * The returned middleware is stateful — it holds a NullifierSet and optionally
 * a WithdrawalQueue. Create it once and reuse across requests:
 *
 *   const paywall = wraithPaywall({ ... });
 *   app.post('/api/query', paywall, handler);
 */
export function wraithPaywall(config: PaywallConfig) {
  const nullifiers: INullifierSet = config.nullifierSet ?? new NullifierSet();

  // Optionally start a withdrawal queue
  let queue: WithdrawalQueue | null = null;
  if (config.withdrawal) {
    queue = new WithdrawalQueue(config.withdrawal);
    queue.start();
  }

  return async function wraithMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    const proofHeader = req.headers['x-payment-proof'] as string | undefined;
    const schemeHeader = req.headers['x-payment-scheme'] as string | undefined;

    // No payment proof — issue a 402 challenge
    if (!proofHeader || schemeHeader !== X402_SCHEME) {
      res
        .status(402)
        .setHeader('WWW-Authenticate', buildChallenge(config))
        .json({
          error: 'Payment Required',
          scheme: X402_SCHEME,
          amount: config.amount.toString(),
          token: config.token,
          network: config.network ?? 'starknet-mainnet',
          payTo: config.serverAddress,
          poolAddress: config.poolAddress,
        });
      return;
    }

    // Parse the proof header
    let proof: X402PaymentProof;
    try {
      proof = parsePaymentHeader(proofHeader);
    } catch {
      res.status(400).json({ error: 'Malformed payment proof' });
      return;
    }

    // Validate public inputs (recipient, amount, scheme, structure)
    // This does NOT run Groth16 verification — that happens on-chain when we submit.
    const { valid, reason } = verifyPaymentProofFields(
      proof,
      config.amount,
      config.serverAddress
    );

    if (!valid) {
      res.status(402).json({ error: 'Payment verification failed', reason });
      return;
    }

    // Check for replay: has this nullifierHash been spent already?
    const nullifierHash = proof.nullifierHash;
    if (await nullifiers.has(nullifierHash)) {
      res.status(402).json({
        error: 'Payment verification failed',
        reason: `Nullifier already spent: ${nullifierHash.slice(0, 20)}...`,
      });
      return;
    }

    // Mark as spent BEFORE serving (prevents race conditions on concurrent requests)
    await nullifiers.add(nullifierHash);

    // Notify caller (e.g., for custom withdrawal handling)
    config.onVerified?.(proof, req);

    // Submit withdrawal to Starknet (fire-and-forget, off the critical path)
    if (queue && proof.zkProof && proof.zkProof.length > 0) {
      queue.enqueue(proof.zkProof, nullifierHash, config.amount);
    }

    // Attach payment info to request for downstream handlers
    (req as WraithRequest).wraith = {
      paid: true,
      amount: config.amount,
      token: config.token,
      nullifierHash,
      agentId: proof.agentId,
      agentURI: proof.agentURI,
    };

    // Strip the payment proof header before calling downstream handlers.
    // Without this, any logging middleware or error handler will capture the
    // full base64-encoded proof (including nullifierHash) in access logs,
    // error reports, APM traces, etc. — creating a persistent record that
    // links HTTP request timestamps to on-chain nullifiers.
    delete req.headers['x-payment-proof'];
    delete req.headers['x-payment-scheme'];

    next();
  };
}

/**
 * Build the WWW-Authenticate challenge header.
 *
 * Format: Wraith-Starknet-v1 network="starknet-mainnet",token="USDC",amount="3000",payTo="0x...",poolAddress="0x..."
 */
function buildChallenge(config: PaywallConfig): string {
  const parts = [
    `Wraith-Starknet-v1`,
    `network="${config.network ?? 'starknet-mainnet'}"`,
    `token="${config.token}"`,
    `amount="${config.amount}"`,
    `payTo="${config.serverAddress}"`,
  ];
  if (config.poolAddress) {
    parts.push(`poolAddress="${config.poolAddress}"`);
  }
  return parts.join(' ');
}
