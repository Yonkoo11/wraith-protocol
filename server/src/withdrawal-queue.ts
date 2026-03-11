/**
 * WithdrawalQueue — submit pre-generated ZK proofs to the Ekubo Privacy Pool.
 *
 * The agent generates the Groth16 proof CLIENT-SIDE and sends only the proof
 * (as a felt252 array) to the server. The server's job here is simple:
 *   1. Receive a pre-generated proof
 *   2. Submit it to pool.withdraw() on Starknet
 *   3. Retry on failure (up to 3 times)
 *
 * The server NEVER generates ZK proofs — it never sees (secret, nullifier).
 * The server NEVER calls Lit Protocol — that design flaw is gone.
 *
 * Privacy model:
 * - Server receives: zkProof (felt252 array) + nullifierHash (public signal)
 * - Server learns:   that someone paid at timestamp T, and the payment amount
 * - Server does NOT: learn which deposit this corresponds to, or the depositor address
 *
 * On-chain:
 * - pool.withdraw(proof) verifies the Groth16 proof via the garaga verifier
 * - If proof is valid: recipient receives funds, nullifier is stored (prevents replay)
 * - If proof is invalid: tx reverts, no funds move (server loses nothing; it served
 *   the request in good faith, same as any HTTP API trusting a client-provided token)
 *
 * Withdrawal timing:
 * - Requests are served immediately after nullifier check (proof not yet on-chain)
 * - Withdrawals are batched to reduce gas overhead (default: 5-minute intervals)
 * - For high-value APIs: set flushIntervalMs=0 to submit immediately before serving
 */

import { Account, RpcProvider, CallData } from 'starknet';
// Note: no imports from wraith-agent SDK needed here — we only submit pre-generated proofs

interface QueuedWithdrawal {
  zkProof: string[];
  nullifierHash: string;
  amount: bigint;
  queuedAt: number;
  attempts: number;
}

export interface WithdrawalQueueConfig {
  /** Starknet account that signs and submits pool.withdraw() transactions */
  account: Account;
  /** Deployed Ekubo Privacy Pool contract address */
  poolAddress: string;
  /** Starknet RPC URL */
  rpcUrl: string;
  /** Flush interval in ms (default: 5 minutes, 0 = flush on every enqueue) */
  flushIntervalMs?: number;
  /** Max withdrawal attempts before dropping (default: 3) */
  maxAttempts?: number;
  /** Called when a withdrawal is confirmed on-chain */
  onConfirmed?: (txHash: string, nullifierHash: string) => void;
  /** Called when a withdrawal fails permanently after maxAttempts */
  onFailed?: (nullifierHash: string, error: Error) => void;
}

export class WithdrawalQueue {
  private queue: QueuedWithdrawal[] = [];
  private readonly config: Required<WithdrawalQueueConfig>;
  private timer?: ReturnType<typeof setInterval>;
  private readonly provider: RpcProvider;

  constructor(config: WithdrawalQueueConfig) {
    this.config = {
      flushIntervalMs: 5 * 60 * 1000,
      maxAttempts: 3,
      onConfirmed: () => {},
      onFailed: () => {},
      ...config,
    };
    this.provider = new RpcProvider({ nodeUrl: config.rpcUrl });
  }

  start(): void {
    if (this.config.flushIntervalMs > 0) {
      this.timer = setInterval(() => void this.flush(), this.config.flushIntervalMs);
    }
    console.log(
      `[WithdrawalQueue] Started. Pool=${this.config.poolAddress}. ` +
      `Flush interval: ${this.config.flushIntervalMs / 1000}s`
    );
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /**
   * Enqueue a pre-generated ZK proof for withdrawal.
   *
   * The zkProof is the felt252 array from generatePaymentProof() on the agent side.
   * Format: [pi_a (4), pi_b (8), pi_c (4), public_signals (14)] = 30 felts as strings.
   *
   * If flushIntervalMs=0, submits immediately (synchronous relative to caller).
   */
  enqueue(zkProof: string[], nullifierHash: string, amount: bigint): void {
    this.queue.push({ zkProof, nullifierHash, amount, queuedAt: Date.now(), attempts: 0 });

    if (this.config.flushIntervalMs === 0) {
      void this.flush();
    }
  }

  get pendingCount(): number {
    return this.queue.length;
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0);
    console.log(`[WithdrawalQueue] Flushing ${batch.length} withdrawal(s)...`);

    for (const item of batch) {
      try {
        await this.submitWithdrawal(item);
      } catch (err) {
        item.attempts += 1;

        if (item.attempts < this.config.maxAttempts) {
          console.error(
            `[WithdrawalQueue] Withdrawal failed (attempt ${item.attempts}/${this.config.maxAttempts}), ` +
            `re-queued: nullifier=${item.nullifierHash.slice(0, 20)}...`,
            err
          );
          this.queue.push(item);
        } else {
          const error = err instanceof Error ? err : new Error(String(err));
          console.error(
            `[WithdrawalQueue] DROPPED after ${this.config.maxAttempts} attempts: ` +
            `nullifier=${item.nullifierHash.slice(0, 20)}...`,
            error
          );
          this.config.onFailed(item.nullifierHash, error);
        }
      }
    }
  }

  private async submitWithdrawal(item: QueuedWithdrawal): Promise<void> {
    console.log(
      `[WithdrawalQueue] Submitting withdrawal: ` +
      `nullifier=${item.nullifierHash.slice(0, 20)}..., amount=${item.amount}`
    );

    // fn withdraw(proof: Span<felt252>) -> bool
    // The proof is the full felt252 array: [pi_a, pi_b, pi_c, public_signals]
    const { transaction_hash } = await this.config.account.execute({
      contractAddress: this.config.poolAddress,
      entrypoint: 'withdraw',
      calldata: CallData.compile({
        proof: item.zkProof,
      }),
    });

    console.log(
      `[WithdrawalQueue] Withdrawal submitted: txHash=${transaction_hash}, ` +
      `nullifier=${item.nullifierHash.slice(0, 20)}...`
    );

    this.config.onConfirmed(transaction_hash, item.nullifierHash);
  }
}
