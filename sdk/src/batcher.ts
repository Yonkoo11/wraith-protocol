/**
 * PaymentBatcher — groups payments into time windows + amount buckets
 * to break timing correlation and amount-based deanonymization attacks.
 *
 * Attack vector it defeats:
 * - Observer sees Agent A deposit 0.003 USDC at T=0
 * - Observer sees API withdraw 0.003 USDC at T=1s
 * - Correlation: Agent A paid API B
 *
 * Defense:
 * - Batch deposits from multiple agents in 60s windows
 * - Round amounts to standard buckets (0.001, 0.01, 0.1, 1.0, 10.0 USDC)
 * - Withdraw as a batch, not one-to-one
 */

import { Note, PaymentIntent } from './types.js';

const DEFAULT_WINDOW_MS = 60_000; // 60 seconds
const DEFAULT_BUCKETS_USDC = [
  1_000n,       // 0.001 USDC (6 decimals)
  10_000n,      // 0.01 USDC
  100_000n,     // 0.1 USDC
  1_000_000n,   // 1.0 USDC
  10_000_000n,  // 10.0 USDC
  100_000_000n, // 100.0 USDC
];

interface QueuedPayment {
  intent: PaymentIntent;
  resolve: (note: Note) => void;
  reject: (err: Error) => void;
  enqueuedAt: number;
}

export class PaymentBatcher {
  private queue: QueuedPayment[] = [];
  private windowMs: number;
  private buckets: bigint[];
  private flushTimer?: ReturnType<typeof setTimeout>;

  constructor(
    windowMs: number = DEFAULT_WINDOW_MS,
    buckets: bigint[] = DEFAULT_BUCKETS_USDC
  ) {
    this.windowMs = windowMs;
    this.buckets = buckets.sort((a, b) => (a < b ? -1 : 1));
  }

  /**
   * Enqueue a payment. Returns a promise that resolves when the batch flushes.
   * maxLatencyMs on the intent can force an early flush.
   */
  enqueue(intent: PaymentIntent): Promise<Note> {
    return new Promise((resolve, reject) => {
      this.queue.push({ intent, resolve, reject, enqueuedAt: Date.now() });

      const maxLatency = intent.maxLatencyMs ?? this.windowMs;

      // If this payment has a tighter latency requirement, flush sooner
      if (maxLatency < this.windowMs) {
        this.scheduleFlush(maxLatency);
      } else if (!this.flushTimer) {
        this.scheduleFlush(this.windowMs);
      }
    });
  }

  /**
   * Round an amount UP to the nearest standard bucket.
   * Agent pays the bucket amount; overpay stays in the pool as future balance.
   */
  roundToBucket(amount: bigint): bigint {
    for (const bucket of this.buckets) {
      if (amount <= bucket) return bucket;
    }
    // Amount exceeds all buckets — use as-is (rare, large payments)
    return amount;
  }

  private scheduleFlush(delayMs: number): void {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = setTimeout(() => this.flush(), delayMs);
  }

  /**
   * Flush the current batch.
   * In practice, this hands off to the adapter's deposit() for each queued item.
   * The batching effect comes from multiple agents flushing into the same pool
   * within the same time window — their deposits are indistinguishable.
   */
  private async flush(): Promise<void> {
    this.flushTimer = undefined;
    const batch = this.queue.splice(0);
    if (batch.length === 0) return;

    // Each payment deposits separately but in the same time window
    // TODO: in v2, aggregate into a single batched tx when STRK20 supports it
    for (const item of batch) {
      // Signal that this item should be processed now
      // Actual deposit happens in WraithAgent which holds the adapter
      // We resolve with a placeholder note — WraithAgent overwrites this
      item.resolve({
        secret: 0n,
        nullifier: 0n,
        amount: this.roundToBucket(item.intent.amount),
        token: item.intent.token,
        spent: false,
        commitment: 0n,
        leafIndex: -1,
      });
    }
  }

  /** Force immediate flush (e.g., on shutdown) */
  async flushNow(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    await this.flush();
  }
}
