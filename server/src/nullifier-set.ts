/**
 * NullifierSet — double-spend prevention for the server.
 *
 * Tracks nullifierHashes received in payment proofs before they are confirmed
 * on-chain. Once the pool contract processes pool.withdraw(), it records the
 * nullifier permanently in contract storage. Until then, this set is the only
 * guard against replay attacks.
 *
 * Two implementations:
 * - NullifierSet: in-memory. Fast, zero deps, survives until process restart.
 * - RedisNullifierSet: Redis-backed. Survives restarts, shared across replicas.
 *
 * Production vulnerability of in-memory set:
 * - Attacker captures a valid proof (from logs, network sniff, whatever)
 * - Server restarts (crash, deploy, OOM)
 * - Attacker replays before the original on-chain withdrawal confirms
 * - Server serves a second request for the same nullifier
 * - On-chain: first withdrawal succeeds, second fails (pool rejects spent nullifier)
 * - Net loss: one free API call per server restart event
 *
 * For low-value APIs (< $0.10/call) the in-memory set is acceptable.
 * For high-value APIs: use RedisNullifierSet.
 */

/** Shared interface. Pass either implementation to cipherPolPaywall(). */
export interface INullifierSet {
  has(nullifierHash: string): boolean | Promise<boolean>;
  add(nullifierHash: string): void | Promise<void>;
  remove(nullifierHash: string): void | Promise<void>;
  readonly size: number | Promise<number>;
}

export class NullifierSet implements INullifierSet {
  private readonly spent = new Set<string>();

  has(nullifierHash: string): boolean {
    return this.spent.has(nullifierHash.toLowerCase());
  }

  add(nullifierHash: string): void {
    this.spent.add(nullifierHash.toLowerCase());
  }

  remove(nullifierHash: string): void {
    this.spent.delete(nullifierHash.toLowerCase());
  }

  get size(): number {
    return this.spent.size;
  }
}

/**
 * Redis-backed nullifier set. Survives server restarts and scales across replicas.
 *
 * Requires a Redis client implementing the minimal interface below.
 * Works with `redis` v4 (npm install redis) or `ioredis`:
 *
 * ```ts
 * import { createClient } from 'redis';
 * const redis = await createClient({ url: process.env.REDIS_URL }).connect();
 * const nullifiers = new RedisNullifierSet(redis, { key: 'cipher-pol:nullifiers' });
 * ```
 *
 * The key holds a Redis Set. No TTL by default — nullifiers must persist at
 * least until the on-chain nullifier is stored (typically 60-120s on Starknet).
 */
export class RedisNullifierSet implements INullifierSet {
  private readonly client: RedisLike;
  private readonly key: string;

  constructor(
    client: RedisLike,
    opts: { key?: string } = {}
  ) {
    this.client = client;
    this.key = opts.key ?? 'cipher-pol:nullifiers';
  }

  async has(nullifierHash: string): Promise<boolean> {
    return this.client.sIsMember(this.key, nullifierHash.toLowerCase());
  }

  async add(nullifierHash: string): Promise<void> {
    await this.client.sAdd(this.key, nullifierHash.toLowerCase());
  }

  async remove(nullifierHash: string): Promise<void> {
    await this.client.sRem(this.key, nullifierHash.toLowerCase());
  }

  get size(): Promise<number> {
    return this.client.sCard(this.key);
  }
}

/**
 * Minimal Redis client interface.
 * Compatible with `redis` v4 and `ioredis` (method names match redis v4).
 */
export interface RedisLike {
  sAdd(key: string, member: string): Promise<number>;
  sIsMember(key: string, member: string): Promise<boolean>;
  sRem(key: string, member: string): Promise<number>;
  sCard(key: string): Promise<number>;
}
