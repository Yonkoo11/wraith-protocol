/**
 * NullifierSet — in-memory double-spend prevention for the server.
 *
 * Tracks nullifierHashes received in payment proofs before they are confirmed
 * on-chain. Once the pool contract processes pool.withdraw(), it records the
 * nullifier permanently in contract storage. Until then, this set is the only
 * guard against replay attacks.
 *
 * PRODUCTION NOTE:
 * An in-memory set is lost on server restart. A payment proof submitted just
 * before a restart could be replayed after it. For production, persist this
 * set to a database (Redis, Postgres) with TTL = max time from proof acceptance
 * to on-chain confirmation (typically 60-120s on Starknet).
 *
 * The economic risk of an in-memory set:
 * - Attacker captures a valid proof from your logs
 * - Server restarts (crash, deploy, etc.)
 * - Attacker replays the same proof before the original withdrawal confirms
 * - Server serves a second request for the same nullifier
 * - On-chain: first withdrawal succeeds, second fails (pool rejects spent nullifier)
 * - Net loss: one free API call per restart event
 *
 * For low-value APIs this risk is acceptable. For high-value APIs, use Redis.
 */
export class NullifierSet {
  private readonly spent = new Set<string>();

  /**
   * Check if a nullifierHash has already been spent.
   * Compare case-insensitively (felt252 hex may be upper or lower case).
   */
  has(nullifierHash: string): boolean {
    return this.spent.has(nullifierHash.toLowerCase());
  }

  /**
   * Mark a nullifierHash as spent.
   * Call this BEFORE calling next() in middleware, not after.
   */
  add(nullifierHash: string): void {
    this.spent.add(nullifierHash.toLowerCase());
  }

  /**
   * Remove a nullifierHash from the set (e.g., if withdrawal fails permanently).
   * Use with care: removing a nullifier allows replay.
   */
  remove(nullifierHash: string): void {
    this.spent.delete(nullifierHash.toLowerCase());
  }

  get size(): number {
    return this.spent.size;
  }
}
