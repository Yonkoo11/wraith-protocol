/**
 * STRK20Adapter — private payments via StarkWare's token-native privacy framework
 *
 * PRIVACY GUARANTEES (when STRK20 ships):
 * - Depositor address is HIDDEN (ZK-native, no on-chain link)
 * - Proof system: Stwo STARKs (hash-based = quantum-resistant)
 * - Anonymity set: unlimited (ZK-native, no minimum users required)
 * - Compliance: viewing keys + audit proofs
 * - No liquidity fragmentation (embedded in ERC-20 standard)
 *
 * STATUS: STUB — STRK20 contracts not yet public.
 * Monitor: github.com/starkware-libs + starknet.io/blog
 * When repo ships: read pool/src/*.cairo for exact function signatures.
 *
 * DO NOT USE IN PRODUCTION until repo is confirmed.
 */

import { IPrivacyAdapter, Note, PrivacyScore, AuditProof } from '../types.js';

export class STRK20Adapter implements IPrivacyAdapter {
  name = 'strk20';

  // Viewing key for this agent's identity
  // Generated at init, registered on-chain via STRK20
  private viewingKey: string;

  constructor(viewingKey?: string) {
    this.viewingKey =
      viewingKey ?? generateViewingKey();
  }

  getPrivacyScore(): PrivacyScore {
    return {
      adapter: this.name,
      depositorVisible: false,      // ZK-native: no on-chain identity link
      proofSystem: 'stark',         // Stwo STARKs (hash-based)
      quantumResistant: true,       // Hash-based proofs survive quantum
      anonymitySetSize: 'unlimited', // No minimum user threshold
      guarantee: 'zk-native',
    };
  }

  /**
   * Shield tokens into STRK20 private balance.
   *
   * Expected interface (from STRK20 whitepaper description):
   * fn shield(token: ContractAddress, amount: u256, commitment: felt252) -> Note
   *
   * UNCONFIRMED: exact function signature depends on repo.
   * Note discovery mechanism: likely ECDH-tagged events.
   * Confirm when github.com/starkware-libs repo ships.
   */
  async deposit(_amount: bigint, _token: string): Promise<{ txHash: string; note: Note }> {
    throw new Error(
      'STRK20Adapter.deposit() is a stub. ' +
        'STRK20 contracts are not yet public. ' +
        'Use PrivacyPoolsAdapter for demos, or wait for repo: github.com/starkware-libs'
    );
  }

  /**
   * Transfer within STRK20 private balance (shielded transfer).
   * Recipient identified by viewing key, not address.
   *
   * Expected interface:
   * fn shielded_transfer(recipient_key: felt252, amount: u256, note_in: Note) -> Note
   */
  async shieldedTransfer(
    _recipientKey: string,
    _amount: bigint,
    _noteIn: Note
  ): Promise<{ note: Note }> {
    throw new Error('STRK20Adapter.shieldedTransfer() is a stub.');
  }

  /**
   * Unshield tokens back to public balance.
   *
   * Expected interface:
   * fn unshield(token: ContractAddress, amount: u256, note_in: Note) -> bool
   */
  async withdraw(_note: Note, _recipient: string, _proof?: bigint[]): Promise<{ txHash: string }> {
    throw new Error('STRK20Adapter.withdraw() is a stub.');
  }

  /**
   * Generate compliance audit proof.
   * Proves payment amounts to a specific party without revealing counterparties.
   * Uses STRK20 viewing keys.
   */
  async generateAuditProof(
    _viewingKey: string,
    _range: { from: number; to: number }
  ): Promise<AuditProof> {
    throw new Error('STRK20Adapter.generateAuditProof() is a stub.');
  }

  /** Get the viewing key for this agent — share with auditors/regulators */
  getViewingKey(): string {
    return this.viewingKey;
  }
}

function generateViewingKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return '0x' + Buffer.from(bytes).toString('hex');
}
