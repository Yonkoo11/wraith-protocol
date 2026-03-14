/// Ekubo Privacy Pool interface — exact signatures from pool.cairo source
/// Source: github.com/EkuboProtocol/privacy-pools/pool/src/pool.cairo
///
/// CONFIRMED:
/// - deposit() emits Deposit(caller, secret_and_nullifier_hash, amount) -- caller is PUBLIC
/// - withdraw() uses Groth16 proof (BN254, NOT quantum-resistant)
/// - current_root() returns the Merkle root for proof generation

use starknet::ContractAddress;

#[starknet::interface]
pub trait IEkuboPool<TContractState> {
    /// Deposit into the privacy pool.
    /// secret_and_nullifier_hash = poseidon_hash(secret, nullifier)
    /// IMPORTANT: Your caller address is visible in the Deposit event.
    fn deposit(
        ref self: TContractState,
        secret_and_nullifier_hash: u256,
        amount: u256,
    ) -> bool;

    /// Withdraw from the privacy pool using a Groth16 proof.
    /// The proof encodes: root, nullifier_hash, recipient, fee, amount, associated_set_root
    fn withdraw(
        ref self: TContractState,
        proof: Span<felt252>,
    ) -> bool;

    /// Withdraw fees accumulated in the pool to a recipient.
    fn withdraw_fee(
        ref self: TContractState,
        recipient: ContractAddress,
        amount: u256,
    ) -> bool;

    /// Get the current Merkle root (needed for proof generation off-chain).
    fn current_root(self: @TContractState) -> u256;
}

/// CipherPolAgent on-chain identity (future: Starknet Account Abstraction)
/// Enables custom validation logic for agent payments.
#[starknet::interface]
pub trait ICipherPolAgent<TContractState> {
    /// Register a new payment channel with a counterparty API.
    fn open_channel(
        ref self: TContractState,
        counterparty: ContractAddress,
        token: ContractAddress,
        capacity: u256,
    ) -> felt252; // returns channel_id

    /// Record a completed payment (called during channel settlement).
    fn record_payment(
        ref self: TContractState,
        channel_id: felt252,
        amount: u256,
        nullifier_hash: u256,
    );

    /// Get total payments made through this agent.
    fn total_payments(self: @TContractState) -> u256;

    /// Get viewing key for compliance (STRK20 v2 only).
    fn viewing_key(self: @TContractState) -> felt252;
}
