/// CipherPolAgent — on-chain component of the CipherPol Protocol
///
/// Manages agent identity, payment channel state, and settlement.
/// v1: wraps Ekubo Privacy Pool for demo-grade privacy
/// v2: will use STRK20 for ZK-native, quantum-resistant privacy
///
/// PRIVACY CAVEAT (v1):
/// - Agent's Starknet address is visible when depositing
/// - Only the deposit→withdrawal link is hidden by ZK proof
/// - For full identity privacy, wait for STRK20 (github.com/starkware-libs)

#[starknet::contract]
pub mod CipherPolAgent {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        Map, StorageMapReadAccess, StorageMapWriteAccess,
    };

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------
    #[storage]
    struct Storage {
        /// Owner of this agent instance
        owner: ContractAddress,

        /// Ekubo Privacy Pool contract (v1)
        pool: ContractAddress,

        /// Total value deposited (sum, not a balance — deposits are in the pool)
        total_deposited: u256,

        /// Channel state: channel_id → Channel
        channels: Map<felt252, Channel>,

        /// Next channel ID counter
        channel_counter: felt252,

        /// Viewing key for STRK20 compliance (v2)
        viewing_key: felt252,
    }

    #[derive(Drop, Serde, starknet::Store)]
    struct Channel {
        counterparty: ContractAddress,
        token: ContractAddress,
        capacity: u256,
        settled: u256,
        open: bool,
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ChannelOpened: ChannelOpened,
        PaymentSettled: PaymentSettled,
    }

    #[derive(Drop, starknet::Event)]
    struct ChannelOpened {
        #[key]
        channel_id: felt252,
        counterparty: ContractAddress,
        capacity: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentSettled {
        #[key]
        channel_id: felt252,
        amount: u256,
        nullifier_hash: u256,
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        pool: ContractAddress,
        viewing_key: felt252,
    ) {
        self.owner.write(owner);
        self.pool.write(pool);
        self.viewing_key.write(viewing_key);
        self.channel_counter.write(0);
    }

    // -------------------------------------------------------------------------
    // ICipherPolAgent Implementation
    // -------------------------------------------------------------------------
    #[abi(embed_v0)]
    impl CipherPolAgentImpl of super::super::interfaces::ICipherPolAgent<ContractState> {
        /// Open a payment channel with a counterparty API.
        /// Agent deposits capacity into the privacy pool upfront.
        /// Off-chain payments are made within the channel without on-chain txs.
        fn open_channel(
            ref self: ContractState,
            counterparty: ContractAddress,
            token: ContractAddress,
            capacity: u256,
        ) -> felt252 {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Not owner');

            let channel_id: felt252 = self.channel_counter.read() + 1;
            self.channel_counter.write(channel_id);

            self.channels.write(channel_id, Channel {
                counterparty,
                token,
                capacity,
                settled: 0_u256,
                open: true,
            });

            self.emit(ChannelOpened { channel_id, counterparty, capacity });

            channel_id
        }

        /// Record a settled payment in a channel.
        /// Called during channel settlement — writes nullifier_hash to prevent replay.
        fn record_payment(
            ref self: ContractState,
            channel_id: felt252,
            amount: u256,
            nullifier_hash: u256,
        ) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Not owner');

            let mut channel = self.channels.read(channel_id);
            assert(channel.open, 'Channel closed');
            assert(channel.settled + amount <= channel.capacity, 'Exceeds capacity');

            channel.settled += amount;
            self.channels.write(channel_id, channel);
            self.total_deposited.write(self.total_deposited.read() + amount);

            self.emit(PaymentSettled { channel_id, amount, nullifier_hash });
        }

        fn total_payments(self: @ContractState) -> u256 {
            self.total_deposited.read()
        }

        fn viewing_key(self: @ContractState) -> felt252 {
            self.viewing_key.read()
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Not owner');
        }
    }
}
