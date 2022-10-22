use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{
    collections::TreeMap,
    env,
    json_types::{Base64VecU8, U128},
    log, near_bindgen, require,
    serde_json::json,
    AccountId, Gas, PanicOnDefault, Promise, PromiseOrValue,
};

use crate::{
    lockup::{FullDeposit, Lockups},
    num::*,
    tx_decoder::{Tx, TxType},
    verifier::{alt_bn128_groth16verify, VK},
};

mod lockup;
mod num;
mod tx_decoder;
mod verifier;

pub const MAX_GAS: Gas = Gas(300_000_000_000_000);
const FIRST_ROOT: U256 = U256::from_const_str(
    "11469701942666298368112882412133877458305516134926649826543144744382391691533",
);
const R: U256 = U256::from_const_str(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
const HALF_MAX: U256 = U256([u64::MAX, u64::MAX, 0, 0]);

#[near_bindgen]
#[derive(PanicOnDefault, BorshDeserialize, BorshSerialize)]
pub struct PoolContract {
    /// Operator is an entity that can make new transactions.
    operator: AccountId,
    /// Transaction verifying key.
    tx_vk: VK,
    /// Merkle tree verifying key.
    tree_vk: VK,
    /// The next transaction index.
    pool_index: U256,
    /// Merkle roots. "transaction index" => "merkle root"
    roots: TreeMap<U256, U256>,
    /// Nullifiers for used accounts. "transaction index" => "nullifier".
    nullifiers: TreeMap<U256, U256>,
    /// Accumulative transaction hash
    all_messages_hash: U256,
    denominator: U256,
    /// Temporary deposits: simulation of ethereum's allowance system.
    // TODO: Allow multiple deposits per user
    lockups: Lockups,
}

impl PoolContract {
    fn check_operator(&self) -> AccountId {
        if env::signer_account_id() != self.operator {
            panic!("Only operator can call this method");
        }

        self.operator.clone()
    }
}

#[near_bindgen]
impl PoolContract {
    #[init]
    pub fn new_bin(
        #[serializer(borsh)] tx_vk: VK,
        #[serializer(borsh)] tree_vk: VK,
        #[serializer(borsh)] token_id: AccountId,
        #[serializer(borsh)] denominator: U256,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");

        if token_id.as_str() != "near" && cfg!(not(feature = "ft")) {
            env::panic_str("Non NEAR tokens are not supported");
        }

        let mut roots = TreeMap::new("roots".as_bytes());
        roots.insert(&U256::ZERO, &FIRST_ROOT);

        let default_operator = env::signer_account_id();

        Self {
            tx_vk,
            tree_vk,
            roots,
            operator: default_operator,
            pool_index: U256::ZERO,
            nullifiers: TreeMap::new("nullifiers".as_bytes()),
            all_messages_hash: U256::ZERO,
            denominator,
            lockups: Lockups::new(token_id),
        }
    }

    /// Accepts transaction and merkle tree verifying keys.
    #[init]
    pub fn new(
        tx_vk: Base64VecU8,
        tree_vk: Base64VecU8,
        token_id: AccountId,
        denominator: String,
    ) -> Self {
        assert!(!env::state_exists(), "Already initialized");

        if token_id.as_str() != "near" && cfg!(not(feature = "ft")) {
            env::panic_str("Non NEAR tokens are not supported");
        }

        let tx_vk = VK::deserialize(&mut &Vec::<u8>::from(tx_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));
        let tree_vk = VK::deserialize(&mut &Vec::<u8>::from(tree_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));

        let denominator = U256::from_str(&denominator).unwrap_or_else(|_| {
            env::panic_str("Cannot parse denominator. It should be a decimal number.")
        });

        let mut roots = TreeMap::new("roots".as_bytes());
        roots.insert(&U256::ZERO, &FIRST_ROOT);

        let default_operator = env::signer_account_id();

        Self {
            tx_vk,
            tree_vk,
            roots,
            operator: default_operator,
            pool_index: U256::ZERO,
            nullifiers: TreeMap::new("nullifiers".as_bytes()),
            all_messages_hash: U256::ZERO,
            denominator,
            lockups: Lockups::new(token_id),
        }
    }

    /// Set the operator (relayer).
    #[private]
    pub fn set_operator(&mut self, operator: AccountId) {
        self.operator = operator;
    }

    #[result_serializer(borsh)]
    pub fn denominator(&self) -> U256 {
        self.denominator
    }

    /// Can be called by a client to reserve a certain amount of yoctoNEAR for use in the `transact`
    /// method. Returns the lockup ID.
    #[payable]
    pub fn lock(&mut self, amount: U128) -> u64 {
        let attached_amount = env::attached_deposit();
        let signer = env::signer_account_id();

        require!(
            amount.0 == attached_amount,
            "Invalid attached amount: must be equal to the specified amount"
        );

        self.lockups.lock(signer, amount.0)
    }

    /// Release the funds previously reserved with the `lock` method.
    pub fn release(&mut self, id: u64) -> Promise {
        let signer = env::signer_account_id();
        self.lockups.release(signer, id)
    }

    /// Get all locks for the specified account in JSON format.
    /// ```json
    /// [{ nonce: 123, amount: "123", timestamp: "123" }, ...]
    /// ```
    pub fn account_locks(&self, account_id: AccountId) -> Vec<FullDeposit> {
        self.lockups.account_deposits(account_id)
    }

    /// Return the index of the next transaction.
    #[result_serializer(borsh)]
    pub fn pool_index(&self) -> U256 {
        self.pool_index
    }

    /// Return the merkle root at the specified transaction index.
    #[result_serializer(borsh)]
    pub fn merkle_root(&self, #[serializer(borsh)] index: U256) -> Option<U256> {
        self.roots.get(&index)
    }

    /// The main transaction method.
    /// Validates the transaction, handles deposits/withdrawals, pays fees to the operator.
    /// Can only be called by the current operator.
    pub fn transact(&mut self, #[serializer(borsh)] tx: Tx) -> PromiseOrValue<U128> {
        let operator_id = self.check_operator();
        let message_hash = tx.memo.hash();
        let message_hash_num = U256::from_big_endian(&message_hash).unchecked_rem(R);
        let mut pool_index: U256 = self.pool_index;
        let root_before = self
            .roots
            .get(&pool_index)
            .unwrap_or_else(|| env::panic_str("Root not found"));

        // Verify transaction proof
        const POOL_ID: U256 = U256::ZERO;
        const DELTA_SIZE: u32 = 256;
        let delta = tx.delta.unchecked_add(POOL_ID.unchecked_shr(DELTA_SIZE));

        let transact_inputs = [
            root_before,
            tx.nullifier,
            tx.out_commit,
            delta,
            message_hash_num,
        ];

        if !alt_bn128_groth16verify(self.tx_vk.clone(), tx.transact_proof, &transact_inputs) {
            env::panic_str("Transaction proof is invalid.");
        }

        if self.nullifiers.contains_key(&tx.nullifier) {
            env::panic_str("Double spend.");
        }

        if tx.transfer_index > pool_index.into() {
            env::panic_str("Transfer index is greater than pool index.");
        }

        // Verify tree proof
        let tree_inputs = [root_before, tx.root_after, tx.out_commit];
        if !alt_bn128_groth16verify(self.tree_vk.clone(), tx.tree_proof, &tree_inputs) {
            env::panic_str("Tree proof is invalid.");
        }

        // Set the nullifier
        let mut elements = [0u8; core::mem::size_of::<U256>() * 2];
        elements[..core::mem::size_of::<U256>()].copy_from_slice(&tx.out_commit.to_little_endian());
        elements[core::mem::size_of::<U256>()..].copy_from_slice(&tx.delta.to_little_endian());
        let hash = U256::from_little_endian(&env::keccak256_array(&elements));

        pool_index = U256::from(pool_index).unchecked_add(U256::from(128u8));

        // Calculate all_messages_hash
        let mut hashes = [0u8; core::mem::size_of::<U256>() * 2];
        hashes[..core::mem::size_of::<U256>()]
            .copy_from_slice(&self.all_messages_hash.to_little_endian());
        hashes[core::mem::size_of::<U256>()..].copy_from_slice(&message_hash);
        let new_all_messages_hash = U256::from_big_endian(&env::keccak256_array(&hashes));

        let fee = tx.memo.fee();
        let token_amount = tx.token_amount.overflowing_add(fee).0;
        let energy_amount = tx.energy_amount;

        let mut res = PromiseOrValue::Value(0u128.into());

        match tx.tx_type {
            TxType::Deposit => {
                log!("Deposit: {}", token_amount);
                if token_amount > HALF_MAX || energy_amount != U256::ZERO {
                    env::panic_str("Token amount must be negative and energy_amount must be zero.");
                }

                self.lockups
                    .spend(tx.deposit_address.clone(), tx.deposit_id);
            }
            TxType::Transfer => {
                log!("Transfer: {}", token_amount);
                if token_amount != U256::ZERO || energy_amount != U256::ZERO {
                    env::panic_str("Transfer tx must have zero token and energy amount.");
                }
            }
            TxType::Withdraw => {
                let dest = tx.memo.address();
                let withdraw_amount = token_amount
                    .overflowing_neg()
                    .0
                    .unchecked_mul(self.denominator);

                log!("Withdrawal to {}: {}", dest, withdraw_amount);

                let withdraw_amount = withdraw_amount.try_into().unwrap();

                if tx.token_id.as_str() == "near" {
                    res = PromiseOrValue::Promise(Promise::new(dest).transfer(withdraw_amount));
                } else if cfg!(not(feature = "ft")) {
                    env::panic_str("Non NEAR tokens are not supported");
                } else {
                    res = PromiseOrValue::Promise(
                        Promise::new(tx.token_id.clone()).function_call(
                            "ft_transfer".to_string(),
                            json!({
                                "receiver_id": dest,
                                "amount": withdraw_amount,
                                "memo": "withdraw",
                            })
                            .to_string()
                            .into_bytes(),
                            0,
                            MAX_GAS,
                        ),
                    );
                }
            }
        }

        if fee > U256::ZERO {
            let fee = (fee.unchecked_mul(self.denominator).overflowing_neg().0)
                .try_into()
                .unwrap();

            if tx.token_id.as_str() == "near" {
                res = PromiseOrValue::Promise(Promise::new(operator_id).transfer(fee));
            } else if cfg!(not(feature = "ft")) {
                env::panic_str("Non NEAR tokens are not supported");
            } else {
                res = PromiseOrValue::Promise(
                    Promise::new(tx.token_id).function_call(
                        "ft_transfer".to_string(),
                        json!({
                            "receiver_id": operator_id,
                            "memo": "fee",
                            "amount": fee,
                        })
                        .to_string()
                        .as_bytes()
                        .to_vec(),
                        0,
                        MAX_GAS,
                    ),
                );
            }
        }

        // Change contract state
        self.pool_index = pool_index;
        self.roots.insert(&pool_index, &tx.root_after);
        self.nullifiers.insert(&tx.nullifier, &hash);
        self.all_messages_hash = new_all_messages_hash;

        res
    }

    #[cfg(feature = "ft")]
    /// Support for FT version of `lock`.
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let ft_token_id = env::predecessor_account_id();
        require!(ft_token_id == self.lockups.token_id, "Unsupported token");

        #[derive(Deserialize)]
        #[serde(tag = "method", content = "args")]
        #[serde(rename_all = "snake_case")]
        enum Msg {
            /// { "method": "lock" }
            Lock,
        }

        let msg: Msg = serde_json::from_str(&msg).unwrap_or_else(|_| env::panic_str("Invalid msg"));

        match msg {
            Msg::Lock => {
                self.lockups.lock(sender_id, amount.0);

                PromiseOrValue::Value(0u128.into())
            }
        }
    }
}
