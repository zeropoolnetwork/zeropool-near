use borsh::{BorshDeserialize, BorshSerialize};
use core::str::FromStr;
use near_sdk::collections::{LookupMap, TreeMap};
use near_sdk::{env, json_types::Base64VecU8, near_bindgen, AccountId, Promise};
use near_sdk::{ext_contract, require, Gas, PanicOnDefault, PromiseOrValue};

use crate::num::*;
use crate::reserves::Reserves;
use crate::tx_decoder::{Tx, TxType};
use crate::verifier::{alt_bn128_groth16verify, VK};

mod num;
mod reserves;
mod tx_decoder;
mod verifier;

const FIRST_ROOT: U256 = U256::from_const_str(
    "11469701942666298368112882412133877458305516134926649826543144744382391691533",
);
const R: U256 = U256::from_const_str(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

#[near_bindgen]
#[derive(PanicOnDefault, BorshDeserialize, BorshSerialize)]
pub struct MainPool {
    operator: Option<AccountId>,
    tree_vk: VK,
    tx_vk: VK,
    pool_index: U256,
    roots: TreeMap<U256, U256>,
    nullifiers: TreeMap<U256, U256>,
    all_messages_hash: U256,
    denominator: U256,
    /// Temporary deposits: imitation of EVM's allowance system
    // TODO: Allow multiple deposits per user
    reserves: Reserves,
}

impl MainPool {
    fn check_operator(&self) -> AccountId {
        let operator = self.operator.clone();
        if let Some(op) = operator {
            if env::signer_account_id() != op {
                panic!("Only operator can call this function");
            }

            op
        } else {
            env::panic_str("No operator set");
        }
    }
}

#[near_bindgen]
impl MainPool {
    #[init]
    pub fn new(tx_vk: Base64VecU8, tree_vk: Base64VecU8) -> Self {
        assert!(!env::state_exists(), "Already initialized");

        let mut roots = TreeMap::new(b"r");
        roots.insert(&U256::ZERO, &FIRST_ROOT);

        let tx_vk = VK::deserialize(&mut &Vec::<u8>::from(tx_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));
        let tree_vk = VK::deserialize(&mut &Vec::<u8>::from(tree_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));

        Self {
            tx_vk,
            tree_vk,
            roots,
            operator: None,
            pool_index: U256::ZERO,
            nullifiers: TreeMap::new(b"n"),
            all_messages_hash: U256::ZERO,
            denominator: U256::ONE,
            reserves: Reserves::new(b"d"),
        }
    }

    #[private]
    pub fn set_operator(&mut self, operator: AccountId) {
        self.operator = Some(operator);
    }

    #[payable]
    pub fn reserve(&mut self) {
        self.reserves.reserve();
    }

    pub fn release(&mut self) -> Promise {
        self.reserves.release()
    }

    pub fn pool_index(&self) -> String {
        self.pool_index.to_string()
    }

    pub fn merkle_root(&self, index: String) -> String {
        let index = U256::from_str(&index).unwrap();
        self.roots.get(&index).unwrap().to_string()
    }

    pub fn transact(&mut self, encoded_tx: Base64VecU8) {
        let operator_id = self.check_operator();
        let tx: Tx = Tx::try_from_slice(&encoded_tx.0).expect("invalid transaction format");
        let message_hash = tx.memo.hash();
        let message_hash_num = U256::from_little_endian(&message_hash).unchecked_rem(R);
        let mut pool_index: U256 = self.pool_index;
        let root_before = self.roots.get(&pool_index).expect("Root not found.");

        // Verify transaction proof
        const POOL_ID: U256 = U256::ONE;
        const DELTA_SIZE: u32 = 256;
        let delta = tx.delta.unchecked_add(POOL_ID.unchecked_shr(DELTA_SIZE));

        let transact_inputs = [
            root_before,
            tx.nullifier.into(),
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
        // TODO: LE or BE?
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
        let new_all_messages_hash = U256::from_little_endian(&env::keccak256_array(&hashes));

        let fee = tx.memo.fee();
        let token_amount = tx.token_amount.overflowing_add(fee).0;
        let energy_amount = tx.energy_amount;

        match tx.tx_type {
            TxType::Deposit => {
                if token_amount > U256::MAX.unchecked_div(U256::from(2u32))
                    || energy_amount != U256::ZERO
                {
                    env::panic_str("Token amount must be negative and energy_amount must be zero.");
                }

                self.reserves.spend(&tx.deposit_address);
            }
            TxType::Transfer => {
                if token_amount != U256::ZERO || energy_amount != U256::ZERO {
                    env::panic_str("Transfer tx must have zero token and energy amount.");
                }
            }
            TxType::Withdraw => {
                let dest = tx.memo.address();

                let withdraw_amount = (token_amount
                    .overflowing_neg()
                    .0
                    .unchecked_mul(self.denominator))
                .try_into()
                .unwrap();

                Promise::new(dest).transfer(withdraw_amount);
            }
        }

        if fee > U256::ZERO {
            let fee = (fee.unchecked_mul(self.denominator).overflowing_neg().0)
                .try_into()
                .unwrap();

            Promise::new(operator_id).transfer(fee);
        }

        // Change contract state
        self.pool_index = pool_index;
        self.roots.insert(&pool_index, &tx.root_after);
        self.nullifiers.insert(&tx.nullifier, &hash);
        self.all_messages_hash = new_all_messages_hash;
    }

    // TODO: Multi-token support
    // fn ft_on_transfer(
    //     &mut self,
    //     sender_id: AccountId,
    //     amount: U128,
    //     msg: String,
    // ) -> PromiseOrValue<U128> {
    //     PromiseOrValue::Value(amount)
    // }
}
