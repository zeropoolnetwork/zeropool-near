use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, TreeMap};
use near_sdk::{env, json_types::Base64VecU8, near_bindgen, AccountId, Promise};

// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RelayerPool {
    pub owner: AccountId,
    // TODO: Configurable operator
    pub operator: AccountId,
}

impl Default for RelayerPool {
    fn default() -> Self {
        Self {
            owner: env::signer_account_id(),
            operator: env::signer_account_id(),
        }
    }
}

#[near_bindgen]
impl RelayerPool {
    pub fn set_owner(&mut self, owner: AccountId) {
        let account_id = env::signer_account_id();
        if account_id != owner {
            env::panic_str("Only owner can set owner.");
        }

        self.owner = owner;
    }

    pub fn deposit(&mut self, amount: u128) {
        let account_id = env::signer_account_id();


    }

    // pub fn transfer(&self, account_id: AccountId, amount: u128) {
    //     Promise::new(account_id).transfer(amount);
    // }
}
