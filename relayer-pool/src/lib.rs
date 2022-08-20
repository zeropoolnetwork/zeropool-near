use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap};
use near_sdk::require;
use near_sdk::{env, near_bindgen, AccountId, Promise};

const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RelayerPool {
    deposits: LookupMap<AccountId, Deposit>,
}

impl Default for RelayerPool {
    fn default() -> Self {
        Self {
            deposits: LookupMap::new(b"d"),
        }
    }
}

#[near_bindgen]
impl RelayerPool {
    #[payable]
    pub fn deposit(&mut self) {
        let account_id = env::signer_account_id();
        let timestamp = env::block_timestamp_ms();
        let amount = env::attached_deposit();

        require!(!self.deposits.contains_key(&account_id), "Deposit already exists");

        self.deposits.insert(&account_id, &Deposit {
            timestamp,
            amount,
        });
    }

    pub fn withdraw(&mut self) -> Promise {
        let account_id = env::signer_account_id();
        let deposit = self.deposits.get(&account_id).expect("Deposit not found");
        let timestamp = env::block_timestamp_ms();
        let elapsed = timestamp - deposit.timestamp;

        require!(elapsed > WITHDRAW_TIMEOUT_MS, "Cannot withdraw yet. Wait for the timeout.");

        self.deposits.remove(&account_id);

        Promise::new(account_id).transfer(deposit.amount)
    }

    #[payable]
    pub fn transact(&self) {
        require!();
    }
}
