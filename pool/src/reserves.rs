use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{collections::LookupMap, env, require, AccountId, Promise};

const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Reserves {
    reserves: LookupMap<AccountId, Deposit>,
    // TODO: Support tokens
}

impl Reserves {
    pub fn new(prefix: &[u8]) -> Self {
        Self {
            reserves: LookupMap::new(prefix),
        }
    }

    pub fn reserve(&mut self) {
        let account_id = env::signer_account_id();
        let timestamp = env::block_timestamp_ms();
        let amount = env::attached_deposit();

        require!(
            !self.reserves.contains_key(&account_id),
            "Deposit already exists"
        );

        self.reserves
            .insert(&account_id, &Deposit { timestamp, amount });
    }

    pub fn release(&mut self) -> Promise {
        let account_id = env::signer_account_id();
        let deposit = self.reserves.get(&account_id).expect("Deposit not found");
        let timestamp = env::block_timestamp_ms();
        let elapsed = timestamp - deposit.timestamp;

        require!(
            elapsed > WITHDRAW_TIMEOUT_MS,
            "Cannot withdraw yet. Wait for the timeout."
        );

        self.reserves.remove(&account_id);

        Promise::new(account_id).transfer(deposit.amount)
    }

    pub fn spend(&mut self, account_id: &AccountId) {
        let res = self.reserves.remove(account_id);
        require!(res.is_some(), "No lock to spend");
    }
}
