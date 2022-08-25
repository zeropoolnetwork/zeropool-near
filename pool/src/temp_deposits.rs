use borsh::{BorshSerialize, BorshDeserialize};
use near_sdk::{env, collections::LookupMap, AccountId, require, Promise};

const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Deposits {
    deposits: LookupMap<AccountId, Deposit>,
    // TODO: Support tokens
}

impl Deposits {
    pub fn new(prefix: &[u8]) -> Self {
        Self {
            deposits: LookupMap::new(prefix),
        }
    }

    pub fn lock(&mut self) {
        let account_id = env::signer_account_id();
        let timestamp = env::block_timestamp_ms();
        let amount = env::attached_deposit();

        require!(
            !self.deposits.contains_key(&account_id),
            "Deposit already exists"
        );

        self.deposits
            .insert(&account_id, &Deposit { timestamp, amount });
    }

    pub fn release(&mut self) -> Promise {
        let account_id = env::signer_account_id();
        let deposit = self.deposits.get(&account_id).expect("Deposit not found");
        let timestamp = env::block_timestamp_ms();
        let elapsed = timestamp - deposit.timestamp;

        require!(
            elapsed > WITHDRAW_TIMEOUT_MS,
            "Cannot withdraw yet. Wait for the timeout."
        );

        self.deposits.remove(&account_id);

        Promise::new(account_id).transfer(deposit.amount)
    }

    pub fn spend(&mut self, account_id: &AccountId) {
        let res = self.deposits.remove(account_id);
        require!(res.is_some(), "No lock to spend");
    }
}
