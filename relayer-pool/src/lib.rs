use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap};
use near_sdk::json_types::Base64VecU8;
use near_sdk::{require, ext_contract, Gas, PromiseError, log, env, near_bindgen, AccountId, Promise};

const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const TGAS: u64 = 1_000_000_000_000;

#[ext_contract(main_pool)]
trait MainPool {
  #[payable]
  fn transact(&mut self, data: Base64VecU8);
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RelayerPool {
    deposits: LookupMap<AccountId, Deposit>,
    pool: AccountId,
}

impl Default for RelayerPool {
    fn default() -> Self {
        Self {
            deposits: LookupMap::new(b"d"),
            pool: AccountId::new_unchecked("invalid".into()),
        }
    }
}

#[near_bindgen]
impl RelayerPool {
    #[init]
    pub fn new(pool: AccountId) -> Self {
        RelayerPool { pool, ..Default::default() }
    }

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

    #[private]
    pub fn transact(&self, data: Base64VecU8, deposit: bool) -> Promise {
        let promise = main_pool::ext(self.pool.clone())
            .with_static_gas(Gas(TGAS))
            .transact(data);

        return promise.then( // Create a promise to callback query_greeting_callback
            Self::ext(env::current_account_id())
                .with_static_gas(Gas(5*TGAS))
                .transact_callback()
        )

    }

    #[private] // Public - but only callable by env::current_account_id()
    pub fn transact_callback(&self, #[callback_result] call_result: Result<String, PromiseError>) {
        // Check if the promise succeeded by calling the method outlined in external.rs
        if call_result.is_err() {
            log!("There was an error contacting the main pool");
        }
    }
}
