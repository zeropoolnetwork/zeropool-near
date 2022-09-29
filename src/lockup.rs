//! Primitive lockups for the pool.

use crate::MAX_GAS;
use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde_json::json;
use near_sdk::{collections::LookupMap, env, require, AccountId, Promise};

const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(BorshSerialize, BorshDeserialize, PartialEq)]
struct DepositId {
    token_id: AccountId,
    account_id: AccountId,
    nonce: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Lockups {
    nonces: LookupMap<AccountId, u64>,
    lockups: LookupMap<DepositId, Deposit>,
}

impl Lockups {
    pub fn new() -> Self {
        Self {
            nonces: LookupMap::new("nonces".as_bytes()),
            lockups: LookupMap::new("lockups".as_bytes()),
        }
    }

    pub fn lock(&mut self, token_id: AccountId, account_id: AccountId, amount: u128) -> u64 {
        let timestamp = env::block_timestamp_ms();
        let nonce = self.nonces.get(&account_id).unwrap_or(0);

        self.nonces.insert(&account_id, &(nonce + 1));
        self.lockups.insert(
            &DepositId {
                token_id,
                account_id,
                nonce,
            },
            &Deposit { timestamp, amount },
        );

        nonce
    }

    pub fn release(&mut self, token_id: AccountId, account_id: AccountId, nonce: u64) -> Promise {
        let deposit = self
            .lockups
            .get(&DepositId {
                token_id: token_id.clone(),
                account_id: account_id.clone(),
                nonce,
            })
            .expect("no deposit");
        let timestamp = env::block_timestamp_ms();
        let elapsed = timestamp - deposit.timestamp;

        require!(
            elapsed > WITHDRAW_TIMEOUT_MS,
            "Cannot withdraw yet. Wait for the timeout."
        );

        self.lockups.remove(&DepositId {
            token_id: token_id.clone(),
            account_id: account_id.clone(),
            nonce,
        });

        if token_id.as_str() == "near" {
            Promise::new(account_id).transfer(deposit.amount.into())
        } else {
            Promise::new(account_id).function_call(
                "ft_transfer".into(),
                json!({
                    "amount": deposit.amount,
                    "memo": "withdraw",
                    "sender_id": env::predecessor_account_id(),
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                0,
                MAX_GAS, // FIXME: How much gas should we use?
            )
        }
    }

    pub fn spend(&mut self, token_id: AccountId, account_id: AccountId, nonce: u64) {
        let res = self.lockups.remove(&DepositId {
            token_id,
            account_id,
            nonce,
        });
        require!(res.is_some(), "No deposit to spend");
    }
}
