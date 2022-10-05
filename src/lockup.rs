//! Primitive lockups for the pool.

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{
    env,
    json_types::{U128, U64},
    require,
    serde_json::json,
    store::{LookupMap, TreeMap},
    AccountId, Promise,
};
use serde::Serialize;

use crate::MAX_GAS;

const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

type Nonce = u64;

#[derive(Serialize)]
pub struct FullDeposit {
    nonce: Nonce,
    timestamp: U64,
    amount: U128,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposits {
    nonce: Nonce,
    deposits: TreeMap<Nonce, Deposit>,
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Lockups {
    lockups: LookupMap<AccountId, Deposits>,
    pub(crate) token_id: AccountId,
}

impl Lockups {
    pub fn new(token_id: AccountId) -> Self {
        Self {
            lockups: LookupMap::new("lockups".as_bytes()),
            token_id,
        }
    }

    pub fn account_deposits(&self, account_id: AccountId) -> Vec<FullDeposit> {
        self.lockups
            .get(&account_id)
            .map(|deposits| {
                deposits
                    .deposits
                    .iter()
                    .map(|(nonce, deposit)| FullDeposit {
                        nonce: *nonce,
                        timestamp: deposit.timestamp.into(),
                        amount: deposit.amount.into(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn lock(&mut self, account_id: AccountId, amount: u128) -> u64 {
        let timestamp = env::block_timestamp_ms();

        let deposits = self.lockups.entry(account_id.clone()).or_insert_with(|| {
            let key = env::sha256(format!("deposits{account_id}").as_bytes());
            Deposits {
                nonce: 0,
                deposits: TreeMap::new(key),
            }
        });

        let nonce = deposits.nonce;
        deposits
            .deposits
            .insert(deposits.nonce, Deposit { timestamp, amount });
        deposits.nonce += 1;

        nonce
    }

    pub fn release(&mut self, account_id: AccountId, nonce: u64) -> Promise {
        let deposits: &mut Deposits = self
            .lockups
            .get_mut(&account_id)
            .unwrap_or_else(|| env::panic_str("Account has no deposits"));

        let deposit = *deposits.deposits.get(&nonce).unwrap_or_else(|| {
            env::panic_str("Deposit not found");
        });

        let timestamp = env::block_timestamp_ms();
        let elapsed = timestamp - deposit.timestamp;

        require!(
            elapsed > WITHDRAW_TIMEOUT_MS,
            "Cannot withdraw yet. Wait for the timeout."
        );

        deposits.deposits.remove(&nonce);

        if deposits.deposits.is_empty() {
            self.lockups.remove(&account_id);
        }

        if self.token_id.as_str() == "near" {
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

    pub fn spend(&mut self, account_id: AccountId, nonce: u64) {
        let res = self.remove_deposit(account_id, nonce);
        require!(res.is_some(), "No deposit to spend");
    }

    fn remove_deposit(&mut self, account_id: AccountId, nonce: u64) -> Option<Deposit> {
        let deposits: &mut Deposits = self.lockups.get_mut(&account_id)?;
        let deposit = deposits.deposits.remove(&nonce);

        if deposits.deposits.is_empty() {
            self.lockups.remove(&account_id);
        }

        deposit
    }
}
