use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env, serde_json::json, store::LookupMap, AccountId, Balance, Promise};

use crate::FT_TRANSFER_GAS;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Withdraws {
    token_id: AccountId,
    withdraws: LookupMap<AccountId, Withdraw>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Withdraw {
    amount: Balance,
}

impl Withdraws {
    pub fn new(token_id: AccountId) -> Self {
        Self {
            withdraws: LookupMap::new("withdraws".as_bytes()),
            token_id,
        }
    }

    pub fn exists(&self, account_id: &AccountId) -> bool {
        self.withdraws.contains_key(account_id)
    }

    pub fn insert(&mut self, account_id: AccountId, amount: Balance) {
        if self.withdraws.contains_key(&account_id) {
            env::panic_str("Already has withdraw");
        }

        self.withdraws.insert(account_id, Withdraw { amount });
    }

    pub fn execute(&mut self, account_id: AccountId) -> Promise {
        let withdraw = self
            .withdraws
            .remove(&account_id)
            .expect("Withdraw not found");

        if self.token_id.as_str() == "near" {
            Promise::new(account_id).transfer(withdraw.amount)
        } else {
            Promise::new(account_id).function_call(
                "ft_transfer".into(),
                json!({
                    "amount": withdraw.amount,
                    "memo": "withdraw",
                    "sender_id": env::predecessor_account_id(),
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                1,
                FT_TRANSFER_GAS, // FIXME: How much gas should we use?
            )
        }
    }
}
