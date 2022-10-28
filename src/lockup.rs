//! Primitive lockups for the pool.

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{PublicKey, Signature, Verifier, PUBLIC_KEY_LENGTH};
use near_sdk::{
    env,
    json_types::{U128, U64},
    log, require,
    serde_json::json,
    store::{LookupMap, TreeMap},
    AccountId, Promise,
};
use serde::Serialize;

use crate::{num::U256, tx_decoder::DepositDataForSigning, MAX_GAS};

pub const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

type Nonce = u64;

#[derive(Serialize)]
pub struct FullDeposit {
    pub nonce: Nonce,
    pub timestamp: U64,
    pub amount: U128,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct Deposits {
    nonce: Nonce,
    deposits: TreeMap<Nonce, Deposit>,
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
struct Deposit {
    timestamp: u64,
    amount: u128,
    public_key: [u8; PUBLIC_KEY_LENGTH],
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

    pub fn lock(&mut self, account_id: AccountId, amount: u128, public_key: PublicKey) -> u64 {
        let timestamp = env::block_timestamp_ms();

        let deposits = self.lockups.entry(account_id.clone()).or_insert_with(|| {
            let key = env::sha256(format!("deposits{account_id}").as_bytes());
            Deposits {
                nonce: 0,
                deposits: TreeMap::new(key),
            }
        });

        let public_key = public_key.to_bytes();

        let nonce = deposits.nonce;
        deposits.deposits.insert(
            deposits.nonce,
            Deposit {
                timestamp,
                amount,
                public_key,
            },
        );
        deposits.nonce += 1;

        nonce
    }

    pub fn release(&mut self, account_id: AccountId, nonce: u64) -> Promise {
        let deposits: &mut Deposits = self
            .lockups
            .get_mut(&account_id)
            .unwrap_or_else(|| env::panic_str("Account has no deposits"));

        let deposit = deposits.deposits.get(&nonce).cloned().unwrap_or_else(|| {
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

    pub fn spend(
        &mut self,
        account_id: &AccountId,
        nonce: u64,
        signature: &Signature,
        nullifier: U256,
    ) {
        log!("Spending lock {} for {}", nonce, account_id);

        let deposits: &mut Deposits = self
            .lockups
            .get_mut(account_id)
            .expect("Account has no deposits");

        if let Some(deposit) = deposits.deposits.get(&nonce).cloned() {
            let public_key =
                PublicKey::from_bytes(&deposit.public_key).expect("Invalid public key");

            let deposit_message = DepositDataForSigning {
                nullifier,
                account_id,
                id: nonce,
            };
            let message = deposit_message.try_to_vec().unwrap();
            public_key
                .verify(&message, signature) // TODO: nullifier + deposit_address + deposit_id
                .expect("Invalid deposit signature");
        } else {
            env::panic_str("Lock not found");
        }

        if deposits.deposits.is_empty() {
            self.lockups.remove(&account_id);
        }
    }
}
