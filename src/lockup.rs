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

use crate::{num::U256, tx_decoder::DepositDataForSigning, FT_TRANSFER_GAS};

pub const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;

type Nonce = u64;

#[derive(Serialize)]
pub struct FullLock {
    pub nonce: Nonce,
    pub timestamp: U64,
    pub amount: U128,
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
struct Locks {
    nonce: Nonce,
    locks: TreeMap<Nonce, Lock>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct Lock {
    timestamp: u64,
    amount: u128,
    public_key: [u8; PUBLIC_KEY_LENGTH],
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Lockups {
    lockups: LookupMap<AccountId, Locks>,
    pub(crate) token_id: AccountId,
}

impl Lockups {
    pub fn new(token_id: AccountId) -> Self {
        Self {
            lockups: LookupMap::new("lockups".as_bytes()),
            token_id,
        }
    }

    pub fn account_locks(&self, account_id: AccountId) -> Vec<FullLock> {
        self.lockups
            .get(&account_id)
            .map(|locks| {
                locks
                    .locks
                    .iter()
                    .map(|(nonce, lock)| FullLock {
                        nonce: *nonce,
                        timestamp: lock.timestamp.into(),
                        amount: lock.amount.into(),
                        public_key: lock.public_key,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn lock(&mut self, account_id: AccountId, amount: u128, public_key: PublicKey) -> u64 {
        let timestamp = env::block_timestamp_ms();

        let locks = self.lockups.entry(account_id.clone()).or_insert_with(|| {
            let key = env::sha256(format!("deposits{account_id}").as_bytes());
            Locks {
                nonce: 0,
                locks: TreeMap::new(key),
            }
        });

        let public_key = public_key.to_bytes();

        let nonce = locks.nonce;
        locks.locks.insert(
            locks.nonce,
            Lock {
                timestamp,
                amount,
                public_key,
            },
        );
        locks.nonce += 1;

        nonce
    }

    pub fn release(&mut self, account_id: AccountId, nonce: u64) -> Promise {
        let locks: &mut Locks = self
            .lockups
            .get_mut(&account_id)
            .unwrap_or_else(|| env::panic_str("Account has no deposits"));

        let lock = locks.locks.get(&nonce).cloned().unwrap_or_else(|| {
            env::panic_str("Deposit not found");
        });

        let timestamp = env::block_timestamp_ms();
        let elapsed = timestamp - lock.timestamp;

        require!(
            elapsed > WITHDRAW_TIMEOUT_MS,
            "Cannot withdraw yet. Wait for the timeout."
        );

        locks.locks.remove(&nonce);

        if locks.locks.is_empty() {
            self.lockups.remove(&account_id);
        }

        if self.token_id.as_str() == "near" {
            Promise::new(account_id).transfer(lock.amount.into())
        } else {
            Promise::new(account_id).function_call(
                "ft_transfer".into(),
                json!({
                    "amount": lock.amount,
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

    pub fn spend(
        &mut self,
        account_id: &AccountId,
        nonce: u64,
        signature: &Signature,
        nullifier: U256,
    ) {
        log!("Spending lock {} for {}", nonce, account_id);

        let locks: &mut Locks = self
            .lockups
            .get_mut(account_id)
            .expect("Account has no deposits");

        if let Some(lock) = locks.locks.get(&nonce).cloned() {
            let public_key = PublicKey::from_bytes(&lock.public_key).expect("Invalid public key");

            let lock_message = DepositDataForSigning {
                nullifier,
                account_id,
                id: nonce,
            };
            let message = lock_message.try_to_vec().unwrap();
            let message_hash = env::sha256_array(&message);

            public_key
                .verify(&message_hash, signature)
                .expect("Invalid deposit signature");

            locks.locks.remove(&nonce);
        } else {
            log!("Existing locks: {:?}", &locks);
            env::panic_str("Lock not found");
        }
    }
}
