use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{PublicKey as PublicKeyEd25519, Signature, Verifier, PUBLIC_KEY_LENGTH};
use near_sdk::{
    env, ext_contract,
    json_types::{U128, U64},
    log, require,
    store::{LookupMap, TreeMap},
    AccountId, Balance, PublicKey,
};
use serde::Serialize;

use crate::{num::U256, tx_decoder::DepositDataForSigning};

type Nonce = u64;

pub const WITHDRAW_TIMEOUT_MS: u64 = 5 * 60 * 1000;
pub const SPEND_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(Serialize)]
pub struct FullLock {
    pub nonce: Nonce,
    pub timestamp: U64,
    pub amount: U128,
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct Locks {
    pub nonce: Nonce,
    pub locks: TreeMap<Nonce, Lock>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Lock {
    pub timestamp: u64,
    pub amount: Balance,
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ZeropoolLockups {
    pub lockups: LookupMap<AccountId, Locks>,
}

impl ZeropoolLockups {
    pub fn new() -> Self {
        Self {
            lockups: LookupMap::new("lockups".as_bytes()),
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

    pub fn lock(&mut self, account_id: AccountId, amount: Balance, public_key: PublicKey) -> u64 {
        let pk_serialized = &public_key.as_bytes()[1..];
        let public_key = PublicKeyEd25519::from_bytes(&pk_serialized).expect("Invalid public key");

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

    pub fn release(&mut self, account_id: AccountId, nonce: u64) -> Lock {
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

        lock
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
            let public_key =
                PublicKeyEd25519::from_bytes(&lock.public_key).expect("Invalid public key");

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

            let timestamp = env::block_timestamp_ms();
            let elapsed = timestamp - lock.timestamp;

            require!(elapsed < SPEND_TIMEOUT_MS, "Lock is expired");

            locks.locks.remove(&nonce);
        } else {
            log!("Existing locks: {:?}", &locks);
            env::panic_str("Lock not found");
        }
    }
}

#[ext_contract(ext_zeropool_lockups)]
pub trait ZeropoolLockupMethods {
    /// Can be called by a client to reserve a certain amount for use in the `transact`
    /// method. Returns the lockup ID.
    fn lock(&mut self, amount: u128) -> u64;
    /// Release the funds previously reserved with the `lock` method.
    fn release(&mut self, lock_id: u64);
    /// Get all locks for the specified account in JSON format.
    /// ```json
    /// [{ nonce: 123, amount: "123", timestamp: "123" }, ...]
    /// ```
    fn account_locks(&self) -> Vec<FullLock>;
}

#[macro_export]
macro_rules! impl_zeropool_lockups {
    ($contract:ident, $($locks:ident).+, $token:ident) => {
        use $crate::ZeropoolLockupMethods;

        #[near_bindgen]
        impl ZeropoolLockupMethods for $contract {
            fn lock(&mut self, amount: u128) -> u64 {
                let account_id = env::signer_account_id();
                let public_key = env::signer_account_pk();

                let balance = self.$token.internal_unwrap_balance_of(&account_id);
                if let Some(new_balance) = balance.checked_sub(amount) {
                    self.$token.accounts.insert(&account_id, &new_balance);
                } else {
                    env::panic_str("The account doesn't have enough balance");
                }

                let nonce = self.$($locks).+.lock(account_id.clone(), amount, public_key);

                log!(
                    "Locked {} tokens for {} (lock {})",
                    amount,
                    account_id,
                    nonce
                );

                nonce
            }

            fn release(&mut self, lock_id: u64) {
                let account_id = env::signer_account_id();
                let lock = self.$($locks).+.release(account_id.clone(), lock_id);
                let balance = self.$token.internal_unwrap_balance_of(&account_id);
                let new_balance = balance + lock.amount;

                self.$token.accounts.insert(&account_id, &new_balance);

                log!(
                    "Released {} tokens for {} (lock {})",
                    lock.amount,
                    account_id,
                    lock_id
                );
            }

            fn account_locks(&self) -> Vec<$crate::FullLock> {
                let account_id = env::predecessor_account_id();
                self.$($locks).+.account_locks(account_id)
            }
        }
    };
}
