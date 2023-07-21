use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ff_uint::{Num, NumRepr, PrimeField};
use near_sdk::{collections::TreeMap, env, ext_contract, log, AccountId, Balance};
use serde::{Deserialize, Serialize};

use crate::{
    lockup::{ZeropoolLockupMethods, ZeropoolLockups},
    num::*,
    tx_decoder::{parse_delta, Tx, TxType},
    verifier::{alt_bn128_groth16verify, VK},
};

const FIRST_ROOT: U256 = U256::from_const_str(
    "11469701942666298368112882412133877458305516134926649826543144744382391691533",
);
const R: U256 = U256::from_const_str(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

#[ext_contract(ext_zeropool)]
pub trait ZeropoolMethods {
    fn set_operator(&mut self, operator: AccountId);
    fn denominator(&self) -> U256;
    fn pool_index(&self) -> U256;
    fn merkle_root(&self, #[serializer(borsh)] index: U256) -> Option<U256>;
    fn transact(&mut self, #[serializer(borsh)] tx: Tx);
}

#[macro_export]
macro_rules! impl_zeropool {
    ($contract:ident, $pool:ident, $token:ident) => {
        use $crate::ZeropoolMethods;

        #[near_bindgen]
        impl ZeropoolMethods for $contract {
            #[private]
            fn set_operator(&mut self, operator: AccountId) {
                self.$pool.set_operator(operator);
            }

            #[result_serializer(borsh)]
            fn denominator(&self) -> $crate::U256 {
                self.$pool.denominator
            }

            #[result_serializer(borsh)]
            fn pool_index(&self) -> $crate::U256 {
                self.$pool.pool_index
            }

            #[result_serializer(borsh)]
            fn merkle_root(&self, #[serializer(borsh)] index: $crate::U256) -> Option<U256> {
                self.$pool.roots.get(&index)
            }

            fn transact(&mut self, #[serializer(borsh)] tx: $crate::Tx) {
                if env::signer_account_id() != self.$pool.operator {
                    panic!("Only operator can call this method");
                }

                let mut transfer = |account_id, amount| {
                    let balance = self.$token.internal_unwrap_balance_of(&account_id);
                    let new_balance = balance + amount;
                    self.$token.accounts.insert(&account_id, &new_balance);
                };

                self.$pool.transact(tx, transfer);
            }
        }

        $crate::impl_zeropool_lockups!($contract, $pool.lockups, $token);
    };
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ZeropoolState {
    /// Operator is an entity that can make new transactions.
    pub operator: AccountId,
    /// Transaction verifying key.
    pub tx_vk: VK,
    /// Merkle tree verifying key.
    pub tree_vk: VK,
    /// The next transaction index.
    pub pool_index: U256,
    /// Merkle roots. "transaction index" => "merkle root"
    pub roots: TreeMap<U256, U256>,
    /// Nullifiers for used accounts. "nullifier" => "keccak256(out_commit + delta)".
    pub nullifiers: TreeMap<U256, U256>,
    /// Accumulative transaction hash
    pub all_messages_hash: U256,
    pub denominator: U256,
    pub lockups: ZeropoolLockups,
}

impl ZeropoolState {
    pub fn new(tx_vk: VK, tree_vk: VK, denominator: U256) -> Self {
        let mut roots = TreeMap::new("roots".as_bytes());
        roots.insert(&U256::ZERO, &FIRST_ROOT);

        let default_operator = env::signer_account_id();

        Self {
            tx_vk,
            tree_vk,
            roots,
            operator: default_operator,
            pool_index: U256::ZERO,
            nullifiers: TreeMap::new("nullifiers".as_bytes()),
            all_messages_hash: U256::ZERO,
            denominator,
            lockups: ZeropoolLockups::new(),
        }
    }

    /// Set the operator (relayer).
    pub fn set_operator(&mut self, operator: AccountId) {
        self.operator = operator;
    }

    /// Return the index of the next transaction.
    pub fn pool_index(&self) -> U256 {
        self.pool_index
    }

    /// Return the merkle root at the specified transaction index.
    pub fn merkle_root(&self, index: U256) -> Option<U256> {
        self.roots.get(&index)
    }

    /// The main transaction method.
    /// Validates the transaction, handles deposits/withdrawals, pays fees to the operator.
    /// Can only be called by the current operator.
    pub fn transact<Transfer>(&mut self, tx: Tx, mut transfer: Transfer)
    where
        Transfer: FnMut(AccountId, Balance),
    {
        let message_hash = tx.memo.hash();
        let message_hash_num = U256::from_big_endian(&message_hash).unchecked_rem(R);

        let (token_amount, energy_amount, transfer_index, _) =
            parse_delta(Num::new(Fr::from_uint(tx.delta).unwrap()));

        let transfer_index = transfer_index.to_uint().0;

        if transfer_index > self.pool_index {
            env::panic_str("Transfer index is out of bounds");
        }

        let token_amount: i128 = token_amount.try_into().unwrap();
        let energy_amount: i128 = energy_amount.try_into().unwrap();

        let root_before = self
            .roots
            .get(&transfer_index)
            .unwrap_or_else(|| env::panic_str("Root not found"));

        // Verify transaction proof
        const POOL_ID: U256 = U256::ZERO;
        const DELTA_SIZE: u32 = 256;

        let transact_inputs = [
            root_before,
            tx.nullifier,
            tx.out_commit,
            tx.delta.unchecked_add(POOL_ID.unchecked_shr(DELTA_SIZE)),
            message_hash_num,
        ];

        if !alt_bn128_groth16verify(self.tx_vk.clone(), tx.transact_proof, &transact_inputs) {
            let msg = format!(
                "Transaction proof is invalid. Inputs:\nroot_before: {},\nnullifier: {},\nout_commit: {},\ndelta: {},\nmessage_hash_num: {}", root_before, tx.nullifier, tx.out_commit, transact_inputs[3], message_hash_num
            );
            log!(&msg);
            env::panic_str(&msg);
        }

        if self.nullifiers.contains_key(&tx.nullifier) {
            env::panic_str("Double spend.");
        }

        if transfer_index > self.pool_index {
            env::panic_str("Transfer index is greater than pool index.");
        }

        // Verify tree proof
        let pool_root = self
            .roots
            .get(&self.pool_index)
            .unwrap_or_else(|| env::panic_str("Root not found"));
        let tree_inputs = [pool_root, tx.root_after, tx.out_commit];
        if !alt_bn128_groth16verify(self.tree_vk.clone(), tx.tree_proof, &tree_inputs) {
            log!(
                "Tree proof inputs:\npool_root: {},\nroot_after: {},\nout_commit: {}",
                pool_root,
                tx.root_after,
                tx.out_commit
            );
            env::panic_str("Tree proof is invalid.");
        }

        // Set the nullifier
        let mut elements = [0u8; core::mem::size_of::<U256>() * 2];
        elements[..core::mem::size_of::<U256>()].copy_from_slice(&tx.out_commit.to_little_endian());
        elements[core::mem::size_of::<U256>()..].copy_from_slice(&tx.delta.to_little_endian());
        let hash = U256::from_little_endian(&env::keccak256_array(&elements));

        // Calculate all_messages_hash
        let mut hashes = [0u8; core::mem::size_of::<U256>() * 2];
        hashes[..core::mem::size_of::<U256>()]
            .copy_from_slice(&self.all_messages_hash.to_little_endian());
        hashes[core::mem::size_of::<U256>()..].copy_from_slice(&message_hash);
        let new_all_messages_hash = U256::from_big_endian(&env::keccak256_array(&hashes));

        let fee: i128 = tx
            .memo
            .fee()
            .try_into()
            .expect("fee must be positive or zero");
        let token_amount = token_amount + fee as i128;
        let energy_amount = energy_amount;
        let denominator: i128 = Num::<Fr>::from_uint(NumRepr(self.denominator))
            .unwrap()
            .try_into()
            .unwrap();

        match tx.tx_type {
            TxType::Deposit => {
                log!("Deposit: {}", token_amount);
                if token_amount < 0 || energy_amount != 0 {
                    env::panic_str(
                        "token_amount must be positive or 0 and energy_amount must be zero.",
                    );
                }

                let deposit_data = tx.deposit_data.0.expect("Deposit data is missing.");

                self.lockups.spend(
                    &deposit_data.address,
                    deposit_data.id,
                    &deposit_data.signature(),
                    tx.nullifier,
                );
            }
            TxType::Transfer => {
                log!("Transfer: {}", token_amount);
                if token_amount != 0 || energy_amount != 0 {
                    env::panic_str("token_amount and energy_amount must be zero.");
                }
            }
            TxType::Withdraw => {
                if token_amount > 0 || energy_amount > 0 {
                    env::panic_str("token_amount and energy_amount must be negative or zero.");
                }

                let withdraw_amount = -token_amount * denominator;
                let dest = tx.memo.withdraw_address();

                log!("Withdrawal to {}: {}", dest, withdraw_amount);

                let withdraw_amount = withdraw_amount.try_into().unwrap();

                transfer(dest, withdraw_amount);
            }
        }

        if fee > 0 {
            let fee = fee * denominator;
            transfer(self.operator.clone(), fee.try_into().unwrap());
        }

        self.pool_index = U256::from(self.pool_index).unchecked_add(U256::from(128u8));
        self.roots.insert(&self.pool_index, &tx.root_after);
        self.nullifiers.insert(&tx.nullifier, &hash);
        self.all_messages_hash = new_all_messages_hash;
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use libzeropool_rs::{
        client::{state::State, TransactionData, TxType as ZpTxType, UserAccount},
        libzeropool::{
            circuit::{tree::tree_update, tx::c_transfer},
            constants::*,
            fawkes_crypto::backend::bellman_groth16::{
                engines::{Bn256, Engine},
                prover::prove,
                Parameters,
            },
            native::{
                account::Account,
                boundednum::BoundedNum,
                params::PoolBN256,
                tree::{TreePub, TreeSec},
                tx::{TransferPub, TransferSec},
            },
            POOL_PARAMS,
        },
        store::MemoryDatabase,
    };
    use near_crypto::{KeyType, SecretKey, Signer};
    use near_sdk::{
        test_utils::{accounts, VMContextBuilder},
        testing_env, PublicKey as SdkPublicKey,
    };

    use super::*;
    use crate::{
        lockup::WITHDRAW_TIMEOUT_MS,
        tx_decoder::{DepositData, DepositDataForSigning, Memo, OptDepositData},
        verifier,
    };

    const DENOMINATOR: u128 = 1_000_000_000_000_000;

    fn signer() -> AccountId {
        accounts(0)
    }

    fn get_context() -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        let sk = SecretKey::from_seed(KeyType::ED25519, signer().as_ref());
        let pk_str = sk.public_key().to_string();
        let pk = SdkPublicKey::from_str(&pk_str).unwrap();
        builder.signer_account_id(signer()).signer_account_pk(pk);
        builder
    }

    fn get_contract(context: &mut VMContextBuilder) -> ZeropoolState {
        let tx_vk = std::fs::read("params/transfer_verification_key.bin").unwrap();
        let tree_vk = std::fs::read("params/tree_verification_key.bin").unwrap();

        let tx_vk = VK::deserialize(&mut &Vec::<u8>::from(tx_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));
        let tree_vk = VK::deserialize(&mut &Vec::<u8>::from(tree_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));

        testing_env!(context.build());
        ZeropoolState::new_bin(
            tx_vk,
            tree_vk,
            AccountId::new_unchecked("near".to_string()),
            DENOMINATOR.into(),
        )
    }

    fn tx_proof(
        public: TransferPub<<Bn256 as Engine>::Fr>,
        secret: TransferSec<<Bn256 as Engine>::Fr>,
    ) -> verifier::Proof {
        let params_bin = std::fs::read("params/transfer_params.bin").unwrap();
        let params = Parameters::<Bn256>::read(&mut params_bin.as_slice(), true, true).unwrap();

        let circuit = |public, secret| {
            c_transfer(&public, &secret, &*POOL_PARAMS);
        };

        let (_inputs, snark_proof) = prove(&params, &public, &secret, circuit);

        let proof_bytes = snark_proof.try_to_vec().unwrap();
        verifier::Proof::try_from_slice(&proof_bytes).unwrap()
    }

    fn tree_proof(
        public: TreePub<<Bn256 as Engine>::Fr>,
        secret: TreeSec<<Bn256 as Engine>::Fr>,
    ) -> verifier::Proof {
        let params_bin = std::fs::read("params/tree_params.bin").unwrap();
        let params = Parameters::<Bn256>::read(&mut params_bin.as_slice(), true, true).unwrap();

        let circuit = |public, secret| {
            tree_update(&public, &secret, &*POOL_PARAMS);
        };

        let (_inputs, snark_proof) = prove(&params, &public, &secret, circuit);

        let proof_bytes = snark_proof.try_to_vec().unwrap();
        verifier::Proof::try_from_slice(&proof_bytes).unwrap()
    }

    fn create_tx(
        native_tx_type: ZpTxType<<Bn256 as Engine>::Fr>,
        account: &mut UserAccount<MemoryDatabase, PoolBN256>,
        context: &mut VMContextBuilder,
        contract: &mut ZeropoolState,
    ) -> Tx {
        let signer = signer();

        let tx_data = account
            .create_tx(native_tx_type.clone(), None, None)
            .unwrap();

        let (tx_value, _, tx_index, _) = parse_delta(Num::new(
            Fr::from_uint(U256(tx_data.public.delta.to_uint().0 .0)).unwrap(),
        ));
        let tx_index = tx_index.try_into().unwrap();

        let v: i64 = tx_value.try_into().unwrap();
        println!("!!!!!! v: {}", v);

        let tx_type = match &native_tx_type {
            ZpTxType::Deposit { .. } => TxType::Deposit,
            ZpTxType::Withdraw { .. } => TxType::Withdraw,
            ZpTxType::Transfer { .. } => TxType::Transfer,
            _ => panic!("Invalid tx type"),
        };

        let deposit_data = if let ZpTxType::Deposit { deposit_amount, .. } = &native_tx_type {
            let deposit_amount: u64 = deposit_amount.to_num().try_into().unwrap();
            let deposit_amount = deposit_amount as u128 * DENOMINATOR;

            testing_env!(context.attached_deposit(deposit_amount).build());
            let lock_nonce = contract.lock(deposit_amount.into());

            let signature = {
                let data_to_sign = DepositDataForSigning {
                    nullifier: U256(tx_data.public.nullifier.to_uint().0 .0),
                    account_id: &signer,
                    id: lock_nonce,
                };

                let bytes_to_sign = data_to_sign.try_to_vec().unwrap();
                let hash = env::sha256_array(&bytes_to_sign);

                let data_signer = near_crypto::InMemorySigner::from_seed(
                    signer.as_str().parse().unwrap(),
                    near_crypto::KeyType::ED25519,
                    signer.as_ref(),
                );

                data_signer.sign(&hash).try_to_vec().unwrap()[1..]
                    .try_into()
                    .unwrap()
            };

            Some(DepositData {
                address: signer.clone(),
                id: lock_nonce,
                signature,
            })
        } else {
            None
        };

        let transact_proof = tx_proof(tx_data.public.clone(), tx_data.secret.clone());
        let transfer_num = account.state.tree.next_index();
        let next_commit_index = transfer_num / OUTPLUSONELOG as u64;
        let prev_commit_index = next_commit_index.saturating_sub(1);

        let root_before = account.state.tree.get_root();
        account.state.tree.add_hash_at_height(
            OUTPLUSONELOG as u32,
            next_commit_index,
            tx_data.commitment_root,
            false,
        );
        let root_after = account.state.tree.get_root();

        let tree_pub = TreePub {
            root_before,
            root_after,
            leaf: tx_data.commitment_root,
        };

        let tree_sec = TreeSec {
            proof_filled: account.state.tree.get_proof_unchecked(prev_commit_index),
            proof_free: account.state.tree.get_proof_unchecked(next_commit_index),
            prev_leaf: account
                .state
                .tree
                .get(OUTPLUSONELOG as u32, prev_commit_index),
        };

        let tree_proof = tree_proof(tree_pub, tree_sec);

        let tx = Tx {
            nullifier: U256(tx_data.public.nullifier.to_uint().0 .0),
            out_commit: U256(tx_data.public.out_commit.to_uint().0 .0),
            token_id: "near".parse().unwrap(),
            delta: U256(tx_data.public.delta.to_uint().0 .0),
            transact_proof,
            root_after: U256(root_after.to_uint().0 .0),
            tree_proof,
            tx_type,
            memo: Memo(tx_data.memo),
            deposit_data: OptDepositData(deposit_data),
        };

        let acc = tx_data.secret.tx.output.0;
        let out_notes = tx_data
            .secret
            .tx
            .output
            .1
            .iter()
            .enumerate()
            .map(|(i, n)| (tx_index + i as u64, *n))
            .collect::<Vec<_>>();

        println!("!!!!!! tx_index: {}", tx_index);
        println!("!!!!!! acc: {:?}", &acc);
        println!("!!!!!! out_notes: {:?}", &out_notes);

        account.state.add_full_tx(
            tx_index,
            tx_data.out_hashes.as_slice(),
            Some(acc),
            &out_notes,
        );

        println!("root_before: {}", &root_before);
        println!("root_after: {}", &root_after);
        println!("nullifier: {}", &tx.nullifier);
        println!("out_commit: {}", &tx_data.public.out_commit);
        println!("delta: {}", &tx_data.public.delta);

        tx
    }

    // transact: deposit + transfer + withdraw
    #[cfg(feature = "heavy_tests")]
    #[test]
    fn test_transact() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);
        let signer = signer();

        let sk = 123.try_into().unwrap();
        let state = State::init_test(POOL_PARAMS.clone());
        let mut account = UserAccount::new(sk, state, POOL_PARAMS.clone());

        assert_eq!(contract.pool_index(), U256::from(0));
        // deposit
        {
            let deposit = create_tx(
                ZpTxType::Deposit {
                    fee: BoundedNum::new(0.try_into().unwrap()),
                    deposit_amount: BoundedNum::new(3.try_into().unwrap()),
                    outputs: vec![],
                },
                &mut account,
                &mut context,
                &mut contract,
            );

            testing_env!(context.build());
            contract.transact(deposit);
        }
        assert_eq!(contract.pool_index(), U256::from(128));

        // // withdraw
        // {
        //     let to = signer.try_to_vec().unwrap();
        //     let withdraw = create_tx(
        //         ZpTxType::Withdraw {
        //             fee: BoundedNum::new(0.try_into().unwrap()),
        //             withdraw_amount: BoundedNum::new(3.try_into().unwrap()),
        //             to,
        //             native_amount: BoundedNum::new(3.try_into().unwrap()),
        //             energy_amount: BoundedNum::new(0.try_into().unwrap()),
        //         },
        //         &mut account,
        //         &mut context,
        //         &mut contract,
        //     );
        //
        //     testing_env!(context.build());
        //     assert_eq!(contract.pool_index(), U256::from(128));
        //     contract.transact(withdraw);
        // }
    }

    // lock
    #[test]
    fn test_lock() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        testing_env!(context.attached_deposit(1000000000000000_u128).build());
        let lock_nonce = contract.lock(1000000000000000_u128.into());
        assert_eq!(lock_nonce, 0);

        testing_env!(context.attached_deposit(2000000000000000_u128).build());
        let lock_nonce = contract.lock(2000000000000000_u128.into());
        assert_eq!(lock_nonce, 1);
    }

    #[test]
    #[should_panic]
    fn test_lock_with_no_deposit() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        contract.lock(1000000000000000_u128.into());
    }

    #[test]
    #[should_panic]
    fn test_lock_with_lower_deposit() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        testing_env!(context.attached_deposit(1000000000000000_u128).build());
        contract.lock(2000000000000000_u128.into());
    }

    #[test]
    #[should_panic]
    fn test_lock_with_higher_deposit() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        testing_env!(context.attached_deposit(2000000000000000_u128).build());
        contract.lock(1000000000000000_u128.into());
    }

    // release
    #[test]
    fn test_release() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        testing_env!(context
            .attached_deposit(1000000000000000_u128)
            .block_timestamp(0)
            .build());
        let lock_nonce = contract.lock(1000000000000000_u128.into());
        assert_eq!(lock_nonce, 0);

        testing_env!(context
            .block_timestamp(WITHDRAW_TIMEOUT_MS * 1000000 + 1000000) // To ns + 1ms
            .build());
        contract.release(lock_nonce);
    }

    #[test]
    #[should_panic]
    fn test_release_timeout() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        testing_env!(context
            .attached_deposit(1000000000000000_u128)
            .block_timestamp(0)
            .build());
        let lock_nonce = contract.lock(1000000000000000_u128.into());
        assert_eq!(lock_nonce, 0);

        testing_env!(context
            .block_timestamp(WITHDRAW_TIMEOUT_MS * 1000000 - 1000000) // To ns - 1ms
            .build());
        contract.release(lock_nonce);
    }

    // account_locks
    #[test]
    fn test_account_locks() {
        let mut context = get_context();
        let mut contract = get_contract(&mut context);

        testing_env!(context.attached_deposit(1000000000000000_u128).build());
        let lock_nonce = contract.lock(1000000000000000_u128.into());
        assert_eq!(lock_nonce, 0);

        testing_env!(context.build());
        let locks = contract.account_locks(signer());
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].amount, 1000000000000000_u128.into());
    }
}
