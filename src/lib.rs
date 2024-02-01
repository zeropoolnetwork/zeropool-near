#![feature(iterator_try_collect)]

use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::PublicKey;
use ff_uint::{Num, NumRepr, PrimeField};
use near_sdk::{
    collections::TreeMap, env, json_types::U128, log, near_bindgen, require, serde_json::json,
    AccountId, Gas, PanicOnDefault, Promise, PromiseOrValue,
};

use crate::{
    lockup::{FullLock, Lockups},
    num::*,
    tx_decoder::{parse_delta, Tx, TxType},
    withdraw::Withdraws,
};

mod lockup;
mod num;
mod tx_decoder;
mod withdraw;

pub mod verifiers;

use core::num::NonZeroU32;

use getrandom::{register_custom_getrandom, Error};

use crate::verifiers::{
    default::{Backend, VK},
    VerifierBackend,
};

// Some application-specific error code
const MY_CUSTOM_ERROR_CODE: u32 = Error::CUSTOM_START + 42;
pub fn always_fail(_buf: &mut [u8]) -> Result<(), Error> {
    let code = NonZeroU32::new(MY_CUSTOM_ERROR_CODE).unwrap();
    Err(Error::from(code))
}

register_custom_getrandom!(always_fail);

pub const FT_TRANSFER_GAS: Gas = Gas(10_000_000_000_000);
const FIRST_ROOT: U256 = U256::from_const_str(
    "11469701942666298368112882412133877458305516134926649826543144744382391691533",
);
const R: U256 = U256::from_const_str(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

fn tree_vk() -> VK {
    #[cfg(feature = "plonk")]
    const TREE_VK: &[u8] = include_bytes!("../params/tree_vd.bin");
    #[cfg(feature = "groth16")]
    const TREE_VK: &[u8] = include_bytes!("../params/tree_vk.bin");

    VK::deserialize(&mut &Vec::<u8>::from(TREE_VK)[..]).unwrap()
    // .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."))
}

fn tx_vk() -> VK {
    #[cfg(feature = "plonk")]
    const TX_VK: &[u8] = include_bytes!("../params/transfer_vd.bin");
    #[cfg(feature = "groth16")]
    const TX_VK: &[u8] = include_bytes!("../params/transfer_vk.bin");

    VK::deserialize(&mut &Vec::<u8>::from(TX_VK)[..])
        .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."))
}

#[near_bindgen]
#[derive(PanicOnDefault, BorshDeserialize, BorshSerialize)]
pub struct PoolContract {
    /// Operator is an entity that can make new transactions.
    operator: AccountId,
    /// The next transaction index.
    pool_index: U256,
    /// Merkle roots. "transaction index" => "merkle root"
    roots: TreeMap<U256, U256>,
    /// Nullifiers for used accounts. "nullifier" => "keccak256(out_commit + delta)".
    nullifiers: TreeMap<U256, U256>,
    /// Accumulative transaction hash
    all_messages_hash: U256,
    denominator: U256,
    /// Temporary deposits: simulation of ethereum's allowance system.
    // TODO: Allow multiple deposits per user
    lockups: Lockups,
    withdraws: Withdraws,
}

impl PoolContract {
    fn check_operator(&self) -> AccountId {
        if env::signer_account_id() != self.operator {
            panic!("Only operator can call this method");
        }

        self.operator.clone()
    }
}

#[near_bindgen]
impl PoolContract {
    /// Accepts transaction and merkle tree verifying keys.
    #[init]
    pub fn new(token_id: AccountId, denominator: String) -> Self {
        assert!(!env::state_exists(), "Already initialized");

        if token_id.as_str() != "near" && cfg!(not(feature = "ft")) {
            env::panic_str("Non NEAR tokens are not supported");
        }

        let denominator = U256::from_str(&denominator).unwrap_or_else(|_| {
            env::panic_str("Cannot parse denominator. It should be a decimal number.")
        });

        let mut roots = TreeMap::new("roots".as_bytes());
        roots.insert(&U256::ZERO, &FIRST_ROOT);

        let default_operator = env::signer_account_id();

        Self {
            roots,
            operator: default_operator,
            pool_index: U256::ZERO,
            nullifiers: TreeMap::new("nullifiers".as_bytes()),
            all_messages_hash: U256::ZERO,
            denominator,
            lockups: Lockups::new(token_id.clone()),
            withdraws: Withdraws::new(token_id),
        }
    }

    /// Set the operator (relayer).
    #[private]
    pub fn set_operator(&mut self, operator: AccountId) {
        self.operator = operator;
    }

    #[result_serializer(borsh)]
    pub fn denominator(&self) -> U256 {
        self.denominator
    }

    /// Can be called by a client to reserve a certain amount of yoctoNEAR for use in the `transact`
    /// method. Returns the lockup ID.
    #[payable]
    pub fn lock(&mut self, amount: U128) -> u64 {
        let attached_amount = env::attached_deposit();
        let signer = env::signer_account_id();
        let signer_pk = env::signer_account_pk();

        require!(
            amount.0 == attached_amount,
            "Invalid attached amount: must be equal to the specified amount"
        );

        let pk_serialized = &signer_pk.as_bytes()[1..];
        let pk = PublicKey::from_bytes(&pk_serialized).expect("Invalid public key");

        self.lockups.lock(signer, amount.0, pk)
    }

    /// Release the funds previously reserved with the `lock` method.
    pub fn release(&mut self, id: u64) -> Promise {
        let signer = env::signer_account_id();
        self.lockups.release(signer, id)
    }

    pub fn withdraw(&mut self, account_id: AccountId) -> Promise {
        self.withdraws.execute(account_id)
    }

    /// Get all locks for the specified account in JSON format.
    /// ```json
    /// [{ nonce: 123, amount: "123", timestamp: "123" }, ...]
    /// ```
    pub fn account_locks(&self, account_id: AccountId) -> Vec<FullLock> {
        self.lockups.account_locks(account_id)
    }

    /// Return the index of the next transaction.
    #[result_serializer(borsh)]
    pub fn pool_index(&self) -> U256 {
        self.pool_index
    }

    /// Return the merkle root at the specified transaction index.
    #[result_serializer(borsh)]
    pub fn merkle_root(&self, #[serializer(borsh)] index: U256) -> Option<U256> {
        self.roots.get(&index)
    }

    /// The main transaction method.
    /// Validates the transaction, handles deposits/withdrawals, pays fees to the operator.
    /// Can only be called by the current operator.
    pub fn transact(&mut self, #[serializer(borsh)] tx: Tx) -> PromiseOrValue<()> {
        let operator_id = self.check_operator();
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

        const POOL_ID: U256 = U256::ZERO;
        const DELTA_SIZE: u32 = 256;

        let transact_inputs = [
            root_before,
            tx.nullifier,
            tx.out_commit,
            tx.delta.unchecked_add(POOL_ID.unchecked_shr(DELTA_SIZE)),
            message_hash_num,
        ];

        log!("Verifying transaction proof");
        if !<Backend as VerifierBackend>::verify(tx_vk(), tx.transact_proof, &transact_inputs) {
            log!("Transaction proof inputs:\nroot_before: {},\nnullifier: {},\nout_commit: {},\ndelta: {},\nmessage_hash_num: {}", root_before, tx.nullifier, tx.out_commit, transact_inputs[3], message_hash_num);
            env::panic_str("Transaction proof is invalid.");
        }

        if self.nullifiers.contains_key(&tx.nullifier) {
            env::panic_str("Double spend.");
        }

        if transfer_index > self.pool_index {
            env::panic_str("Transfer index is greater than pool index.");
        }

        let pool_root = self
            .roots
            .get(&self.pool_index)
            .unwrap_or_else(|| env::panic_str("Root not found"));
        let tree_inputs = [pool_root, tx.root_after, tx.out_commit];

        log!("Verifying tree proof");
        if !<Backend as VerifierBackend>::verify(tree_vk(), tx.tree_proof, &tree_inputs) {
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
                let dest = tx.memo.withdraw_address();

                if self.withdraws.exists(&dest) {
                    env::panic_str("Already has unexecuted withdraw");
                }

                if token_amount > 0 || energy_amount > 0 {
                    env::panic_str("token_amount and energy_amount must be negative or zero.");
                }

                let withdraw_amount = -token_amount * denominator;

                log!("Withdrawal to {}: {}", dest, withdraw_amount);

                let withdraw_amount = withdraw_amount.try_into().unwrap();

                self.withdraws.insert(dest.clone(), withdraw_amount);
            }
        }

        let mut res = PromiseOrValue::Value(());
        if fee > 0 {
            let fee = fee * denominator;

            let promise = if cfg!(not(feature = "ft")) {
                if tx.token_id.as_str() != "near" {
                    env::panic_str("Only NEAR withdrawals are supported.");
                }

                Promise::new(operator_id).transfer(fee as u128)
            } else if cfg!(feature = "ft") {
                Promise::new(tx.token_id).function_call(
                    "ft_transfer".to_string(),
                    json!({
                        "receiver_id": operator_id,
                        "memo": "fee",
                        "amount": fee,
                    })
                    .to_string()
                    .as_bytes()
                    .to_vec(),
                    1,
                    FT_TRANSFER_GAS,
                )
            } else {
                env::panic_str("Unsupported token");
            };

            res = PromiseOrValue::Promise(promise);
        }

        self.pool_index = U256::from(self.pool_index).unchecked_add(U256::from(128u8));
        self.roots.insert(&self.pool_index, &tx.root_after);
        self.nullifiers.insert(&tx.nullifier, &hash);
        self.all_messages_hash = new_all_messages_hash;

        res
    }

    #[cfg(feature = "ft")]
    /// Support for FT version of `lock`.
    /// Used with ft_transfer_call.
    pub fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let ft_token_id = env::predecessor_account_id();
        require!(ft_token_id == self.lockups.token_id, "Unsupported token");

        #[derive(Deserialize)]
        #[serde(tag = "method", content = "args")]
        #[serde(rename_all = "snake_case")]
        enum Msg {
            /// { "method": "lock" }
            Lock,
        }

        let msg: Msg = serde_json::from_str(&msg).unwrap_or_else(|_| env::panic_str("Invalid msg"));

        match msg {
            Msg::Lock => {
                let signer_pk = env::signer_account_pk();
                let pk_serialized = &signer_pk.as_bytes()[1..];
                let pk = PublicKey::from_bytes(&pk_serialized).expect("Invalid public key");
                self.lockups.lock(sender_id, amount.0, pk);

                PromiseOrValue::Value(0u128.into())
            }
        }
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
        verifiers::default::Proof,
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

    fn get_contract(context: &mut VMContextBuilder) -> PoolContract {
        let tx_vk = std::fs::read("params/transfer_verification_key.bin").unwrap();
        let tree_vk = std::fs::read("params/tree_verification_key.bin").unwrap();

        let tx_vk = VK::deserialize(&mut &Vec::<u8>::from(tx_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));
        let tree_vk = VK::deserialize(&mut &Vec::<u8>::from(tree_vk)[..])
            .unwrap_or_else(|_| env::panic_str("Cannot deserialize vk."));

        testing_env!(context.build());
        PoolContract::new_bin(
            tx_vk,
            tree_vk,
            AccountId::new_unchecked("near".to_string()),
            DENOMINATOR.into(),
        )
    }

    fn tx_proof(
        public: TransferPub<<Bn256 as Engine>::Fr>,
        secret: TransferSec<<Bn256 as Engine>::Fr>,
    ) -> Proof {
        let params_bin = std::fs::read("params/transfer_params.bin").unwrap();
        let params = Parameters::<Bn256>::read(&mut params_bin.as_slice(), true, true).unwrap();

        let circuit = |public, secret| {
            c_transfer(&public, &secret, &*POOL_PARAMS);
        };

        let (_inputs, snark_proof) = prove(&params, &public, &secret, circuit);

        let proof_bytes = snark_proof.try_to_vec().unwrap();
        Proof::try_from_slice(&proof_bytes).unwrap()
    }

    fn tree_proof(
        public: TreePub<<Bn256 as Engine>::Fr>,
        secret: TreeSec<<Bn256 as Engine>::Fr>,
    ) -> Proof {
        let params_bin = std::fs::read("params/tree_params.bin").unwrap();
        let params = Parameters::<Bn256>::read(&mut params_bin.as_slice(), true, true).unwrap();

        let circuit = |public, secret| {
            tree_update(&public, &secret, &*POOL_PARAMS);
        };

        let (_inputs, snark_proof) = prove(&params, &public, &secret, circuit);

        let proof_bytes = snark_proof.try_to_vec().unwrap();
        Proof::try_from_slice(&proof_bytes).unwrap()
    }

    fn create_tx(
        native_tx_type: ZpTxType<<Bn256 as Engine>::Fr>,
        account: &mut UserAccount<MemoryDatabase, PoolBN256>,
        context: &mut VMContextBuilder,
        contract: &mut PoolContract,
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
