use crate::{num::*, verifier::Proof};
use borsh::BorshDeserialize;
use near_sdk::{env, AccountId};

const BALANCE_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshDeserialize)]
#[repr(u16)]
pub enum TxType {
    Deposit = 0,
    Transfer = 1,
    Withdraw = 2,
}

#[derive(Debug, PartialEq, BorshDeserialize)]
pub struct Tx {
    pub nullifier: U256,
    pub out_commit: U256,
    pub transfer_index: U256,
    pub energy_amount: U256,
    pub token_amount: U256,
    pub delta: U256,
    pub transact_proof: Proof,
    pub root_after: U256,
    pub tree_proof: Proof,
    pub tx_type: TxType,
    pub memo: Memo,
    pub deposit_address: AccountId,
}

#[derive(Debug, PartialEq, BorshDeserialize)]
pub struct Memo(Vec<u8>);

impl Memo {
    #[inline]
    pub fn fee(&self) -> U256 {
        U256::from_big_endian(&self.0[0..BALANCE_SIZE])
    }

    #[inline]
    pub fn _native_amount(&self) -> U256 {
        const OFFSET: usize = BALANCE_SIZE;
        U256::from_big_endian(&self.0[OFFSET..(OFFSET + BALANCE_SIZE)])
    }

    #[inline]
    pub fn address(&self) -> AccountId {
        const OFFSET: usize = BALANCE_SIZE * 2;
        AccountId::try_from_slice(&self.0[OFFSET..]).expect("invalid address")
    }

    #[inline]
    pub fn hash(&self) -> [u8; 32] {
        env::keccak256_array(&self.0)
    }
}
