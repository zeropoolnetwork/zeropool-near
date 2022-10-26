use borsh::{BorshDeserialize, BorshSerialize};
use ff_uint::{Num, NumRepr, PrimeField};
use near_crypto::Signature;
use near_sdk::{env, AccountId};

use crate::{num::*, verifier::Proof};

const BALANCE_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TxType {
    Deposit = 0,
    Transfer = 1,
    Withdraw = 2,
}

#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Tx {
    pub nullifier: U256,
    pub out_commit: U256,
    pub token_id: AccountId,
    pub delta: U256,
    pub transact_proof: Proof,
    pub root_after: U256,
    pub tree_proof: Proof,
    pub tx_type: TxType,
    pub memo: Memo,
}

#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Memo(Vec<u8>);

impl Memo {}

#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct DepositData {
    pub deposit_address: AccountId,
    pub deposit_id: u64,
    pub deposit_signature: Signature,
}

impl Memo {
    #[inline]
    pub fn fee(&self) -> U256 {
        U256::from_big_endian(&self.0[0..BALANCE_SIZE])
    }

    #[inline]
    pub fn _withdraw_native_amount(&self) -> U256 {
        const OFFSET: usize = BALANCE_SIZE;
        U256::from_big_endian(&self.0[OFFSET..(OFFSET + BALANCE_SIZE)])
    }

    #[inline]
    pub fn withdraw_address(&self) -> AccountId {
        const OFFSET: usize = BALANCE_SIZE * 2;
        let str_len = u32::from_le_bytes(self.0[OFFSET..(OFFSET + 4)].try_into().unwrap());
        let address_end = OFFSET + 4 + str_len as usize;
        AccountId::try_from_slice(&self.0[OFFSET..address_end]).expect("invalid address")
    }

    #[inline]
    pub fn hash(&self) -> [u8; 32] {
        env::keccak256_array(&self.0)
    }

    #[inline]
    pub fn _user_data(&self, tx_type: TxType) -> Vec<u8> {
        let ciphertext_offset = match tx_type {
            TxType::Deposit | TxType::Transfer => BALANCE_SIZE,
            TxType::Withdraw => {
                const OFFSET: usize = BALANCE_SIZE * 2;
                let str_length =
                    u32::from_le_bytes(self.0[OFFSET..(OFFSET + 4)].try_into().unwrap());
                OFFSET + 4 + str_length as usize
            }
        };

        let buf_len =
            u32::from_le_bytes(self.0[BALANCE_SIZE..(BALANCE_SIZE + 4)].try_into().unwrap());

        let full_offset = ciphertext_offset + 4 + buf_len as usize;
        self.0[full_offset..].to_vec()
    }

    #[inline]
    pub fn deposit_data(&self) -> DepositData {
        let ciphertext_len =
            u32::from_le_bytes(self.0[BALANCE_SIZE..(BALANCE_SIZE + 4)].try_into().unwrap());

        let full_offset = BALANCE_SIZE + 4 + ciphertext_len as usize;
        DepositData::try_from_slice(&self.0[full_offset..]).expect("Invalid deposit data")
    }
}

pub fn parse_delta(delta: Num<Fr>) -> (Num<Fr>, Num<Fr>, Num<Fr>, Num<Fr>) {
    const HEIGHT: usize = 48;
    const BALANCE_SIZE_BITS: usize = 64;
    const ENERGY_SIZE_BITS: usize = BALANCE_SIZE_BITS + HEIGHT;
    const POOLID_SIZE_BITS: usize = 24;

    fn _parse_uint<U: Uint>(n: &mut NumRepr<U>, len: usize) -> NumRepr<U> {
        let t = *n;
        *n = *n >> len as u32;
        t - (*n << len as u32)
    }

    fn parse_uint<Fr: PrimeField>(n: &mut NumRepr<Fr::Inner>, len: usize) -> Num<Fr> {
        Num::from_uint(_parse_uint(n, len)).unwrap()
    }

    fn parse_int<Fr: PrimeField>(n: &mut NumRepr<Fr::Inner>, len: usize) -> Num<Fr> {
        let two_component_term = -Num::from_uint(NumRepr::ONE << len as u32).unwrap();
        let r = _parse_uint(n, len);
        if r >> (len as u32 - 1) == NumRepr::ZERO {
            Num::from_uint(r).unwrap()
        } else {
            Num::from_uint(r).unwrap() + two_component_term
        }
    }

    let mut delta_num = delta.to_uint();

    (
        parse_int(&mut delta_num, BALANCE_SIZE_BITS),
        parse_int(&mut delta_num, ENERGY_SIZE_BITS),
        parse_uint(&mut delta_num, HEIGHT),
        parse_uint(&mut delta_num, POOLID_SIZE_BITS),
    )
}
