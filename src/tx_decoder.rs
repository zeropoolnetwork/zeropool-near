use std::io::Write;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use ff_uint::{Num, NumRepr, PrimeField};
use near_sdk::{env, AccountId};

use crate::{num::*, verifiers::default::Proof};

const BALANCE_SIZE: usize = 8;

#[derive(BorshSerialize)]
pub struct DepositDataForSigning<'a> {
    pub nullifier: U256,
    pub account_id: &'a AccountId,
    pub id: u64,
}

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
    pub deposit_data: OptDepositData,
}

// Since deposit_data is at the end of the transaction, we can save 1 byte by interpreting EOF as None.
#[derive(Debug, PartialEq)]
pub struct OptDepositData(pub Option<DepositData>);

impl BorshSerialize for OptDepositData {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if let Some(deposit_data) = &self.0 {
            deposit_data.serialize(writer)?;
        }

        Ok(())
    }
}

impl BorshDeserialize for OptDepositData {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        if buf.is_empty() {
            Ok(Self(None))
        } else {
            Ok(Self(Some(DepositData::deserialize(buf)?)))
        }
    }
}

#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct DepositData {
    pub signature: [u8; SIGNATURE_LENGTH],
    pub address: AccountId,
    pub id: u64,
}

impl DepositData {
    pub fn signature(&self) -> Signature {
        Signature::from_bytes(&self.signature).expect("Invalid signature")
    }
}

#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Memo(pub Vec<u8>);

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
