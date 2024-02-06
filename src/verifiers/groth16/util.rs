use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::env;

use crate::num::*;

pub type Fr = U256;
pub type Fq = U256;
pub type G1 = [Fq; 2];
pub type G2 = [Fq; 4];

#[inline]
pub fn alt_bn128_g1_multiexp(v: &[(G1, Fr)]) -> G1 {
    let mut data = Vec::with_capacity(core::mem::size_of::<(G1, Fr)>() * v.len());
    for (g1, fr) in v {
        data.extend_from_slice(
            g1.try_to_vec()
                .unwrap_or_else(|_| env::panic_str("Cannot serialize data."))
                .as_slice(),
        );
        data.extend_from_slice(
            fr.try_to_vec()
                .unwrap_or_else(|_| env::panic_str("Cannot serialize data."))
                .as_slice(),
        );
    }

    let res = env::alt_bn128_g1_multiexp(&data);
    let mut res_ptr = &res[..];
    <G1 as BorshDeserialize>::deserialize(&mut res_ptr)
        .unwrap_or_else(|_| env::panic_str("Cannot deserialize data."))
}

#[inline]
pub fn alt_bn128_g1_neg(p: G1) -> G1 {
    let data = (true, p)
        .try_to_vec()
        .unwrap_or_else(|_| env::panic_str("Cannot serialize data."));
    let res = env::alt_bn128_g1_sum(&data);
    <G1 as BorshDeserialize>::deserialize(&mut res.as_slice())
        .unwrap_or_else(|_| env::panic_str("Cannot deserialize data."))
}

#[inline]
pub fn alt_bn128_pairing_check(v: Vec<(G1, G2)>) -> bool {
    let mut data = Vec::with_capacity(core::mem::size_of::<(G1, Fr)>() * v.len());

    for (g1, g2) in v {
        data.extend_from_slice(
            g1.try_to_vec()
                .unwrap_or_else(|_| env::panic_str("Cannot serialize data."))
                .as_slice(),
        );
        data.extend_from_slice(
            g2.try_to_vec()
                .unwrap_or_else(|_| env::panic_str("Cannot serialize data."))
                .as_slice(),
        );
    }

    env::alt_bn128_pairing_check(&data)
}
