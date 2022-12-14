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

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default)]
pub struct VK {
    pub alpha_g1: G1,
    pub beta_g2: G2,
    pub gamma_g2: G2,
    pub delta_g2: G2,
    pub ic: Vec<G1>,
}

#[derive(BorshDeserialize, BorshSerialize, Clone, PartialEq, Debug)]
pub struct Proof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
}

pub fn alt_bn128_groth16verify(vk: VK, proof: Proof, input: &[U256]) -> bool {
    if vk.ic.len() != input.len() + 1 {
        env::panic_str("Wrong input len.");
    }

    let neg_a = alt_bn128_g1_neg(proof.a);
    let acc_expr = vk
        .ic
        .iter()
        .zip([U256::ONE].iter().chain(input.iter()))
        .map(|(&base, &exp)| (base, exp))
        .collect::<Vec<_>>();
    let acc = alt_bn128_g1_multiexp(&acc_expr);

    let pairing_expr = vec![
        (neg_a, proof.b),
        (vk.alpha_g1, vk.beta_g2),
        (acc, vk.gamma_g2),
        (proof.c, vk.delta_g2),
    ];

    alt_bn128_pairing_check(pairing_expr)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test argument serialization
    #[test]
    fn test_alt_bn128_g1_multiexp() {
        let v = vec![(G1::default(), Fr::default())];
        let res = alt_bn128_g1_multiexp(&v);
        assert_eq!(res, G1::default());
    }

    #[test]
    fn test_alt_bn128_g1_neg() {
        let p = G1::default();
        let res = alt_bn128_g1_neg(p);
        assert_eq!(res, G1::default());
    }

    #[test]
    fn test_alt_bn128_pairing_check() {
        let v = vec![(G1::default(), G2::default())];
        let res = alt_bn128_pairing_check(v);
        assert_eq!(res, true);
    }
}
