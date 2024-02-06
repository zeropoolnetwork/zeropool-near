use super::num::U256;
use borsh::{BorshDeserialize, BorshSerialize};

pub mod default;

pub trait VerifierBackend {
    type VerifyingKey: BorshSerialize + BorshDeserialize;
    type Proof;
    fn verify(vk: Self::VerifyingKey, proof: Self::Proof, inputs: &[U256]) -> bool;
}

#[cfg(all(feature="groth16"))]
pub mod groth16;

#[cfg(all(feature="groth16"))]
pub struct Groth16Backend;

#[cfg(all(feature="groth16"))]
impl VerifierBackend for Groth16Backend {
    type VerifyingKey = groth16::VK;

    type Proof = groth16::Proof;

    fn verify(vk: Self::VerifyingKey, proof: Self::Proof, inputs: &[U256]) -> bool {
        groth16::alt_bn128_groth16verify(vk, proof, inputs)
    }
}

#[cfg(all(feature="plonk"))]
pub struct PlonkBackend;

#[cfg(all(feature="plonk"))]
use near_halo2_verifier::{
    plonk_verify,
    PlonkVerifierData,
    bn256::Fr,
};

#[cfg(all(feature="plonk"))]
impl VerifierBackend for PlonkBackend {
    type VerifyingKey = PlonkVerifierData;
    type Proof = Vec<u8>;

    fn verify(vk: Self::VerifyingKey, proof: Self::Proof, inputs: &[U256]) -> bool {
        use crate::num::Uint;
        fn fr_from_near(v: U256) -> Fr {
            Fr::from_bytes(&v.to_little_endian().try_into().unwrap()).unwrap()
        }

        let inputs : Vec<_> = inputs.iter().map(|x| fr_from_near(*x)).collect();
        plonk_verify(&vk, inputs, proof)
    }
}
