use super::{
    VerifierBackend
};

#[cfg(all(feature="groth16"))]
pub type Backend = crate::verifiers::Groth16Backend;

#[cfg(all(feature="plonk"))]
pub type Backend = crate::verifiers::PlonkBackend;

#[cfg(not(any(feature = "groth16", feature = "plonk")))]
compile_error!("You must enable either 'groth16' or 'plonk' feature to build this crate.");

pub type VK = <Backend as VerifierBackend>::VerifyingKey;
pub type Proof = <Backend as VerifierBackend>::Proof;
