#![no_main]
#![no_std]
extern crate alloc;
#[macro_use] extern crate arrayref;

#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

use alloc::vec;
use alloc::vec::Vec;

use stylus_sdk::stylus_proc::entrypoint;
use p256::ecdsa::{VerifyingKey, signature::Verifier, Signature};
use p256::EncodedPoint;

#[entrypoint]
pub fn user_main(input: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    let message = array_ref!(&input, 0, 32);
    let r: &[u8;32] = array_ref!(&input, 32, 32);
    let s: &[u8;32] = array_ref!(&input, 64, 32);
    let x: &[u8;32] = array_ref!(&input, 96, 32);
    let y: &[u8;32] = array_ref!(&input, 128, 32);

    let signature = Signature::from_scalars(*r, *s).unwrap();
    let pk_bytes = EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    let verifying_key = VerifyingKey::from_encoded_point(&pk_bytes).unwrap();

    verifying_key.verify(message, &signature).unwrap();
    let mut result = vec![0u8;32];
    result[31] = 1;
    Ok(result)
}
