#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;

pub struct HardwareTrustCircuit<ConstraintField: PrimeField> {
    pub hardware_public_key_x: Option<ConstraintField>,
    pub hardware_public_key_y: Option<ConstraintField>,
    pub signature_r: Option<ConstraintField>,
    pub signature_s: Option<ConstraintField>,
    pub challenge_hash: Option<ConstraintField>,
}

impl<ConstraintField: PrimeField> ConstraintSynthesizer<ConstraintField> for HardwareTrustCircuit<ConstraintField> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintField>,
    ) -> Result<(), SynthesisError> {
        let _pub_key_x = FpVar::new_witness(ark_relations::ns!(cs, "pub_key_x"), || {
            self.hardware_public_key_x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _pub_key_y = FpVar::new_witness(ark_relations::ns!(cs, "pub_key_y"), || {
            self.hardware_public_key_y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _sig_r = FpVar::new_witness(ark_relations::ns!(cs, "sig_r"), || {
            self.signature_r.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _sig_s = FpVar::new_witness(ark_relations::ns!(cs, "sig_s"), || {
            self.signature_s.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _challenge = FpVar::new_input(ark_relations::ns!(cs, "challenge"), || {
            self.challenge_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "C" fn prove_hardware_signature(
    _pk_x_ptr: *const u8,
    _pk_y_ptr: *const u8,
    _sig_r_ptr: *const u8,
    _sig_s_ptr: *const u8,
    _challenge_ptr: *const u8,
    _out_proof_ptr: *mut u8,
) -> i32 {
    0
}
