
use std::slice;
use std::os::raw::{c_uchar, c_void};
use crate::attestation::{prepare_private_attestation, finalize_private_attestation, PreparedAttestation, AttestationEnvelope};


#[no_mangle]
pub extern "C" fn hte_prepare_private_attestation(
    payload_ptr: *const c_uchar,
    payload_len: usize,
    nonce_out: *mut u16,
    timestamp_ms_out: *mut u128,
) -> *mut c_void {
    let payload = unsafe { slice::from_raw_parts(payload_ptr, payload_len) };

    match prepare_private_attestation(payload) {
        Ok(prepared_attestation) => {
            unsafe {
                *nonce_out = prepared_attestation.nonce;
                *timestamp_ms_out = prepared_attestation.timestamp_ms;
            }
            Box::into_raw(Box::new(prepared_attestation)) as *mut c_void
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn hte_finalize_private_attestation(
    prepared_attestation_ptr: *mut c_void,
    signed_data_ptr: *const c_uchar,
    signed_data_len: usize,
    signature_ptr: *const c_uchar,
    signature_len: usize,
    envelope_out: *mut AttestationEnvelope,
) -> bool {
    let prepared_attestation = unsafe { Box::from_raw(prepared_attestation_ptr as *mut PreparedAttestation) };
    let signed_data = unsafe { slice::from_raw_parts(signed_data_ptr, signed_data_len) };
    let signature = unsafe { slice::from_raw_parts(signature_ptr, signature_len) };

    match finalize_private_attestation(*prepared_attestation, signed_data, signature) {
        Ok(envelope) => {
            unsafe {
                *envelope_out = envelope;
            }
            true
        },
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn hte_free_prepared_attestation(prepared_attestation_ptr: *mut c_void) {
    if !prepared_attestation_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(prepared_attestation_ptr as *mut PreparedAttestation);
        }
    }
}

#[no_mangle]
pub extern "C" fn hte_free_attestation_envelope(envelope_ptr: *mut AttestationEnvelope) {
    if !envelope_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(envelope_ptr);
        }
    }
}
