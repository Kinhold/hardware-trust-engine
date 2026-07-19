use crate::attestation::{
    finalize_private_attestation, prepare_private_attestation, AttestationEnvelope,
    PreparedAttestation, CHALLENGE_LENGTH,
};
use std::{
    os::raw::{c_int, c_uchar},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};

pub const HTE_FAILURE: c_int = 0;
pub const HTE_SUCCESS: c_int = 1;
pub const HTE_SIGNATURE_NOT_VERIFIED: u8 = 0;

/// Opaque C handle. Only functions in this module may inspect its contents.
#[repr(C)]
pub struct HtePreparedAttestationHandle {
    _private: [u8; 0],
}

/// Opaque C handle. Only functions in this module may inspect its contents.
#[repr(C)]
pub struct HteAttestationEnvelopeHandle {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HtePreparedAttestationMetadata {
    pub challenge: [u8; CHALLENGE_LENGTH],
    pub timestamp_ms: u64,
    pub signing_message_len: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HteAttestationEnvelopeMetadata {
    pub challenge: [u8; CHALLENGE_LENGTH],
    pub timestamp_ms: u64,
    pub signed_data_len: usize,
    pub signature_len: usize,
    /// Always `HTE_SIGNATURE_NOT_VERIFIED` in this scaffold.
    pub signature_verification: u8,
}

/// Creates a one-use prepared-attestation handle.
///
/// Returns null on invalid input or internal failure. The caller owns a
/// non-null handle and must pass it exactly once to either
/// `hte_finalize_private_attestation` or `hte_free_prepared_attestation`.
///
/// # Safety
///
/// `payload_ptr` must reference `payload_len` readable bytes when the length is
/// non-zero. `metadata_out` must be non-null, aligned, and writable.
#[no_mangle]
pub unsafe extern "C" fn hte_prepare_private_attestation(
    payload_ptr: *const c_uchar,
    payload_len: usize,
    metadata_out: *mut HtePreparedAttestationMetadata,
) -> *mut HtePreparedAttestationHandle {
    if metadata_out.is_null() {
        return ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let payload = unsafe { input_slice(payload_ptr, payload_len) }?;
        let prepared = prepare_private_attestation(payload).ok()?;
        let metadata = HtePreparedAttestationMetadata {
            challenge: *prepared.challenge(),
            timestamp_ms: prepared.timestamp_ms(),
            signing_message_len: prepared.signing_message().len(),
        };
        let handle = Box::into_raw(Box::new(prepared)).cast::<HtePreparedAttestationHandle>();
        unsafe { ptr::write(metadata_out, metadata) };
        Some(handle)
    }));

    match result {
        Ok(Some(handle)) => handle,
        Ok(None) | Err(_) => ptr::null_mut(),
    }
}

/// Copies the exact challenge-bound message that the hardware key should sign.
///
/// # Safety
///
/// `handle` must be a live prepared handle returned by this library.
/// `output_ptr` must reference at least `output_len` writable bytes and must not
/// overlap the handle's internal storage.
#[no_mangle]
pub unsafe extern "C" fn hte_prepared_attestation_copy_signing_message(
    handle: *const HtePreparedAttestationHandle,
    output_ptr: *mut c_uchar,
    output_len: usize,
) -> c_int {
    if handle.is_null() {
        return HTE_FAILURE;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let prepared = unsafe { prepared_from_handle(handle) };
        unsafe { copy_to_output(prepared.signing_message(), output_ptr, output_len) }
    }))
    .unwrap_or(HTE_FAILURE)
}

/// Finalizes and consumes a prepared handle.
///
/// A non-null `prepared_handle` is consumed on every return path, including
/// failure. The returned envelope owns only unverified signature bytes. The
/// caller must eventually free a non-null result with
/// `hte_free_attestation_envelope`.
///
/// # Safety
///
/// `prepared_handle` must be a live handle returned by this library and not
/// used again after this call. Each non-empty input must point to the stated
/// number of readable bytes. Input buffers must not overlap the prepared
/// handle's allocation.
#[no_mangle]
pub unsafe extern "C" fn hte_finalize_private_attestation(
    prepared_handle: *mut HtePreparedAttestationHandle,
    signed_data_ptr: *const c_uchar,
    signed_data_len: usize,
    signature_ptr: *const c_uchar,
    signature_len: usize,
) -> *mut HteAttestationEnvelopeHandle {
    if prepared_handle.is_null() {
        return ptr::null_mut();
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let prepared = unsafe { Box::from_raw(prepared_handle.cast::<PreparedAttestation>()) };
        let signed_data = unsafe { input_slice(signed_data_ptr, signed_data_len) }?;
        let signature = unsafe { input_slice(signature_ptr, signature_len) }?;
        let envelope = finalize_private_attestation(*prepared, signed_data, signature).ok()?;
        Some(Box::into_raw(Box::new(envelope)).cast::<HteAttestationEnvelopeHandle>())
    }));

    match result {
        Ok(Some(handle)) => handle,
        Ok(None) | Err(_) => ptr::null_mut(),
    }
}

/// Reads stable metadata from an envelope handle.
///
/// # Safety
///
/// `handle` must be a live envelope handle and `metadata_out` must be non-null,
/// aligned, writable, and not overlap the handle's allocation.
#[no_mangle]
pub unsafe extern "C" fn hte_attestation_envelope_metadata(
    handle: *const HteAttestationEnvelopeHandle,
    metadata_out: *mut HteAttestationEnvelopeMetadata,
) -> c_int {
    if handle.is_null() || metadata_out.is_null() {
        return HTE_FAILURE;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let envelope = unsafe { envelope_from_handle(handle) };
        let metadata = HteAttestationEnvelopeMetadata {
            challenge: envelope.challenge,
            timestamp_ms: envelope.timestamp_ms,
            signed_data_len: envelope.signed_data.len(),
            signature_len: envelope.signature.len(),
            signature_verification: HTE_SIGNATURE_NOT_VERIFIED,
        };
        unsafe { ptr::write(metadata_out, metadata) };
        HTE_SUCCESS
    }))
    .unwrap_or(HTE_FAILURE)
}

/// Copies envelope signed data to caller-owned storage.
///
/// # Safety
///
/// `handle` must be live. `output_ptr` must reference at least `output_len`
/// writable bytes and must not overlap the envelope's internal storage.
#[no_mangle]
pub unsafe extern "C" fn hte_attestation_envelope_copy_signed_data(
    handle: *const HteAttestationEnvelopeHandle,
    output_ptr: *mut c_uchar,
    output_len: usize,
) -> c_int {
    if handle.is_null() {
        return HTE_FAILURE;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let envelope = unsafe { envelope_from_handle(handle) };
        unsafe { copy_to_output(&envelope.signed_data, output_ptr, output_len) }
    }))
    .unwrap_or(HTE_FAILURE)
}

/// Copies envelope signature bytes to caller-owned storage.
///
/// # Safety
///
/// `handle` must be live. `output_ptr` must reference at least `output_len`
/// writable bytes and must not overlap the envelope's internal storage.
#[no_mangle]
pub unsafe extern "C" fn hte_attestation_envelope_copy_signature(
    handle: *const HteAttestationEnvelopeHandle,
    output_ptr: *mut c_uchar,
    output_len: usize,
) -> c_int {
    if handle.is_null() {
        return HTE_FAILURE;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let envelope = unsafe { envelope_from_handle(handle) };
        unsafe { copy_to_output(&envelope.signature, output_ptr, output_len) }
    }))
    .unwrap_or(HTE_FAILURE)
}

/// Frees a prepared handle. Passing null is a no-op.
///
/// # Safety
///
/// A non-null pointer must be a live prepared handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn hte_free_prepared_attestation(handle: *mut HtePreparedAttestationHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(handle.cast::<PreparedAttestation>()));
        }));
    }
}

/// Frees an envelope handle. Passing null is a no-op.
///
/// # Safety
///
/// A non-null pointer must be a live envelope handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn hte_free_attestation_envelope(handle: *mut HteAttestationEnvelopeHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(handle.cast::<AttestationEnvelope>()));
        }));
    }
}

unsafe fn input_slice<'a>(input_ptr: *const c_uchar, input_len: usize) -> Option<&'a [u8]> {
    if input_len == 0 {
        Some(&[])
    } else if input_ptr.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(input_ptr, input_len) })
    }
}

unsafe fn copy_to_output(source: &[u8], output_ptr: *mut c_uchar, output_len: usize) -> c_int {
    if output_len < source.len() || (output_ptr.is_null() && !source.is_empty()) {
        return HTE_FAILURE;
    }
    if !source.is_empty() {
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), output_ptr, source.len()) };
    }
    HTE_SUCCESS
}

unsafe fn prepared_from_handle<'a>(
    handle: *const HtePreparedAttestationHandle,
) -> &'a PreparedAttestation {
    unsafe { &*handle.cast::<PreparedAttestation>() }
}

unsafe fn envelope_from_handle<'a>(
    handle: *const HteAttestationEnvelopeHandle,
) -> &'a AttestationEnvelope {
    unsafe { &*handle.cast::<AttestationEnvelope>() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_round_trip_uses_opaque_owned_handles() {
        let payload = b"payload";
        let signature = b"unverified signature";
        let mut prepared_metadata = HtePreparedAttestationMetadata::default();

        unsafe {
            let prepared = hte_prepare_private_attestation(
                payload.as_ptr(),
                payload.len(),
                &mut prepared_metadata,
            );
            assert!(!prepared.is_null());
            assert_eq!(prepared_metadata.challenge.len(), CHALLENGE_LENGTH);

            let mut message = vec![0; prepared_metadata.signing_message_len];
            assert_eq!(
                hte_prepared_attestation_copy_signing_message(
                    prepared,
                    message.as_mut_ptr(),
                    message.len(),
                ),
                HTE_SUCCESS
            );

            let envelope = hte_finalize_private_attestation(
                prepared,
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            );
            assert!(!envelope.is_null());

            let mut envelope_metadata = HteAttestationEnvelopeMetadata::default();
            assert_eq!(
                hte_attestation_envelope_metadata(envelope, &mut envelope_metadata),
                HTE_SUCCESS
            );
            assert_eq!(
                envelope_metadata.signature_verification,
                HTE_SIGNATURE_NOT_VERIFIED
            );
            assert_eq!(envelope_metadata.signed_data_len, message.len());
            assert_eq!(envelope_metadata.signature_len, signature.len());

            let mut copied_signature = vec![0; envelope_metadata.signature_len];
            assert_eq!(
                hte_attestation_envelope_copy_signature(
                    envelope,
                    copied_signature.as_mut_ptr(),
                    copied_signature.len(),
                ),
                HTE_SUCCESS
            );
            assert_eq!(copied_signature, signature);
            hte_free_attestation_envelope(envelope);
        }
    }

    #[test]
    fn ffi_rejects_null_required_pointers() {
        let payload = b"payload";
        let mut metadata = HtePreparedAttestationMetadata::default();

        unsafe {
            assert!(
                hte_prepare_private_attestation(ptr::null(), payload.len(), &mut metadata)
                    .is_null()
            );
            assert!(hte_prepare_private_attestation(
                payload.as_ptr(),
                payload.len(),
                ptr::null_mut()
            )
            .is_null());
            assert!(hte_finalize_private_attestation(
                ptr::null_mut(),
                ptr::null(),
                0,
                ptr::null(),
                0
            )
            .is_null());
            hte_free_prepared_attestation(ptr::null_mut());
            hte_free_attestation_envelope(ptr::null_mut());
        }
    }

    #[test]
    fn ffi_rejects_short_output_buffer_without_writing() {
        let payload = b"payload";
        let mut metadata = HtePreparedAttestationMetadata::default();

        unsafe {
            let prepared =
                hte_prepare_private_attestation(payload.as_ptr(), payload.len(), &mut metadata);
            assert!(!prepared.is_null());
            let mut output = vec![0xA5; metadata.signing_message_len - 1];

            assert_eq!(
                hte_prepared_attestation_copy_signing_message(
                    prepared,
                    output.as_mut_ptr(),
                    output.len(),
                ),
                HTE_FAILURE
            );
            assert!(output.iter().all(|byte| *byte == 0xA5));
            hte_free_prepared_attestation(prepared);
        }
    }

    #[test]
    fn ffi_rejects_empty_signature_and_consumes_prepared_handle() {
        let payload = b"payload";
        let mut metadata = HtePreparedAttestationMetadata::default();

        unsafe {
            let prepared =
                hte_prepare_private_attestation(payload.as_ptr(), payload.len(), &mut metadata);
            let mut message = vec![0; metadata.signing_message_len];
            assert_eq!(
                hte_prepared_attestation_copy_signing_message(
                    prepared,
                    message.as_mut_ptr(),
                    message.len(),
                ),
                HTE_SUCCESS
            );

            assert!(hte_finalize_private_attestation(
                prepared,
                message.as_ptr(),
                message.len(),
                ptr::null(),
                0,
            )
            .is_null());
        }
    }
}
