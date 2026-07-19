use crate::HteError;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

pub const CHALLENGE_LENGTH: usize = 32;
pub const ATTESTATION_EXPIRATION_MS: u64 = 2_000;
const SIGNING_DOMAIN: &[u8] = b"kinhold-hte-attestation-v1\0";

/// One-use state containing the exact message that a hardware key should sign.
///
/// This value is intentionally not `Clone`: finalization consumes it, preventing
/// safe Rust callers from finalizing the same challenge twice.
pub struct PreparedAttestation {
    signing_message: Vec<u8>,
    challenge: [u8; CHALLENGE_LENGTH],
    timestamp_ms: u64,
}

impl PreparedAttestation {
    pub fn signing_message(&self) -> &[u8] {
        &self.signing_message
    }

    pub fn challenge(&self) -> &[u8; CHALLENGE_LENGTH] {
        &self.challenge
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }
}

impl fmt::Debug for PreparedAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAttestation")
            .field("signing_message", &"<redacted>")
            .field("challenge", &self.challenge)
            .field("timestamp_ms", &self.timestamp_ms)
            .finish()
    }
}

impl Zeroize for PreparedAttestation {
    fn zeroize(&mut self) {
        self.signing_message.zeroize();
        self.challenge.zeroize();
        self.timestamp_ms.zeroize();
    }
}

impl Drop for PreparedAttestation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Whether this crate cryptographically verified the signature in an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureVerification {
    /// The signature bytes are transport data only. No public key verification occurred.
    NotPerformed,
}

/// A transport envelope, not proof of a valid hardware-backed signature.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    pub signed_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub challenge: [u8; CHALLENGE_LENGTH],
    pub timestamp_ms: u64,
    pub signature_verification: SignatureVerification,
}

pub fn prepare_private_attestation(payload: &[u8]) -> Result<PreparedAttestation, HteError> {
    prepare_private_attestation_at(payload, current_timestamp_ms()?)
}

/// Packages signer output without cryptographically verifying it.
///
/// The function rejects empty signature bytes and requires `signed_data` to be
/// the exact challenge-bound message returned by
/// [`PreparedAttestation::signing_message`]. A verifier must still validate the
/// signature and attested public key before trusting the returned envelope.
///
/// Consuming `PreparedAttestation` makes replay through the safe API a compile
/// error:
///
/// ```compile_fail
/// use hardware_trust_engine::{
///     finalize_private_attestation, prepare_private_attestation,
/// };
///
/// let prepared = prepare_private_attestation(b"payload").unwrap();
/// let message = prepared.signing_message().to_vec();
/// let _first = finalize_private_attestation(prepared, &message, b"signature").unwrap();
/// let _replay = finalize_private_attestation(prepared, &message, b"signature");
/// ```
pub fn finalize_private_attestation(
    prepared_attestation: PreparedAttestation,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<AttestationEnvelope, HteError> {
    finalize_private_attestation_at(
        prepared_attestation,
        signed_data,
        signature,
        current_timestamp_ms()?,
    )
}

fn prepare_private_attestation_at(
    payload: &[u8],
    timestamp_ms: u64,
) -> Result<PreparedAttestation, HteError> {
    if payload.is_empty() {
        return Err(HteError::InvalidAttestationData(
            "payload must not be empty".to_string(),
        ));
    }

    let payload_len = u64::try_from(payload.len()).map_err(|_| {
        HteError::InvalidAttestationData("payload is too large to encode".to_string())
    })?;
    let mut challenge = [0_u8; CHALLENGE_LENGTH];
    OsRng.try_fill_bytes(&mut challenge).map_err(|error| {
        HteError::AttestationStateError(format!("challenge generation failed: {error}"))
    })?;

    let mut signing_message = Vec::new();
    signing_message.extend_from_slice(SIGNING_DOMAIN);
    signing_message.extend_from_slice(&challenge);
    signing_message.extend_from_slice(&timestamp_ms.to_le_bytes());
    signing_message.extend_from_slice(&payload_len.to_le_bytes());
    signing_message.extend_from_slice(payload);

    Ok(PreparedAttestation {
        signing_message,
        challenge,
        timestamp_ms,
    })
}

fn finalize_private_attestation_at(
    prepared_attestation: PreparedAttestation,
    signed_data: &[u8],
    signature: &[u8],
    current_timestamp_ms: u64,
) -> Result<AttestationEnvelope, HteError> {
    let age_ms = current_timestamp_ms
        .checked_sub(prepared_attestation.timestamp_ms)
        .ok_or_else(|| {
            HteError::AttestationStateError(
                "system clock precedes attestation preparation".to_string(),
            )
        })?;

    if age_ms > ATTESTATION_EXPIRATION_MS {
        return Err(HteError::AttestationStateError(
            "attestation challenge expired".to_string(),
        ));
    }
    if signature.is_empty() {
        return Err(HteError::AttestationStateError(
            "signature must not be empty".to_string(),
        ));
    }
    if signed_data != prepared_attestation.signing_message.as_slice() {
        return Err(HteError::AttestationStateError(
            "signed data does not match the prepared challenge".to_string(),
        ));
    }

    Ok(AttestationEnvelope {
        signed_data: signed_data.to_vec(),
        signature: signature.to_vec(),
        challenge: prepared_attestation.challenge,
        timestamp_ms: prepared_attestation.timestamp_ms,
        signature_verification: SignatureVerification::NotPerformed,
    })
}

fn current_timestamp_ms() -> Result<u64, HteError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| HteError::AttestationStateError(format!("system clock error: {error}")))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| HteError::AttestationStateError("timestamp overflow".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared_at(timestamp_ms: u64) -> PreparedAttestation {
        prepare_private_attestation_at(b"private payload", timestamp_ms).unwrap()
    }

    #[test]
    fn preparation_uses_unique_256_bit_challenges_bound_to_messages() {
        let first = prepared_at(100);
        let second = prepared_at(100);

        assert_ne!(first.challenge(), second.challenge());
        assert!(first
            .signing_message()
            .windows(CHALLENGE_LENGTH)
            .any(|window| window == first.challenge()));
    }

    #[test]
    fn packages_non_empty_signature_as_explicitly_unverified() {
        let prepared = prepared_at(100);
        let message = prepared.signing_message().to_vec();

        let envelope =
            finalize_private_attestation_at(prepared, &message, b"not verified", 101).unwrap();

        assert_eq!(envelope.signed_data, message);
        assert_eq!(
            envelope.signature_verification,
            SignatureVerification::NotPerformed
        );
    }

    #[test]
    fn rejects_empty_signature() {
        let prepared = prepared_at(100);
        let message = prepared.signing_message().to_vec();

        let error = finalize_private_attestation_at(prepared, &message, b"", 101).unwrap_err();

        assert!(error.to_string().contains("signature must not be empty"));
    }

    #[test]
    fn rejects_message_not_bound_to_prepared_challenge() {
        let prepared = prepared_at(100);

        let error =
            finalize_private_attestation_at(prepared, b"private payload", b"signature", 101)
                .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match the prepared challenge"));
    }

    #[test]
    fn rejects_expired_challenge() {
        let prepared = prepared_at(100);
        let message = prepared.signing_message().to_vec();

        let error = finalize_private_attestation_at(
            prepared,
            &message,
            b"signature",
            100 + ATTESTATION_EXPIRATION_MS + 1,
        )
        .unwrap_err();

        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn accepts_challenge_at_expiration_boundary() {
        let prepared = prepared_at(100);
        let message = prepared.signing_message().to_vec();

        let result = finalize_private_attestation_at(
            prepared,
            &message,
            b"signature",
            100 + ATTESTATION_EXPIRATION_MS,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn rejects_clock_rollback_without_panicking() {
        let prepared = prepared_at(100);
        let message = prepared.signing_message().to_vec();

        let error =
            finalize_private_attestation_at(prepared, &message, b"signature", 99).unwrap_err();

        assert!(error.to_string().contains("system clock precedes"));
    }

    #[test]
    fn rejects_empty_payload() {
        let error = prepare_private_attestation_at(b"", 100).unwrap_err();

        assert!(error.to_string().contains("payload must not be empty"));
    }
}
