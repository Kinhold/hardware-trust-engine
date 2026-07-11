
use crate::HteError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE_EXPIRATION_MS: u128 = 2000; // 2 seconds

#[derive(Debug, Serialize, Deserialize)]
pub struct PreparedAttestation {
    #[serde(skip)] // Don't serialize sensitive payload
    pub transient_payload: Vec<u8>,
    pub nonce: u16,
    pub timestamp_ms: u128,
}

impl Zeroize for PreparedAttestation {
    fn zeroize(&mut self) {
        self.transient_payload.zeroize();
        self.nonce.zeroize();
        self.timestamp_ms.zeroize();
    }
}

impl Drop for PreparedAttestation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    pub signed_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: u16,
    pub timestamp_ms: u128,
}

pub fn prepare_private_attestation(payload: &[u8]) -> Result<PreparedAttestation, HteError> {
    let nonce = generate_nonce();
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HteError::AttestationStateError(format!("SystemTime error: {}", e)))?
        .as_millis();

    let transient_payload = payload.to_vec();
    // In a real scenario, `transient_payload` would be wrapped in a `secrecy::Secret` type
    // or similar to ensure it's zeroized on drop.

    Ok(PreparedAttestation {
        transient_payload,
        nonce,
        timestamp_ms,
    })
}

pub fn finalize_private_attestation(
    prepared_attestation: PreparedAttestation,
    signed_data: &[u8],
    signature: &[u8],
) -> Result<AttestationEnvelope, HteError> {
    let current_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| HteError::AttestationStateError(format!("SystemTime error: {}", e)))?
        .as_millis();

    if current_timestamp_ms - prepared_attestation.timestamp_ms > NONCE_EXPIRATION_MS {
        return Err(HteError::AttestationStateError("Nonce expired".to_string()));
    }

    // In a real implementation, you would verify the signature against the public key
    // associated with the hardware that performed the signing.
    // For this example, we'll just check if the signed_data matches the original payload.
    if signed_data != prepared_attestation.transient_payload.as_slice() {
        return Err(HteError::AttestationStateError("Signed data mismatch".to_string()));
    }

    Ok(AttestationEnvelope {
        signed_data: signed_data.to_vec(),
        signature: signature.to_vec(),
        nonce: prepared_attestation.nonce,
        timestamp_ms: prepared_attestation.timestamp_ms,
    })
}

fn generate_nonce() -> u16 {
    // In a real scenario, this would be a cryptographically secure random nonce
    // For simplicity, a basic random number is used.
    use rand::Rng;
    rand::thread_rng().gen::<u16>()
}
