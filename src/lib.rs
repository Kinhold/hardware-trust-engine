
pub mod verifier;
pub mod receipt;
pub mod tee;
pub mod attestation;
pub mod ffi;
pub mod jni;

#[derive(Debug, thiserror::Error)]
pub enum HteError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("FFI error: {0}")]
    FfiError(String),
    #[error("Invalid attestation data: {0}")]
    InvalidAttestationData(String),
    #[error("Untrusted certificate chain: {0}")]
    UntrustedChain(String),
    #[error("Attestation state error: {0}")]
    AttestationStateError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("ASN.1 parsing error: {0}")]
    Asn1ParsingError(String),
    // Add other error types as needed
}

// Re-export key types for easier access
pub use verifier::{ReceiptVerifierPlugin, VerifierRegistry, VerificationOutcome};
pub use receipt::ReceiptProofMaterial;
pub use tee::{TeeQuoteBackend, TeeQuoteReceiptVerifier, AndroidKeyDescription, SecurityLevel};
pub use attestation::{PreparedAttestation, AttestationEnvelope};
pub use ffi::{hte_prepare_private_attestation, hte_finalize_private_attestation, hte_free_prepared_attestation, hte_free_attestation_envelope};
pub use jni::Java_com_genspark_hte_HteBridge_processPayload;
