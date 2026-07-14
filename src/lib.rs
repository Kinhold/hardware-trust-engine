pub mod attestation;
pub mod ffi;
#[cfg(target_os = "android")]
pub mod jni;
pub mod receipt;
pub mod tee;
pub mod verifier;

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
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
}

pub use attestation::{
    finalize_private_attestation, prepare_private_attestation, AttestationEnvelope,
    PreparedAttestation, SignatureVerification,
};
pub use ffi::{
    HteAttestationEnvelopeHandle, HteAttestationEnvelopeMetadata, HtePreparedAttestationHandle,
    HtePreparedAttestationMetadata,
};
#[cfg(target_os = "android")]
pub use jni::Java_com_genspark_hte_HteBridge_processPayload;
pub use receipt::ReceiptProofMaterial;
pub use tee::{AndroidKeyDescription, SecurityLevel, TeeQuoteBackend, TeeQuoteReceiptVerifier};
#[cfg(feature = "barretenberg-ffi")]
pub use verifier::NoirProofBackend;
pub use verifier::{ReceiptVerifierPlugin, VerificationOutcome, VerifierRegistry};
