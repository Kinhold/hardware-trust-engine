use crate::HteError;
use std::collections::HashMap;

pub trait ReceiptVerifierPlugin: Send + Sync {
    fn verify_receipt(&self, receipt_proof: &[u8], public_inputs: &[u8]) -> Result<(), HteError>;
}

/// Registry of explicitly supplied verifier implementations.
///
/// The scaffold does not install dummy verifiers: an unknown encoding fails
/// closed by returning `None`.
#[derive(Default)]
pub struct VerifierRegistry {
    verifiers: HashMap<String, Box<dyn ReceiptVerifierPlugin>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        proof_encoding: impl Into<String>,
        verifier: Box<dyn ReceiptVerifierPlugin>,
    ) -> Result<(), HteError> {
        let proof_encoding = proof_encoding.into();
        if proof_encoding.trim().is_empty() {
            return Err(HteError::InvalidProof(
                "proof encoding must not be empty".to_string(),
            ));
        }
        if self.verifiers.contains_key(&proof_encoding) {
            return Err(HteError::InvalidProof(format!(
                "verifier already registered for {proof_encoding}"
            )));
        }
        self.verifiers.insert(proof_encoding, verifier);
        Ok(())
    }

    pub fn get_verifier(&self, proof_encoding: &str) -> Option<&dyn ReceiptVerifierPlugin> {
        self.verifiers.get(proof_encoding).map(Box::as_ref)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    Success,
    Failure(String),
}

/// Native Barretenberg adapter.
///
/// This adapter is excluded from default builds because the final binary must
/// supply a native symbol with this exact ABI. Enabling the feature does not
/// make the verifier trusted; the embedding application is responsible for
/// linking and validating its Barretenberg implementation.
#[cfg(feature = "barretenberg-ffi")]
pub struct NoirProofBackend {
    verification_key: Vec<u8>,
}

#[cfg(feature = "barretenberg-ffi")]
impl NoirProofBackend {
    pub fn new(verification_key: Vec<u8>) -> Result<Self, HteError> {
        if verification_key.is_empty() {
            return Err(HteError::InvalidProof(
                "verification key must not be empty".to_string(),
            ));
        }
        Ok(Self { verification_key })
    }

    pub fn verify_proof(&self, proof_buffer: &[u8], public_inputs: &[u8]) -> Result<(), HteError> {
        if proof_buffer.is_empty() {
            return Err(HteError::InvalidProof(
                "proof must not be empty".to_string(),
            ));
        }

        let verified = unsafe {
            barretenberg_verify_proof(
                self.verification_key.as_ptr(),
                self.verification_key.len(),
                proof_buffer.as_ptr(),
                proof_buffer.len(),
                public_inputs.as_ptr(),
                public_inputs.len(),
            )
        };

        if verified {
            Ok(())
        } else {
            Err(HteError::VerificationFailed(
                "Barretenberg rejected the Noir proof".to_string(),
            ))
        }
    }
}

#[cfg(feature = "barretenberg-ffi")]
impl ReceiptVerifierPlugin for NoirProofBackend {
    fn verify_receipt(&self, receipt_proof: &[u8], public_inputs: &[u8]) -> Result<(), HteError> {
        self.verify_proof(receipt_proof, public_inputs)
    }
}

#[cfg(feature = "barretenberg-ffi")]
extern "C" {
    fn barretenberg_verify_proof(
        verification_key_ptr: *const u8,
        verification_key_len: usize,
        proof_ptr: *const u8,
        proof_len: usize,
        public_inputs_ptr: *const u8,
        public_inputs_len: usize,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectingVerifier;

    impl ReceiptVerifierPlugin for RejectingVerifier {
        fn verify_receipt(
            &self,
            _receipt_proof: &[u8],
            _public_inputs: &[u8],
        ) -> Result<(), HteError> {
            Err(HteError::VerificationFailed("rejected in test".to_string()))
        }
    }

    #[test]
    fn registry_fails_closed_without_registered_verifier() {
        let registry = VerifierRegistry::new();

        assert!(registry.get_verifier("noir").is_none());
        assert!(registry.get_verifier("tee").is_none());
    }

    #[test]
    fn registry_dispatches_only_explicitly_registered_verifier() {
        let mut registry = VerifierRegistry::new();
        registry
            .register("test", Box::new(RejectingVerifier))
            .unwrap();

        let error = registry
            .get_verifier("test")
            .unwrap()
            .verify_receipt(b"proof", b"inputs")
            .unwrap_err();

        assert!(error.to_string().contains("rejected in test"));
    }

    #[test]
    fn registry_rejects_empty_and_duplicate_encodings() {
        let mut registry = VerifierRegistry::new();
        assert!(registry.register("", Box::new(RejectingVerifier)).is_err());
        registry
            .register("test", Box::new(RejectingVerifier))
            .unwrap();
        assert!(registry
            .register("test", Box::new(RejectingVerifier))
            .is_err());
    }
}
