use crate::HteError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Software = 0,
    Tee = 1,
    StrongBox = 2,
}

impl TryFrom<u32> for SecurityLevel {
    type Error = HteError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SecurityLevel::Software),
            1 => Ok(SecurityLevel::Tee),
            2 => Ok(SecurityLevel::StrongBox),
            _ => Err(HteError::InvalidAttestationData(
                "unknown security level".to_string(),
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AndroidKeyDescription {
    pub attestation_version: u32,
    pub attestation_security_level: SecurityLevel,
    pub keymaster_version: u32,
    pub keymaster_security_level: SecurityLevel,
}

impl AndroidKeyDescription {
    /// Parsing is deliberately unavailable until strict DER validation exists.
    pub fn from_asn1_der(der_bytes: &[u8]) -> Result<Self, HteError> {
        if der_bytes.is_empty() {
            return Err(HteError::InvalidAttestationData(
                "Android key description is empty".to_string(),
            ));
        }
        Err(HteError::Unsupported(
            "Android key attestation DER parsing is not implemented".to_string(),
        ))
    }
}

pub struct TeeQuoteBackend;

impl TeeQuoteBackend {
    /// Fails closed until certificate parsing and trust-path validation exist.
    pub fn verify_android_attestation(
        attestation_cert_chain: &[&[u8]],
        google_root_ca_public_key: &[u8],
    ) -> Result<AndroidKeyDescription, HteError> {
        if attestation_cert_chain.is_empty() {
            return Err(HteError::InvalidAttestationData(
                "empty certificate chain".to_string(),
            ));
        }
        if google_root_ca_public_key.is_empty() {
            return Err(HteError::UntrustedChain(
                "trust anchor is empty".to_string(),
            ));
        }
        Err(HteError::Unsupported(
            "Android certificate-chain and key-attestation verification is not implemented"
                .to_string(),
        ))
    }

    /// Fails closed until quote parsing and measurement policy exist.
    pub fn verify_sgx_sev_quote(quote_bytes: &[u8]) -> Result<(), HteError> {
        if quote_bytes.is_empty() {
            return Err(HteError::InvalidAttestationData(
                "SGX/SEV quote is empty".to_string(),
            ));
        }
        Err(HteError::Unsupported(
            "SGX/SEV quote verification is not implemented".to_string(),
        ))
    }
}

pub struct TeeQuoteReceiptVerifier {
    google_root_ca_public_key: Vec<u8>,
}

impl TeeQuoteReceiptVerifier {
    pub fn new(google_root_ca_public_key: Vec<u8>) -> Self {
        Self {
            google_root_ca_public_key,
        }
    }
}

impl crate::ReceiptVerifierPlugin for TeeQuoteReceiptVerifier {
    fn verify_receipt(&self, receipt_proof: &[u8], _public_inputs: &[u8]) -> Result<(), HteError> {
        TeeQuoteBackend::verify_android_attestation(
            &[receipt_proof],
            &self.google_root_ca_public_key,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReceiptVerifierPlugin;

    #[test]
    fn parses_security_level_values_strictly() {
        assert_eq!(SecurityLevel::try_from(0).unwrap(), SecurityLevel::Software);
        assert_eq!(SecurityLevel::try_from(1).unwrap(), SecurityLevel::Tee);
        assert_eq!(
            SecurityLevel::try_from(2).unwrap(),
            SecurityLevel::StrongBox
        );
        assert!(SecurityLevel::try_from(3).is_err());
    }

    #[test]
    fn android_parser_rejects_empty_and_fails_closed_for_non_empty_der() {
        assert!(matches!(
            AndroidKeyDescription::from_asn1_der(b""),
            Err(HteError::InvalidAttestationData(_))
        ));
        assert!(matches!(
            AndroidKeyDescription::from_asn1_der(b"not DER"),
            Err(HteError::Unsupported(_))
        ));
    }

    #[test]
    fn android_verifier_never_accepts_placeholder_chain() {
        assert!(matches!(
            TeeQuoteBackend::verify_android_attestation(&[b"leaf", b"root"], b"anchor"),
            Err(HteError::Unsupported(_))
        ));
    }

    #[test]
    fn sgx_sev_verifier_fails_closed() {
        assert!(matches!(
            TeeQuoteBackend::verify_sgx_sev_quote(b"quote"),
            Err(HteError::Unsupported(_))
        ));
    }

    #[test]
    fn receipt_plugin_fails_closed() {
        let verifier = TeeQuoteReceiptVerifier::new(b"anchor".to_vec());

        assert!(matches!(
            verifier.verify_receipt(b"certificate", b""),
            Err(HteError::Unsupported(_))
        ));
    }
}
