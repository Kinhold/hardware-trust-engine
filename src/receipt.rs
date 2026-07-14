use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiptProofMaterial<'a> {
    #[serde(borrow)]
    pub proof_bytes: &'a [u8],
    #[serde(borrow)]
    pub public_inputs_bytes: &'a [u8],
}

impl<'a> ReceiptProofMaterial<'a> {
    pub fn new(proof: &'a [u8], public_inputs: &'a [u8]) -> Self {
        Self {
            proof_bytes: proof,
            public_inputs_bytes: public_inputs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierMetadata {
    pub name: String,
    pub version: String,
}
