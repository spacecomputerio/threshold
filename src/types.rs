use thiserror::Error as ThisError;
use threshold_crypto::Ciphertext;

/// Error type for the module, using `thiserror` for easy error handling.
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Invalid cipher text: {0}")]
    InvalidCiphertext(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Wrapper for the ciphertext message, which is a serialized version of the ciphertext.
#[derive(Clone)]
pub struct CiphertextMsg(Ciphertext);

impl CiphertextMsg {
    pub fn new(ciphertext: Ciphertext) -> Self {
        CiphertextMsg(ciphertext)
    }

    pub fn get_ciphertext(&self) -> &Ciphertext {
        &self.0
    }
}

impl TryFrom<String> for CiphertextMsg {
    type Error = Error;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(data)
            .map_err(|e| Error::InvalidCiphertext(format!("failed to decode hex: {e}")))?;
        let ciphertext = serde_json::from_slice(bytes.as_slice())
            .map_err(|e| Error::InvalidCiphertext(format!("failed to deserialize hex: {e}")))?;
        Ok(CiphertextMsg(ciphertext))
    }
}

impl TryFrom<CiphertextMsg> for String {
    type Error = Error;

    fn try_from(value: CiphertextMsg) -> Result<Self, Self::Error> {
        let parsed = serde_json::to_string(value.get_ciphertext())
            .map_err(|e| Error::InvalidCiphertext(format!("Serialization error: {}", e)))?;
        Ok(hex::encode(parsed))
    }
}
