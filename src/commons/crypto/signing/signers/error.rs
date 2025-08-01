use std::fmt;

use openssl::error::ErrorStack;
use rpki::crypto::signer::SigningAlgorithm;
use url::Url;

use crate::commons::error::KrillIoError;

#[derive(Debug)]
pub enum SignerError {
    DecodeError,
    InvalidStorage(Url),
    IoError(KrillIoError),
    JsonError(serde_json::Error),
    KeyNotFound,
    KmipError(String),
    OpenSslError(ErrorStack),
    Other(String),
    PermanentlyUnusable,
    Pkcs11Error(String),
    TemporarilyUnavailable,
    UnsupportedSigningAlg(SigningAlgorithm),
}

impl SignerError {
    pub fn other(msg: impl fmt::Display) -> Self {
        SignerError::Other(msg.to_string())
    }
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerError::DecodeError => write!(f, "Could not decode key"),
            SignerError::InvalidStorage(url) => {
                write!(f, "Invalid storage url: {url}")
            }
            SignerError::IoError(e) => e.fmt(f),
            SignerError::JsonError(e) => {
                write!(f, "Could not decode public key info: {e}")
            }
            SignerError::KeyNotFound => write!(f, "Could not find key"),
            SignerError::KmipError(e) => write!(f, "KMIP Error: {e}"),
            SignerError::OpenSslError(e) => write!(f, "OpenSSL Error: {e}"),
            SignerError::Other(e) => write!(f, "Signer error: {e}"),
            SignerError::PermanentlyUnusable => {
                write!(f, "Signer is unusable")
            }
            SignerError::Pkcs11Error(e) => write!(f, "{e}"), /* Cryptoki prefixes e with "PKCS11 error" */
            SignerError::TemporarilyUnavailable => {
                write!(f, "Signer is unavailable")
            }
            SignerError::UnsupportedSigningAlg(key_format) => {
                match key_format {
                    SigningAlgorithm::RsaSha256 => {
                        write!(f, "Signing with RSA not supported")
                    }
                    SigningAlgorithm::EcdsaP256Sha256 => {
                        write!(f, "Signing with EcdsaP256 not supported")
                    }
                }
            }
        }
    }
}

impl From<ErrorStack> for SignerError {
    fn from(e: ErrorStack) -> Self {
        SignerError::OpenSslError(e)
    }
}

impl From<serde_json::Error> for SignerError {
    fn from(e: serde_json::Error) -> Self {
        SignerError::JsonError(e)
    }
}

impl From<KrillIoError> for SignerError {
    fn from(e: KrillIoError) -> Self {
        SignerError::IoError(e)
    }
}
