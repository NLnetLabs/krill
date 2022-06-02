use std::{fmt, path::PathBuf};

use openssl::error::ErrorStack;
use rpki::crypto::signer::SigningAlgorithm;

use crate::commons::error::KrillIoError;

#[derive(Debug)]
pub enum SignerError {
    DecodeError,
    InvalidWorkDir(PathBuf),
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

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerError::DecodeError => write!(f, "Could not decode key"),
            SignerError::InvalidWorkDir(path) => write!(f, "Invalid base path: {}", path.to_string_lossy()),
            SignerError::IoError(e) => e.fmt(f),
            SignerError::JsonError(e) => write!(f, "Could not decode public key info: {}", e),
            SignerError::KeyNotFound => write!(f, "Could not find key"),
            SignerError::KmipError(e) => write!(f, "KMIP Error: {}", e),
            SignerError::OpenSslError(e) => write!(f, "OpenSSL Error: {}", e),
            SignerError::Other(e) => write!(f, "Signer error: {}", e),
            SignerError::PermanentlyUnusable => write!(f, "Signer is unusable"),
            SignerError::Pkcs11Error(e) => write!(f, "PKCS#11 Error: {}", e),
            SignerError::TemporarilyUnavailable => write!(f, "Signer is unavailable"),
            SignerError::UnsupportedSigningAlg(key_format) => match key_format {
                SigningAlgorithm::RsaSha256 => write!(f, "Signing with RSA not supported by signer"),
                SigningAlgorithm::EcdsaP256Sha256 => write!(f, "Signing with EcdsaP256 not supported by signer"),
            },
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
