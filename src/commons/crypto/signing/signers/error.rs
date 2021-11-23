use std::{fmt, path::PathBuf};

use openssl::error::ErrorStack;

use crate::commons::error::KrillIoError;

#[derive(Debug)]
pub enum SignerError {
    KmipError(String),
    OpenSslError(ErrorStack),
    JsonError(serde_json::Error),
    InvalidWorkDir(PathBuf),
    IoError(KrillIoError),
    KeyNotFound,
    DecodeError,
    SignerUnavailable,
    SignerUnusable,
    Other(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerError::KmipError(e) => write!(f, "KMIP Error: {}", e),
            SignerError::OpenSslError(e) => write!(f, "OpenSsl Error: {}", e),
            SignerError::JsonError(e) => write!(f, "Could not decode public key info: {}", e),
            SignerError::InvalidWorkDir(path) => write!(f, "Invalid base path: {}", path.to_string_lossy()),
            SignerError::IoError(e) => e.fmt(f),
            SignerError::KeyNotFound => write!(f, "Could not find key"),
            SignerError::DecodeError => write!(f, "Could not decode key"),
            SignerError::SignerUnavailable => write!(f, "Signer is unavailable"),
            SignerError::SignerUnusable => write!(f, "Signer is unusable"),
            SignerError::Other(e) => write!(f, "Signer error: {}", e),
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
