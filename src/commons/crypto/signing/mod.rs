mod signing;
use std::{fmt, path::PathBuf};

use openssl::error::ErrorStack;

use crate::commons::error::KrillIoError;

pub use self::signing::*;

mod softsigner;
pub use self::softsigner::*;

#[cfg(feature = "hsm")]
mod pkcs11;
#[cfg(feature = "hsm")]
mod kmip;
#[cfg(feature = "hsm")]
pub use self::{pkcs11::*, kmip::*};

#[derive(Debug)]
pub enum SignerError {
    OpenSslError(ErrorStack),
    JsonError(serde_json::Error),
    InvalidWorkDir(PathBuf),
    IoError(KrillIoError),
    KeyNotFound,
    DecodeError,
    #[cfg(feature = "hsm")]
    Pkcs11Error(String),
    #[cfg(feature = "hsm")]
    KmipError(String),
    KeyMapError(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerError::OpenSslError(e) => write!(f, "OpenSsl Error: {}", e),
            SignerError::JsonError(e) => write!(f, "Could not decode public key info: {}", e),
            SignerError::InvalidWorkDir(path) => write!(f, "Invalid base path: {}", path.to_string_lossy()),
            SignerError::IoError(e) => e.fmt(f),
            SignerError::KeyNotFound => write!(f, "Could not find key"),
            SignerError::DecodeError => write!(f, "Could not decode key"),
            #[cfg(feature = "hsm")]
            SignerError::Pkcs11Error(e) => write!(f, "PKCS#11 error: {}", e),
            #[cfg(feature = "hsm")]
            SignerError::KmipError(e) => write!(f, "KMIP error: {}", e),
            SignerError::KeyMapError(e) => write!(f, "Key map access error: {}", e),
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