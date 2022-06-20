use std::fmt;
use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    KeyError(String),
    SigningError(String),
    KeyNotFound,
    SignerError(String),
    DecodeError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::KeyError(e) => e.fmt(f),
            Error::SignerError(e) => e.fmt(f),
            Error::KeyNotFound => write!(f, "Could not find key"),
            Error::SigningError(e) => e.fmt(f),
            Error::DecodeError(e) => e.fmt(f),
        }
    }
}

impl Error {
    pub fn key_error(e: impl Display) -> Self {
        Error::KeyError(e.to_string())
    }

    pub fn signing(e: impl Display) -> Self {
        Error::SigningError(e.to_string())
    }

    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn decode(e: impl Display) -> Self {
        Error::DecodeError(e.to_string())
    }
}
