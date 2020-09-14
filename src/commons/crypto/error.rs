use std::fmt::Display;

use bcder::decode;

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    KeyError(String),

    #[display(fmt = "{}", _0)]
    SigningError(String),

    #[display(fmt = "Could not find key")]
    KeyNotFound,

    #[display(fmt = "{}", _0)]
    SignerError(String),

    #[display(fmt = "{}", _0)]
    DecodeError(decode::Error),
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
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Error::DecodeError(e)
    }
}
