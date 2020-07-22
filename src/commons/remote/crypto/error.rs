use std::fmt;

use bcder::decode;
use rpki::crypto::signer::KeyError;
use rpki::crypto::SigningError;

#[derive(Debug, Display)]
pub enum Error<S: fmt::Debug + fmt::Display> {
    #[display(fmt = "{}", _0)]
    KeyError(KeyError<S>),

    #[display(fmt = "{}", _0)]
    SigningError(SigningError<S>),

    #[display(fmt = "Could not find key")]
    KeyNotFound,

    #[display(fmt = "{}", _0)]
    SignerError(S),

    #[display(fmt = "{}", _0)]
    DecodeError(decode::Error),
}

impl<S: fmt::Debug + fmt::Display> From<KeyError<S>> for Error<S> {
    fn from(e: KeyError<S>) -> Self {
        Error::KeyError(e)
    }
}

impl<S: fmt::Debug + fmt::Display> From<SigningError<S>> for Error<S> {
    fn from(e: SigningError<S>) -> Self {
        Error::SigningError(e)
    }
}

impl<S: fmt::Debug + fmt::Display> From<decode::Error> for Error<S> {
    fn from(e: decode::Error) -> Self {
        Error::DecodeError(e)
    }
}
