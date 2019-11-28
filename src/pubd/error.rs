use std::{fmt, io};

use rpki::uri;

use crate::commons::api::rrdp::VerificationError;
use crate::commons::api::PublisherHandle;
use crate::commons::eventsourcing::AggregateStoreError;
use crate::commons::remote::rfc8181;
use crate::commons::remote::rfc8181::ReportErrorCode;

//------------ Error ---------------------------------------------------------
#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Duplicate publisher '{}'", _0)]
    DuplicatePublisher(PublisherHandle),

    #[display(fmt = "Unknown publisher '{}'", _0)]
    UnknownPublisher(PublisherHandle),

    #[display(fmt = "Publishing uri '{}' outside repository uri '{}'", _0, _1)]
    PublishingOutsideBaseUri(String, String),

    #[display(fmt = "Publisher uri '{}' must have a trailing slash", _0)]
    BaseUriNoDir(String),

    #[display(fmt = "There is no repository enabled in this Krill instance.")]
    NoRepository,

    #[display(fmt = "Could not decode or validate RFC8181 request: {}", _0)]
    Validation(String),

    #[display(fmt = "{}", _0)]
    Rfc8181MessageError(rfc8181::MessageError),

    #[display(fmt = "{}", _0)]
    RrdpVerificationError(VerificationError),

    #[display(fmt = "{}", _0)]
    Store(AggregateStoreError),

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    SignerError(String),
}

impl Error {
    pub fn publishing_outside_jail(uri: &uri::Rsync, jail: &uri::Rsync) -> Self {
        Error::PublishingOutsideBaseUri(uri.to_string(), jail.to_string())
    }

    pub fn signer(e: impl fmt::Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn validation(e: impl fmt::Display) -> Self {
        Error::Validation(e.to_string())
    }

    pub fn to_rfc8181_error_code(&self) -> ReportErrorCode {
        match self {
            Error::Validation(_) | Error::UnknownPublisher(_) => ReportErrorCode::PermissionFailure,
            Error::Rfc8181MessageError(_) => ReportErrorCode::XmlError,
            Error::RrdpVerificationError(e) => match e {
                VerificationError::UriOutsideJail(_, _) => ReportErrorCode::PermissionFailure,
                VerificationError::NoObjectForHashAndOrUri(_) => ReportErrorCode::NoObjectPresent,
                VerificationError::ObjectAlreadyPresent(_) => ReportErrorCode::ObjectAlreadyPresent,
            },
            _ => ReportErrorCode::OtherError,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self {
        Error::Store(e)
    }
}

impl From<rfc8181::MessageError> for Error {
    fn from(e: rfc8181::MessageError) -> Self {
        Error::Rfc8181MessageError(e)
    }
}

impl std::error::Error for Error {}
