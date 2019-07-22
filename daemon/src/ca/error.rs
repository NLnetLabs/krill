use std::fmt::Display;

use krill_commons::api::admin::{Handle};
use krill_commons::api::ca::{KeyRef};
use krill_commons::eventsourcing::{AggregateStoreError};
use krill_commons::remote::rfc6492;

use crate::ca::signing::{Signer};
use ca::{KeyStatus};
use std::{io, fmt};
use krill_commons::util::httpclient;

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Functionality not supported for TA.")]
    NotAllowedForTa,

    #[display(fmt = "Duplicate parent added: {}", _0)]
    DuplicateParent(Handle),

    #[display(fmt = "Got response for unknown parent: {}", _0)]
    UnknownParent(Handle),

    #[display(fmt = "Got response for unknown resource class: {}", _0)]
    UnknownResourceClass(String),

    // Child related errors
    #[display(fmt = "Name reserved for embedded TA.")]
    NameReservedTa,

    #[display(fmt = "Not allowed for non-TA CA.")]
    NotTa,

    #[display(fmt = "Child {} already exists.", _0)]
    DuplicateChild(Handle),

    #[display(fmt = "Unknown child {}.", _0)]
    UnknownChild(Handle),

    #[display(fmt = "Unauthorized child {}", _0)]
    Unauthorized(Handle),

    #[display(fmt = "Not all child resources are held by TA")]
    MissingResources,

    #[display(fmt = "No matching resource class")]
    MissingResourceClass,

    #[display(fmt = "Child CA MUST have resources.")]
    MustHaveResources,

    #[display(fmt = "No issued cert matching pub key in resource class.")]
    NoIssuedCert,

    #[display(fmt = "Invalid CSR for child {}: {}.", _0, _1)]
    InvalidCsr(Handle, String),

    #[display(fmt = "No key held by CA matching issued certificate: {}", _0)]
    NoKeyMatch(KeyRef),

    #[display(fmt = "Signing issue: {}", _0)]
    SignerError(String),

    #[display(fmt = "Key cannot change from status {} to {}", _0, _1)]
    KeyStatusChange(KeyStatus, KeyStatus),

    #[display(fmt = "{}", _0)]
    Rfc6492(rfc6492::Error),

    #[display(fmt = "Invalidly signed RFC 6492 CMS.")]
    InvalidRfc6492,
}

impl From<rfc6492::Error> for Error {
    fn from(e: rfc6492::Error) -> Self {
        Error::Rfc6492(e)
    }
}

impl Error {
    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn invalid_csr(handle: &Handle, msg: &str) -> Self {
        Error::InvalidCsr(handle.clone(), msg.to_string())
    }

}

impl std::error::Error for Error {}



//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum ServerError<S: Signer> {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "TrustAnchor was already initialised")]
    TrustAnchorInitialisedError,

    #[display(fmt = "TrustAnchor was not initialised")]
    TrustAnchorNotInitialisedError,

    #[display(fmt = "{}", _0)]
    CertAuth(Error),

    #[display(fmt = "CA {} was already initialised", _0)]
    DuplicateCa(String),

    #[display(fmt = "CA {} is unknown", _0)]
    UnknownCa(String),

    #[display(fmt = "{}", _0)]
    SignerError(S::Error),

    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),

    #[display(fmt = "{}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt = "{}", _0)]
    Custom(String),
}

impl<S: Signer> ServerError<S> {
    pub fn custom(e: impl fmt::Display) -> Self {
        ServerError::Custom(e.to_string())
    }
}

impl<S: Signer> From<io::Error> for ServerError<S> {
    fn from(e: io::Error) -> Self { ServerError::IoError(e) }
}

impl<S: Signer> From<Error> for ServerError<S> {
    fn from(e: Error) -> Self { ServerError::CertAuth(e) }
}

impl<S: Signer> From<AggregateStoreError> for ServerError<S> {
    fn from(e: AggregateStoreError) -> Self { ServerError::AggregateStoreError(e) }
}