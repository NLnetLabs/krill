//! Dispatch error handling.

use crate::commons::error::{Error, FatalError};
use super::super::response::HttpResponse;


//------------ DispatchError -------------------------------------------------

/// An error occured during dispatch.
///
/// This error type exists so you can use the question mark operator for all
/// sorts of things during dispatch to minimize clutter.
///
/// The error can either be a response sent back to the client or a fatal
/// error ending the server. Various `From<_>` impls are provided to correctly
/// translate errors into one of the two cases.
#[derive(Debug)]
pub enum DispatchError {
    /// A response should be sent to the client.
    Response(HttpResponse),

    /// A fatal error happened that should terminate the server.
    #[allow(dead_code)]
    Fatal(FatalError),
}

impl From<HttpResponse> for DispatchError {
    fn from(src: HttpResponse) -> Self {
        Self::Response(src)
    }
}

impl From<Error> for DispatchError {
    fn from(src: Error) -> Self {
        Self::Response(HttpResponse::response_from_error(src))
    }
}

