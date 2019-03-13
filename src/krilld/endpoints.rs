//! Process requests received, delegate, and wrap up the responses.
use std::sync::{RwLockReadGuard, RwLockWriteGuard};
use actix_web::{HttpResponse, ResponseError};
use actix_web::http::StatusCode;
use serde::Serialize;
use krill_commons::api::publishers;
use krill_commons::api::publishers::PublisherHandle;
use krill_commons::api::publication;
use krill_commons::eventsourcing::DiskKeyStore;
use crate::krilld::http::server::HttpRequest;
use crate::krilld::krillserver::{self, KrillServer};
use crate::krilld::pubd;
use crate::krilld::pubd::publishers::PublisherError;
use crate::krilld::pubd::repo::RrdpServerError;


//------------ Support Functions ---------------------------------------------

/// Returns a server in a read lock
pub fn ro_server(req: &HttpRequest) -> RwLockReadGuard<KrillServer<DiskKeyStore>> {
    req.state().read().unwrap()
}

/// Returns a server in a write lock
pub fn rw_server(req: &HttpRequest) -> RwLockWriteGuard<KrillServer<DiskKeyStore>> {
    req.state().write().unwrap()
}

/// Helper function to render json output.
fn render_json<O: Serialize>(object: O) -> HttpResponse {
    match serde_json::to_string(&object){
        Ok(enc) => {
            HttpResponse::Ok()
                .content_type("application/json")
                .body(enc)
        },
        Err(e) => server_error(&Error::JsonError(e))
    }
}

/// Helper function to render server side errors. Also responsible for
/// logging the errors.
fn server_error(error: &Error) -> HttpResponse {
    error!("{}", error);
    error.error_response()
}

/// A clean 404 result for the API (no content, not for humans)
fn api_not_found() -> HttpResponse {
    HttpResponse::build(StatusCode::NOT_FOUND).finish()
}

/// A clean 200 result for the API (no content, not for humans)
pub fn api_ok() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// Returns the server health. XXX TODO: do a real test!
pub fn health(_r: &HttpRequest) -> HttpResponse {
    api_ok()
}


//------------ Admin: Publishers ---------------------------------------------

/// Returns a json structure with all publishers in it.
pub fn publishers(req: &HttpRequest) -> HttpResponse {
    match ro_server(req).publishers() {
        Err(e) => server_error(&Error::ServerError(e)),
        Ok(publishers) => {
            render_json(
                publishers::PublisherList::build(
                    &publishers,
                    "/api/v1/publishers"
                )
            )
        }
    }
}

/// Adds a publisher
#[allow(clippy::needless_pass_by_value)]
pub fn add_publisher(
    req: HttpRequest,
    pbl: publishers::PublisherRequest
) -> HttpResponse {
    let mut server = rw_server(&req);
    match server.add_publisher(pbl) {
        Ok(()) => api_ok(),
        Err(e) => server_error(&Error::ServerError(e))
    }
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::needless_pass_by_value)]
pub fn deactivate_publisher(
    req: HttpRequest,
    handle: PublisherHandle
) -> HttpResponse {
    match rw_server(&req).deactivate_publisher(&handle) {
        Ok(()) => api_ok(),
        Err(e) => server_error(&Error::ServerError(e))
    }
}

/// Returns a json structure with publisher details
#[allow(clippy::needless_pass_by_value)]
pub fn publisher_details(
    req: HttpRequest,
    handle: PublisherHandle
) -> HttpResponse {
    let server = ro_server(&req);
    match server.publisher(&handle) {
        Ok(None) => api_not_found(),
        Ok(Some(publisher)) => {
            render_json(
                &publisher.as_api_details()
            )
        },
        Err(e) => server_error(&Error::ServerError(e))
    }
}


//------------ Publication ---------------------------------------------------

/// Processes a publishdelta request sent to the API.
#[allow(clippy::needless_pass_by_value)]
pub fn handle_delta(
    req: HttpRequest,
    delta: publication::PublishDelta,
    handle: PublisherHandle
) -> HttpResponse {
    match rw_server(&req).handle_delta(delta, &handle) {
        Ok(()) => api_ok(),
        Err(e) => server_error(&Error::ServerError(e))
    }
}

/// Processes a list request sent to the API.
#[allow(clippy::needless_pass_by_value)]
pub fn handle_list(
    req: HttpRequest,
    handle: PublisherHandle
) -> HttpResponse {
    match ro_server(&req).handle_list(&handle) {
        Ok(list) => render_json(list),
        Err(e)   => server_error(&Error::ServerError(e))
    }
}


//------------ Serving RRDP --------------------------------------------------

pub fn current_snapshot_json(req: &HttpRequest) -> HttpResponse {
    let _server = ro_server(req);
    unimplemented!()
}




//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    ServerError(krillserver::Error),

    #[display(fmt = "{}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Invalid publisher request")]
    PublisherRequestError
}

/// Translate an error to an HTTP Status Code
trait ErrorToStatus {
    fn status(&self) -> StatusCode;
}

/// Translate an error to an error code to include in a json response.
trait ErrorToCode {
    fn code(&self) -> usize;
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        "Error happened"
    }
}

impl ErrorToStatus for Error {
    fn status(&self) -> StatusCode {
        match self {
            Error::ServerError(e) => e.status(),
            Error::JsonError(_) => StatusCode::BAD_REQUEST,
            Error::PublisherRequestError => StatusCode::BAD_REQUEST
        }
    }
}

impl ErrorToStatus for krillserver::Error {
    fn status(&self) -> StatusCode {
        match self {
            krillserver::Error::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            krillserver::Error::PubServer(e) => e.status()
        }
    }
}

impl ErrorToStatus for pubd::Error {
    fn status(&self) -> StatusCode {
        match self {
            pubd::Error::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            pubd::Error::InvalidBaseUri => StatusCode::BAD_REQUEST,
            pubd::Error::InvalidHandle(_) => StatusCode::BAD_REQUEST,
            pubd::Error::ReservedName(_) => StatusCode::BAD_REQUEST,
            pubd::Error::DuplicatePublisher(_) => StatusCode::BAD_REQUEST,
            pubd::Error::UnknownPublisher(_) => StatusCode::FORBIDDEN,
            pubd::Error::ConcurrentModification(_, _) => StatusCode::BAD_REQUEST,
            pubd::Error::PublisherError(e) => e.status(),
            pubd::Error::RrdpServerError(e) => e.status(),
            pubd::Error::KeyStoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

}

impl ErrorToStatus for PublisherError {
    fn status(&self) -> StatusCode {
        match self {
            PublisherError::Deactivated => StatusCode::FORBIDDEN,
            PublisherError::VerificationError(_) => StatusCode::FORBIDDEN,
        }
    }
}

impl ErrorToStatus for RrdpServerError {
    fn status(&self) -> StatusCode {
        match self {
            RrdpServerError::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}



impl ErrorToCode for Error {
    fn code(&self) -> usize {
        match self {
            Error::ServerError(e) => e.code(),
            Error::JsonError(_) => 1001,
            Error::PublisherRequestError => 1002
        }
    }
}

impl ErrorToCode for krillserver::Error {
    fn code(&self) -> usize {
        match self {
            krillserver::Error::IoError(_) => 3001,
            krillserver::Error::PubServer(e) => e.code()
        }
    }
}

impl ErrorToCode for pubd::Error {
    fn code(&self) -> usize {
        match self {
            pubd::Error::IoError(_) => 3001,
            pubd::Error::InvalidBaseUri => 2002,
            pubd::Error::InvalidHandle(_) => 1004,
            pubd::Error::ReservedName(_) => 1007,
            pubd::Error::DuplicatePublisher(_) => 1005,
            pubd::Error::UnknownPublisher(_) => 1006,
            pubd::Error::ConcurrentModification(_, _) => 2003,
            pubd::Error::PublisherError(e) => e.code(),
            pubd::Error::RrdpServerError(e) => e.code(),
            pubd::Error::KeyStoreError(_) => 3001,
        }
    }
}

impl ErrorToCode for PublisherError {
    fn code(&self) -> usize {
        match self {
            PublisherError::Deactivated => 2004,
            PublisherError::VerificationError(_) => 2005,
        }
    }
}

impl ErrorToCode for RrdpServerError {
    fn code(&self) -> usize {
        match self {
            RrdpServerError::IoError(_) => 3001
        }
    }
}



#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: usize,
    msg: String
}

impl Error {
    fn to_error_response(&self) -> ErrorResponse {
        ErrorResponse {
            code: self.code(),
            msg: format!("{}", self)
        }
    }
}

impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status())
            .body(serde_json::to_string(&self.to_error_response()).unwrap())
    }
}