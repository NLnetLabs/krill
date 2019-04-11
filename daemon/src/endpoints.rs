//! Process requests received, delegate, and wrap up the responses.
use std::sync::{RwLockReadGuard, RwLockWriteGuard};
use actix_web::{HttpResponse, ResponseError};
use actix_web::http::StatusCode;
use serde::Serialize;
use krill_cms_proxy::api::{ClientInfo, ClientHandle};
use krill_cms_proxy::sigmsg::SignedMessage;
use krill_commons::api::{admin, publication, ErrorResponse, ErrorCode};
use krill_commons::api::admin::PublisherHandle;
use krill_commons::api::rrdp::VerificationError;
use krill_pubd::publishers::PublisherError;
use krill_pubd::repo::RrdpServerError;
use crate::http::server::HttpRequest;
use crate::krillserver::{self, KrillServer};


//------------ Support Functions ---------------------------------------------

/// Returns a server in a read lock
pub fn ro_server(req: &HttpRequest) -> RwLockReadGuard<KrillServer> {
    req.state().read().unwrap()
}

/// Returns a server in a write lock
pub fn rw_server(req: &HttpRequest) -> RwLockWriteGuard<KrillServer> {
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
    let publishers = ro_server(req).publishers();
    render_json(admin::PublisherList::build(&publishers, "/api/v1/publishers"))
}

/// Adds a publisher
#[allow(clippy::needless_pass_by_value)]
pub fn add_publisher(
    req: HttpRequest,
    pbl: admin::PublisherRequest
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

/// Processes an RFC8181 query and returns the appropriate response.
#[allow(clippy::needless_pass_by_value)]
pub fn handle_rfc8181_request(
    req: HttpRequest,
    msg: SignedMessage,
    handle: PublisherHandle
) -> HttpResponse {
    let client_handle = ClientHandle::from(handle.as_ref());
    match ro_server(&req).handle_rfc8181_req(msg, client_handle) {
        Ok(captured) => {
            HttpResponse::build(StatusCode::OK)
                .content_type("application/rpki-publication")
                .body(captured.into_bytes())
        }
        Err(e) => {
            server_error(&Error::ServerError(e))
        }
    }
}

/// Processes a publishdelta request sent to the API.
#[allow(clippy::needless_pass_by_value)]
pub fn handle_delta(
    req: HttpRequest,
    delta: publication::PublishDelta,
    handle: PublisherHandle
) -> HttpResponse {
    match ro_server(&req).handle_delta(delta, &handle) {
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


//------------ Admin: Rfc8181 -----------------------------------------------

pub fn rfc8181_clients(req: &HttpRequest) -> HttpResponse {
    match ro_server(req).rfc8181_clients() {
        Ok(clients) => render_json(clients),
        Err(e) => server_error(&Error::ServerError(e ))
    }
}

pub fn add_rfc8181_client(
    req: HttpRequest,
    client: ClientInfo
) -> HttpResponse {
    let server = ro_server(&req);
    match server.add_rfc8181_client(client) {
        Ok(()) => api_ok(),
        Err(e) => server_error(&Error::ServerError(e))
    }
}

pub fn repository_response(
    req: HttpRequest,
    handle: PublisherHandle
) -> HttpResponse {
    match ro_server(&req).repository_response(&handle) {
        Ok(res) => {
            HttpResponse::Ok()
                .content_type("application/xml")
                .body(res.encode_vec())
        },

        Err(e) => server_error(&Error::ServerError(e))
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
trait ToErrorCode {
    fn code(&self) -> ErrorCode;
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
            krillserver::Error::PubServer(e) => e.status(),
            krillserver::Error::ProxyServer(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ErrorToStatus for krill_pubd::Error {
    fn status(&self) -> StatusCode {
        match self {
            krill_pubd::Error::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            krill_pubd::Error::InvalidBaseUri => StatusCode::BAD_REQUEST,
            krill_pubd::Error::InvalidHandle(_) => StatusCode::BAD_REQUEST,
            krill_pubd::Error::DuplicatePublisher(_) => StatusCode::BAD_REQUEST,
            krill_pubd::Error::UnknownPublisher(_) => StatusCode::FORBIDDEN,
            krill_pubd::Error::ConcurrentModification(_, _) => StatusCode::BAD_REQUEST,
            krill_pubd::Error::PublisherError(e) => e.status(),
            krill_pubd::Error::RrdpServerError(e) => e.status(),
            krill_pubd::Error::AggregateStoreError(_) => StatusCode::INTERNAL_SERVER_ERROR,
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



impl ToErrorCode for Error {
    fn code(&self) -> ErrorCode {
        match self {
            Error::ServerError(e) => e.code(),
            Error::JsonError(_) => ErrorCode::InvalidJson,
            Error::PublisherRequestError => ErrorCode::InvalidPublisherRequest
        }
    }
}

impl ToErrorCode for krillserver::Error {
    fn code(&self) -> ErrorCode {
        match self {
            krillserver::Error::IoError(_) => ErrorCode::Persistence,
            krillserver::Error::PubServer(e) => e.code(),
            krillserver::Error::ProxyServer(_) => ErrorCode::ProxyError
        }
    }
}

impl ToErrorCode for krill_pubd::Error {
    fn code(&self) -> ErrorCode {
        match self {
            krill_pubd::Error::IoError(_) => ErrorCode::Persistence,
            krill_pubd::Error::InvalidBaseUri => ErrorCode::InvalidBaseUri,
            krill_pubd::Error::InvalidHandle(_) => ErrorCode::InvalidHandle,
            krill_pubd::Error::DuplicatePublisher(_) => ErrorCode::DuplicateHandle,
            krill_pubd::Error::UnknownPublisher(_) => ErrorCode::UnknownPublisher,
            krill_pubd::Error::ConcurrentModification(_, _) => ErrorCode::ConcurrentModification,
            krill_pubd::Error::PublisherError(e) => e.code(),
            krill_pubd::Error::RrdpServerError(e) => e.code(),
            krill_pubd::Error::AggregateStoreError(_) => ErrorCode::Persistence,
        }
    }
}

impl ToErrorCode for PublisherError {
    fn code(&self) -> ErrorCode {
        match self {
            PublisherError::Deactivated => ErrorCode::PublisherDeactivated,
            PublisherError::VerificationError(e) => e.code(),
        }
    }
}

impl ToErrorCode for VerificationError {
    fn code(&self) -> ErrorCode {
        match self {
            VerificationError::NoObjectForHashAndOrUri(_) => ErrorCode::NoObjectForHashAndOrUri,
            VerificationError::ObjectAlreadyPresent(_) => ErrorCode::ObjectAlreadyPresent,
            VerificationError::UriOutsideJail(_, _) => ErrorCode::UriOutsideJail
        }
    }
}

impl ToErrorCode for RrdpServerError {
    fn code(&self) -> ErrorCode {
        match self {
            RrdpServerError::IoError(_) => ErrorCode::Persistence
        }
    }
}

impl Error {
    fn to_error_response(&self) -> ErrorResponse {
        self.code().clone().into()
    }
}

impl actix_web::ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status())
            .body(serde_json::to_string(&self.to_error_response()).unwrap())
    }
}