//! Process requests received, delegate, and wrap up the responses.
use actix_web::http::StatusCode;
use actix_web::web::{self, Json, Path};
use actix_web::{HttpResponse, ResponseError};
use bytes::Bytes;
use serde::Serialize;

use krill_commons::api::admin::{AddChildRequest, AddParentRequest, CertAuthInit, Handle};
use krill_commons::api::rrdp::VerificationError;
use krill_commons::api::{admin, publication, ErrorCode, ErrorResponse, IssuanceRequest};
use krill_commons::remote::api::ClientInfo;
use krill_commons::remote::rfc6492;
use krill_commons::remote::sigmsg::SignedMessage;
use krill_commons::util::softsigner::OpenSslSigner;
use krill_pubd::publishers::PublisherError;
use krill_pubd::repo::RrdpServerError;

use crate::auth::Auth;
use crate::ca;
use crate::ca::ParentHandle;
use crate::http::server::AppServer;
use crate::krillserver;

const NOT_FOUND: &[u8] = include_bytes!("../ui/dist/404.html");

//------------ Support Functions ---------------------------------------------

/// Helper function to render json output.
///
/// XXX TODO: Use actix Json<> when returning values
fn render_json<O: Serialize>(object: O) -> HttpResponse {
    match serde_json::to_string(&object) {
        Ok(enc) => HttpResponse::Ok()
            .content_type("application/json")
            .body(enc),
        Err(e) => server_error(&Error::JsonError(e)),
    }
}

/// Helper function to render server side errors. Also responsible for
/// logging the errors.
fn server_error(error: &Error) -> HttpResponse {
    error!("{}", error);
    error.error_response()
}

fn render_empty_res(res: Result<(), krillserver::Error>) -> HttpResponse {
    match res {
        Ok(()) => api_ok(),
        Err(e) => server_error(&Error::ServerError(e)),
    }
}

/// A clean 404 result for the API (no content, not for humans)
fn api_not_found() -> HttpResponse {
    HttpResponse::build(StatusCode::NOT_FOUND).finish()
}

pub fn not_found() -> HttpResponse {
    HttpResponse::build(StatusCode::NOT_FOUND).body(NOT_FOUND)
}

/// A clean 200 result for the API (no content, not for humans)
pub fn api_ok() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// Returns the server health.
pub fn health() -> HttpResponse {
    api_ok()
}

/// Returns the server health.
pub fn api_health(_auth: Auth) -> HttpResponse {
    api_ok()
}

fn if_allowed<F>(allowed: bool, op: F) -> HttpResponse
where
    F: FnOnce() -> HttpResponse,
{
    if allowed {
        op()
    } else {
        HttpResponse::Forbidden().finish()
    }
}

fn if_api_allowed<F>(server: &web::Data<AppServer>, auth: &Auth, op: F) -> HttpResponse
where
    F: FnOnce() -> HttpResponse,
{
    let allowed = server.read().is_api_allowed(auth);
    if_allowed(allowed, op)
}

fn if_publication_allowed<F>(
    server: &web::Data<AppServer>,
    handle: &Handle,
    auth: &Auth,
    op: F,
) -> HttpResponse
where
    F: FnOnce() -> HttpResponse,
{
    let allowed = server.read().is_publication_api_allowed(handle, auth);
    if_allowed(allowed, op)
}

//------------ Admin: Publishers ---------------------------------------------

/// Returns a json structure with all publishers in it.
pub fn publishers(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    let publishers = server.read().publishers();

    if_api_allowed(&server, &auth, || {
        render_json(admin::PublisherList::build(
            &publishers,
            "/api/v1/publishers",
        ))
    })
}

/// Adds a publisher
#[allow(clippy::needless_pass_by_value)]
pub fn add_publisher(
    server: web::Data<AppServer>,
    auth: Auth,
    pbl: Json<admin::PublisherRequest>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().add_publisher(pbl.into_inner()))
    })
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::needless_pass_by_value)]
pub fn deactivate_publisher(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().deactivate_publisher(&handle))
    })
}

/// Returns a json structure with publisher details
#[allow(clippy::needless_pass_by_value)]
pub fn publisher_details(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || match server.read().publisher(&handle) {
        Ok(None) => api_not_found(),
        Ok(Some(publisher)) => render_json(&publisher.as_api_details()),
        Err(e) => server_error(&Error::ServerError(e)),
    })
}

//------------ Publication ---------------------------------------------------

/// Processes an RFC8181 query and returns the appropriate response.
#[allow(clippy::needless_pass_by_value)]
pub fn rfc8181(
    server: web::Data<AppServer>,
    handle: Path<Handle>,
    msg_bytes: Bytes,
) -> HttpResponse {
    match SignedMessage::decode(msg_bytes, true) {
        Ok(msg) => match server.read().handle_rfc8181_req(msg, handle.into_inner()) {
            Ok(captured) => HttpResponse::build(StatusCode::OK)
                .content_type("application/rpki-publication")
                .body(captured.into_bytes()),
            Err(e) => server_error(&Error::ServerError(e)),
        },
        Err(_) => server_error(&Error::CmsError),
    }
}

/// Processes a publishdelta request sent to the API.
#[allow(clippy::needless_pass_by_value)]
pub fn handle_delta(
    server: web::Data<AppServer>,
    auth: Auth,
    delta: Json<publication::PublishDelta>,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    let delta = delta.into_inner();
    debug!("Received delta request for {}", &handle);
    if_publication_allowed(&server, &handle, &auth, || {
        render_empty_res(server.read().handle_delta(delta, &handle))
    })
}

/// Processes a list request sent to the API.
#[allow(clippy::needless_pass_by_value)]
pub fn handle_list(server: web::Data<AppServer>, auth: Auth, handle: Path<Handle>) -> HttpResponse {
    let handle = handle.into_inner();
    debug!("Received list request for {}", &handle);
    if_publication_allowed(&server, &handle, &auth, || {
        match server.read().handle_list(&handle) {
            Ok(list) => render_json(list),
            Err(e) => server_error(&Error::ServerError(e)),
        }
    })
}

//------------ Admin: Rfc8181 -----------------------------------------------

pub fn rfc8181_clients(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || match server.read().rfc8181_clients() {
        Ok(clients) => render_json(clients),
        Err(e) => server_error(&Error::ServerError(e)),
    })
}

pub fn add_rfc8181_client(
    server: web::Data<AppServer>,
    auth: Auth,
    client: Json<ClientInfo>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().add_rfc8181_client(client.into_inner()))
    })
}

pub fn repository_response(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_publication_allowed(&server, &handle, &auth, || {
        match server.read().repository_response(&handle) {
            Ok(res) => HttpResponse::Ok()
                .content_type("application/xml")
                .body(res.encode_vec()),

            Err(e) => server_error(&Error::ServerError(e)),
        }
    })
}

//------------ Admin: TrustAnchor --------------------------------------------

pub fn ta_info(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || match server.read().ta_info() {
        Some(ta) => render_json(ta),
        None => api_not_found(),
    })
}

pub fn ta_init(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().ta_init())
    })
}

pub fn republish_all(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().republish_all())
    })
}

pub fn tal(server: web::Data<AppServer>) -> HttpResponse {
    match server.read().ta_info() {
        Some(ta) => HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("{}", ta.tal())),
        None => api_not_found(),
    }
}

pub fn ta_cer(server: web::Data<AppServer>) -> HttpResponse {
    match server.read().trust_anchor_cert() {
        Some(cert) => HttpResponse::Ok().body(cert.der_encoded().to_vec()),
        None => api_not_found(),
    }
}

pub fn ta_add_child(
    server: web::Data<AppServer>,
    req: Json<AddChildRequest>,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ta_add_child(req.into_inner()) {
            Ok(info) => render_json(info),
            Err(e) => server_error(&Error::ServerError(e)),
        }
    })
}

//------------ Admin: CertAuth -----------------------------------------------

pub fn cas(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || render_json(server.read().cas()))
}

pub fn ca_init(
    server: web::Data<AppServer>,
    auth: Auth,
    ca_init: Json<CertAuthInit>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().ca_init(ca_init.into_inner()))
    })
}

pub fn ca_info(server: web::Data<AppServer>, auth: Auth, handle: Path<Handle>) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_info(&handle.into_inner()) {
            Some(info) => render_json(info),
            None => api_not_found(),
        }
    })
}

pub fn ca_child_req(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || {
        match server.read().ca_child_req(&handle) {
            Some(req) => HttpResponse::Ok()
                .content_type("application/xml")
                .body(req.encode_vec()),
            None => api_not_found(),
        }
    })
}

pub fn ca_add_parent(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
    parent: Json<AddParentRequest>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(
            server
                .read()
                .ca_add_parent(handle.into_inner(), parent.into_inner()),
        )
    })
}

//------------ Provisioning (RFC6492) ----------------------------------------

/// Lists the child entitlements.
///
/// See: https://tools.ietf.org/html/rfc6492#section-3.3.2
pub fn list(
    server: web::Data<AppServer>,
    auth: Auth,
    parent: Path<Handle>,
    child: Path<Handle>,
) -> HttpResponse {
    match server
        .read()
        .list(&parent.into_inner(), &child.into_inner(), auth)
    {
        Ok(entitlements) => render_json(entitlements),
        Err(e) => server_error(&Error::ServerError(e)),
    }
}

/// Issue a Certificate in response to a Certificate Issuance request
///
/// See: https://tools.ietf.org/html/rfc6492#section3.4.1-2
pub fn issue(
    server: web::Data<AppServer>,
    auth: Auth,
    parent: Path<Handle>,
    child: Path<Handle>,
    issue_req: Json<IssuanceRequest>,
) -> HttpResponse {
    match server.read().issue(
        &parent.into_inner(),
        &child.into_inner(),
        issue_req.into_inner(),
        auth,
    ) {
        Ok(issued) => render_json(issued),
        Err(e) => server_error(&Error::ServerError(e)),
    }
}

/// Process an RFC 6492 request
///
pub fn rfc6492(
    server: web::Data<AppServer>,
    parent: Path<ParentHandle>,
    msg_bytes: Bytes,
) -> HttpResponse {
    match SignedMessage::decode(msg_bytes, false) {
        Ok(msg) => match server.read().rfc6492(parent.into_inner(), msg) {
            Ok(bytes) => HttpResponse::build(StatusCode::OK)
                .content_type(rfc6492::CONTENT_TYPE)
                .body(bytes),
            Err(e) => {
                error!("Error processing RFC6492 req: {}", e);
                server_error(&Error::ServerError(e))
            }
        },
        Err(e) => {
            error!("Error processing RFC6492 req: {}", e);
            server_error(&Error::CmsError)
        }
    }
}

//------------ Serving RRDP --------------------------------------------------

pub fn current_snapshot_json(_server: web::Data<AppServer>) -> HttpResponse {
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

    #[display(fmt = "Could not decode protocol CMS")]
    CmsError,

    #[display(fmt = "Invalid publisher request")]
    PublisherRequestError,
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
            Error::CmsError => StatusCode::BAD_REQUEST,
            Error::PublisherRequestError => StatusCode::BAD_REQUEST,
        }
    }
}

impl ErrorToStatus for krillserver::Error {
    fn status(&self) -> StatusCode {
        match self {
            krillserver::Error::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            krillserver::Error::PubServer(e) => e.status(),
            krillserver::Error::ProxyServer(_) => StatusCode::INTERNAL_SERVER_ERROR,
            krillserver::Error::SignerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            krillserver::Error::CaServerError(e) => e.status(),
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

impl ErrorToStatus for ca::ServerError<OpenSslSigner> {
    fn status(&self) -> StatusCode {
        match self {
            ca::ServerError::CertAuth(e) => e.status(),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ErrorToStatus for ca::Error {
    fn status(&self) -> StatusCode {
        match self {
            ca::Error::Unauthorized(_) => StatusCode::FORBIDDEN,
            ca::Error::SignerError(_) | ca::Error::KeyStatusChange(_, _) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl ToErrorCode for Error {
    fn code(&self) -> ErrorCode {
        match self {
            Error::ServerError(e) => e.code(),
            Error::JsonError(_) => ErrorCode::InvalidJson,
            Error::CmsError => ErrorCode::InvalidCms,
            Error::PublisherRequestError => ErrorCode::InvalidPublisherRequest,
        }
    }
}

impl ToErrorCode for krillserver::Error {
    fn code(&self) -> ErrorCode {
        match self {
            krillserver::Error::IoError(_) => ErrorCode::Persistence,
            krillserver::Error::PubServer(e) => e.code(),
            krillserver::Error::ProxyServer(_) => ErrorCode::ProxyError,
            krillserver::Error::SignerError(_) => ErrorCode::SigningError,
            krillserver::Error::CaServerError(e) => e.code(),
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
            VerificationError::UriOutsideJail(_, _) => ErrorCode::UriOutsideJail,
        }
    }
}

impl ToErrorCode for RrdpServerError {
    fn code(&self) -> ErrorCode {
        match self {
            RrdpServerError::IoError(_) => ErrorCode::Persistence,
        }
    }
}

impl ToErrorCode for ca::ServerError<OpenSslSigner> {
    fn code(&self) -> ErrorCode {
        match self {
            ca::ServerError::CertAuth(e) => e.code(),
            _ => ErrorCode::CaServerError,
        }
    }
}

impl ToErrorCode for ca::Error {
    fn code(&self) -> ErrorCode {
        match self {
            ca::Error::DuplicateChild(_) => ErrorCode::DuplicateChild,
            ca::Error::MustHaveResources => ErrorCode::ChildNeedsResources,
            ca::Error::MissingResources => ErrorCode::ChildOverclaims,
            _ => ErrorCode::CaServerError,
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
