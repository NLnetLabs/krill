//! Process requests received, delegate, and wrap up the responses.
use actix_web::http::StatusCode;
use actix_web::web::{self, Json, Path};
use actix_web::{HttpResponse, ResponseError};
use bytes::Bytes;
use serde::Serialize;

use rpki::x509::Time;

use crate::commons::api::rrdp::VerificationError;
use crate::commons::api::{
    AddChildRequest, CertAuthInit, ErrorCode, ErrorResponse, Handle, ParentCaContact, ParentCaReq,
    ParentHandle, PublisherHandle, PublisherList, RepositoryUpdate, RoaDefinitionUpdates,
    UpdateChildRequest,
};
use crate::commons::remote::{rfc6492, rfc8181, rfc8183};
use crate::daemon::auth::Auth;
use crate::daemon::ca;
use crate::daemon::http::server::AppServer;
use crate::daemon::krillserver;
use crate::pubd;

//------------ Support Functions ---------------------------------------------

/// Helper function to render json output.
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

fn render_json_res<O: Serialize>(res: Result<O, krillserver::Error>) -> HttpResponse {
    match res {
        Ok(o) => render_json(o),
        Err(e) => server_error(&Error::ServerError(e)),
    }
}

/// A clean 404 result for the API (no content, not for humans)
fn api_not_found() -> HttpResponse {
    let code = ErrorCode::UnknownResource;
    let res: ErrorResponse = code.into();
    let msg = serde_json::to_string(&res).unwrap();
    let status = StatusCode::NOT_FOUND;
    HttpResponse::build(status).body(msg)
}

pub fn api_bad_request() -> HttpResponse {
    let code = ErrorCode::UnknownMethod;
    let res: ErrorResponse = code.into();
    let msg = serde_json::to_string(&res).unwrap();
    let status = StatusCode::BAD_REQUEST;
    HttpResponse::build(status).body(msg)
}

pub fn not_found() -> HttpResponse {
    HttpResponse::build(StatusCode::NOT_FOUND).body("NOT_FOUND")
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
pub fn api_authorized(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, api_ok)
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

/// Produce prometheus style metrics
pub fn metrics(server: web::Data<AppServer>) -> HttpResponse {
    let mut res = String::new();
    if let Ok(stats) = server.read().repo_stats() {
        let publishers = stats.get_publishers();

        res.push_str("# HELP krill_repo_publisher number of publishers in repository\n");
        res.push_str("# TYPE krill_repo_publisher gauge\n");
        res.push_str(&format!("krill_repo_publisher {}\n", publishers.len()));

        if let Some(last_update) = stats.last_update() {
            let seconds = Time::now().timestamp() - last_update.timestamp();
            res.push_str("\n");
            res.push_str(
                "# HELP krill_repo_rrdp_last_update seconds since last update by any publisher\n",
            );
            res.push_str("# TYPE krill_repo_rrdp_last_update gauge\n");
            res.push_str(&format!("krill_repo_rrdp_last_update {}\n", seconds));
        }

        res.push_str("\n");
        res.push_str("# HELP krill_repo_rrdp_serial RRDP serial\n");
        res.push_str("# TYPE krill_repo_rrdp_serial gauge\n");
        res.push_str(&format!("krill_repo_rrdp_serial {}\n", stats.serial()));

        res.push_str("\n");
        res.push_str("# HELP krill_repo_rrdp_session RRDP session ID\n");
        res.push_str("# TYPE krill_repo_rrdp_session gauge\n");
        res.push_str(&format!("krill_repo_rrdp_session {}\n", stats.session()));

        res.push_str("\n");
        res.push_str("# HELP krill_repo_objects number of objects in repository for publisher\n");
        res.push_str("# TYPE krill_repo_objects gauge\n");
        for (publisher, stats) in publishers {
            res.push_str(&format!(
                "krill_repo_objects{{publisher=\"{}\"}} {}\n",
                publisher,
                stats.objects()
            ));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_repo_size size of objects in bytes in repository for publisher\n",
        );
        res.push_str("# TYPE krill_repo_size gauge\n");
        for (publisher, stats) in publishers {
            res.push_str(&format!(
                "krill_repo_size{{publisher=\"{}\"}} {}\n",
                publisher,
                stats.size()
            ));
        }

        res.push_str("\n");
        res.push_str("# HELP krill_repo_last_update seconds since last update for publisher\n");
        res.push_str("# TYPE krill_repo_last_update gauge\n");
        for (publisher, stats) in publishers {
            if let Some(last_update) = stats.last_update() {
                let seconds = Time::now().timestamp() - last_update.timestamp();
                res.push_str(&format!(
                    "krill_repo_last_update{{publisher=\"{}\"}} {}\n",
                    publisher, seconds
                ));
            }
        }
    }

    HttpResponse::Ok().body(res)
}

//------------ Admin: Publishers ---------------------------------------------

pub fn repo_stats(server: web::Data<AppServer>) -> HttpResponse {
    render_json_res(server.read().repo_stats())
}

/// Returns a json structure with all publishers in it.
pub fn list_pbl(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(
            server
                .read()
                .publishers()
                .map(|publishers| PublisherList::build(&publishers, "/api/v1/publishers")),
        )
    })
}

/// Adds a publisher
pub fn add_pbl(
    server: web::Data<AppServer>,
    auth: Auth,
    pbl: Json<rfc8183::PublisherRequest>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.write().add_publisher(pbl.into_inner()))
    })
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::needless_pass_by_value)]
pub fn remove_pbl(
    server: web::Data<AppServer>,
    auth: Auth,
    publisher: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().remove_publisher(publisher.into_inner()))
    })
}

/// Returns a json structure with publisher details
#[allow(clippy::needless_pass_by_value)]
pub fn show_pbl(server: web::Data<AppServer>, auth: Auth, publisher: Path<Handle>) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().get_publisher(&publisher.into_inner()))
    })
}

//------------ Publication ---------------------------------------------------

/// Processes an RFC8181 query and returns the appropriate response.
pub fn rfc8181(
    server: web::Data<AppServer>,
    publisher: Path<PublisherHandle>,
    msg_bytes: Bytes,
) -> HttpResponse {
    match server.read().rfc8181(publisher.into_inner(), msg_bytes) {
        Ok(bytes) => HttpResponse::build(StatusCode::OK)
            .content_type(rfc8181::CONTENT_TYPE)
            .body(bytes),
        Err(e) => {
            error!("Error processing RFC8181 req: {}", e);
            server_error(&Error::ServerError(e))
        }
    }
}

//------------ repository_response ---------------------------------------------

pub fn repository_response_xml(
    server: web::Data<AppServer>,
    auth: Auth,
    publisher: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match repository_response(&server, &publisher.into_inner()) {
            Ok(res) => HttpResponse::Ok()
                .content_type("application/xml")
                .body(res.encode_vec()),

            Err(e) => server_error(&e),
        }
    })
}

pub fn repository_response_json(
    server: web::Data<AppServer>,
    auth: Auth,
    publisher: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match repository_response(&server, &publisher.into_inner()) {
            Ok(res) => render_json(res),
            Err(e) => server_error(&e),
        }
    })
}

fn repository_response(
    server: &web::Data<AppServer>,
    publisher: &Handle,
) -> Result<rfc8183::RepositoryResponse, Error> {
    server
        .read()
        .repository_response(publisher)
        .map_err(Error::ServerError)
}

//------------ Admin: TrustAnchor --------------------------------------------

pub fn tal(server: web::Data<AppServer>) -> HttpResponse {
    match server.read().ta() {
        Ok(ta) => HttpResponse::Ok()
            .content_type("text/plain")
            .body(format!("{}", ta.tal())),
        Err(_) => api_not_found(),
    }
}

pub fn ta_cer(server: web::Data<AppServer>) -> HttpResponse {
    match server.read().trust_anchor_cert() {
        Some(cert) => HttpResponse::Ok().body(cert.to_captured().to_vec()),
        None => api_not_found(),
    }
}

pub fn ca_add_child(
    server: web::Data<AppServer>,
    parent: Path<ParentHandle>,
    req: Json<AddChildRequest>,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(
            server
                .read()
                .ca_add_child(&parent.into_inner(), req.into_inner()),
        )
    })
}

pub fn ca_child_update(
    server: web::Data<AppServer>,
    ca_and_child: Path<(Handle, Handle)>,
    req: Json<UpdateChildRequest>,
    auth: Auth,
) -> HttpResponse {
    let ca_and_child = ca_and_child.into_inner();
    let ca = ca_and_child.0;
    let child = ca_and_child.1;

    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_child_update(&ca, child, req.into_inner()))
    })
}

pub fn ca_child_remove(
    server: web::Data<AppServer>,
    ca_and_child: Path<(Handle, Handle)>,
    auth: Auth,
) -> HttpResponse {
    let ca_and_child = ca_and_child.into_inner();
    let ca = ca_and_child.0;
    let child = ca_and_child.1;

    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_child_remove(&ca, child))
    })
}

pub fn ca_show_child(
    server: web::Data<AppServer>,
    ca_and_child: Path<(Handle, Handle)>,
    auth: Auth,
) -> HttpResponse {
    let ca_and_child = ca_and_child.into_inner();
    let ca = ca_and_child.0;
    let child = ca_and_child.1;

    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_show_child(&ca, &child))
    })
}

pub fn ca_parent_contact(
    server: web::Data<AppServer>,
    ca_and_child: Path<(Handle, Handle)>,
    auth: Auth,
) -> HttpResponse {
    let ca_and_child = ca_and_child.into_inner();
    let ca = ca_and_child.0;
    let child = ca_and_child.1;

    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_parent_contact(&ca, child.clone()))
    })
}

pub fn ca_parent_res_json(
    server: web::Data<AppServer>,
    ca_and_child: Path<(Handle, Handle)>,
    auth: Auth,
) -> HttpResponse {
    let ca_and_child = ca_and_child.into_inner();
    let ca = ca_and_child.0;
    let child = ca_and_child.1;

    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_parent_response(&ca, child.clone()))
    })
}

pub fn ca_parent_res_xml(
    server: web::Data<AppServer>,
    ca_and_child: Path<(Handle, Handle)>,
    auth: Auth,
) -> HttpResponse {
    let ca_and_child = ca_and_child.into_inner();
    let ca = ca_and_child.0;
    let child = ca_and_child.1;

    if_api_allowed(&server, &auth, || {
        match server.read().ca_parent_response(&ca, child.clone()) {
            Ok(res) => HttpResponse::Ok()
                .content_type("application/xml")
                .body(res.encode_vec()),

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

pub fn ca_regenerate_id(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_update_id(handle.into_inner()))
    })
}

pub fn ca_info(server: web::Data<AppServer>, auth: Auth, handle: Path<Handle>) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_info(&handle.into_inner()))
    })
}

pub fn ca_my_parent_contact(
    server: web::Data<AppServer>,
    auth: Auth,
    ca_and_parent: Path<(Handle, Handle)>,
) -> HttpResponse {
    let (ca, parent) = ca_and_parent.into_inner();
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_my_parent_contact(&ca, &parent))
    })
}

pub fn ca_history(server: web::Data<AppServer>, auth: Auth, handle: Path<Handle>) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_history(&handle.into_inner()) {
            Some(history) => render_json(history),
            None => api_not_found(),
        }
    })
}

pub fn ca_child_req_xml(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || match ca_child_req(&server, &handle) {
        Ok(req) => HttpResponse::Ok()
            .content_type("application/xml")
            .body(req.encode_vec()),
        Err(e) => server_error(&e),
    })
}

pub fn ca_child_req_json(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || match ca_child_req(&server, &handle) {
        Ok(req) => render_json(req),
        Err(e) => server_error(&e),
    })
}

fn ca_child_req(
    server: &web::Data<AppServer>,
    handle: &Handle,
) -> Result<rfc8183::ChildRequest, Error> {
    server
        .read()
        .ca_child_req(handle)
        .map_err(Error::ServerError)
}

pub fn ca_publisher_req_json(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || {
        match server.read().ca_publisher_req(&handle) {
            Some(req) => render_json(req),
            None => api_not_found(),
        }
    })
}

pub fn ca_publisher_req_xml(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || {
        match server.read().ca_publisher_req(&handle) {
            Some(req) => HttpResponse::Ok()
                .content_type("application/xml")
                .body(req.encode_vec()),
            None => api_not_found(),
        }
    })
}

pub fn ca_repo_details(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_repo_details(&handle))
    })
}

pub fn ca_repo_state(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_repo_state(&handle))
    })
}

pub fn ca_repo_update(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
    update: Json<RepositoryUpdate>,
) -> HttpResponse {
    let handle = handle.into_inner();
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_update_repo(handle, update.into_inner()))
    })
}

pub fn ca_add_parent(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
    parent: Json<ParentCaReq>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(
            server
                .read()
                .ca_parent_add(handle.into_inner(), parent.into_inner()),
        )
    })
}

pub fn ca_update_parent(
    server: web::Data<AppServer>,
    auth: Auth,
    ca_and_parent: Path<(Handle, Handle)>,
    contact: Json<ParentCaContact>,
) -> HttpResponse {
    let (ca, parent) = ca_and_parent.into_inner();
    if_api_allowed(&server, &auth, || {
        render_empty_res(
            server
                .read()
                .ca_parent_update(ca, parent, contact.into_inner()),
        )
    })
}

pub fn ca_remove_parent(
    server: web::Data<AppServer>,
    auth: Auth,
    ca_and_parent: Path<(Handle, Handle)>,
) -> HttpResponse {
    let (ca, parent) = ca_and_parent.into_inner();
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_remove(ca, parent))
    })
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
pub fn ca_kr_init(server: web::Data<AppServer>, auth: Auth, handle: Path<Handle>) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_keyroll_init(handle.into_inner()))
    })
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
pub fn ca_kr_activate(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_keyroll_activate(handle.into_inner()))
    })
}

//------------ Admin: Force republish ----------------------------------------

/// Update the route authorizations for this CA
pub fn ca_routes_update(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
    updates: Json<RoaDefinitionUpdates>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(
            server
                .read()
                .ca_routes_update(handle.into_inner(), updates.into_inner()),
        )
    })
}

/// show the route authorizations for this CA
pub fn ca_routes_show(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        let handle = handle.into_inner();
        match server.read().ca_routes_show(&handle) {
            Ok(roas) => render_json(roas),
            Err(_) => api_not_found(),
        }
    })
}

//------------ Admin: Force republish ----------------------------------------

pub fn republish_all(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().republish_all())
    })
}

pub fn resync_all(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().resync_all())
    })
}

/// Refresh all CAs
pub fn refresh_all(server: web::Data<AppServer>, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().refresh_all())
    })
}

//------------ Provisioning (RFC6492) ----------------------------------------

/// Process an RFC 6492 request
///
pub fn rfc6492(
    server: web::Data<AppServer>,
    parent: Path<ParentHandle>,
    msg_bytes: Bytes,
) -> HttpResponse {
    match server.read().rfc6492(parent.into_inner(), msg_bytes) {
        Ok(bytes) => HttpResponse::build(StatusCode::OK)
            .content_type(rfc6492::CONTENT_TYPE)
            .body(bytes),
        Err(e) => {
            error!("Error processing RFC6492 req: {}", e);
            server_error(&Error::ServerError(e))
        }
    }
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
            krillserver::Error::SignerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            krillserver::Error::CaServerError(e) => e.status(),
            krillserver::Error::NoEmbeddedRepo => StatusCode::BAD_REQUEST,
        }
    }
}

impl ErrorToStatus for pubd::Error {
    fn status(&self) -> StatusCode {
        match self {
            pubd::Error::DuplicatePublisher(_) => StatusCode::BAD_REQUEST,
            pubd::Error::UnknownPublisher(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ErrorToStatus for ca::ServerError {
    fn status(&self) -> StatusCode {
        match self {
            ca::ServerError::CertAuth(e) => e.status(),
            ca::ServerError::DuplicateCa(_) => StatusCode::BAD_REQUEST,
            ca::ServerError::UnknownCa(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl ErrorToStatus for ca::Error {
    fn status(&self) -> StatusCode {
        match self {
            ca::Error::Unauthorized(_) => StatusCode::FORBIDDEN,
            ca::Error::SignerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ca::Error::UnknownChild(_) => StatusCode::NOT_FOUND,
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
            krillserver::Error::SignerError(_) => ErrorCode::SigningError,
            krillserver::Error::CaServerError(e) => e.code(),
            krillserver::Error::NoEmbeddedRepo => ErrorCode::NoEmbeddedRepo,
        }
    }
}

impl ToErrorCode for pubd::Error {
    fn code(&self) -> ErrorCode {
        match self {
            pubd::Error::Validation(_) => ErrorCode::CmsValidation,
            pubd::Error::Rfc8181MessageError(_) => ErrorCode::InvalidPublicationXml,
            pubd::Error::DuplicatePublisher(_) => ErrorCode::DuplicateHandle,
            pubd::Error::UnknownPublisher(_) => ErrorCode::UnknownPublisher,
            pubd::Error::PublishingOutsideBaseUri(_, _) => ErrorCode::UriOutsideJail,
            pubd::Error::BaseUriNoDir(_) => ErrorCode::InvalidBaseUri,
            pubd::Error::RrdpVerificationError(e) => e.code(),
            pubd::Error::NoRepository => ErrorCode::PubServerError,
            pubd::Error::Store(_) => ErrorCode::Persistence,
            pubd::Error::IoError(_) => ErrorCode::Persistence,
            pubd::Error::SignerError(_) => ErrorCode::SigningError,
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

impl ToErrorCode for ca::ServerError {
    fn code(&self) -> ErrorCode {
        match self {
            ca::ServerError::CertAuth(e) => e.code(),
            ca::ServerError::DuplicateCa(_) => ErrorCode::DuplicateCa,
            ca::ServerError::UnknownCa(_) => ErrorCode::UnknownCa,
            _ => ErrorCode::CaServerError,
        }
    }
}

impl ToErrorCode for ca::Error {
    fn code(&self) -> ErrorCode {
        match self {
            ca::Error::DuplicateChild(_) => ErrorCode::DuplicateChild,
            ca::Error::UnknownChild(_) => ErrorCode::UnknownChild,
            ca::Error::UnknownParent(_) => ErrorCode::UnknownParent,
            ca::Error::MustHaveResources => ErrorCode::ChildNeedsResources,
            ca::Error::MissingResources => ErrorCode::ChildOverclaims,
            ca::Error::DuplicateParent(_) => ErrorCode::DuplicateParent,
            ca::Error::AuthorisationAlreadyPresent(_, _) => ErrorCode::RoaUpdateInvalidDuplicate,
            ca::Error::AuthorisationUnknown(_, _) => ErrorCode::RoaUpdateInvalidMissing,
            ca::Error::AuthorisationNotEntitled(_, _) => ErrorCode::RoaUpdateInvalidResources,
            ca::Error::AuthorisationInvalidMaxlength(_, _) => ErrorCode::RoaUpdateInvalidMaxlength,
            ca::Error::NewRepoUpdateNoChange => ErrorCode::NewRepoNoChange,
            ca::Error::NewRepoUpdateNotResponsive(_) => ErrorCode::NewRepoNoResponse,
            ca::Error::RepoNotSet => ErrorCode::NoRepositorySet,
            ca::Error::ParentNotResponsive(_) => ErrorCode::ParentNoResponse,
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
