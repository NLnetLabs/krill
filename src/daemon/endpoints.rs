//! Process requests received, delegate, and wrap up the responses.
use actix_web::http::StatusCode;
use actix_web::web::{self, Json, Path};
use actix_web::HttpResponse;
use bytes::Bytes;
use serde::Serialize;

use crate::commons::api::{
    AddChildRequest, CertAuthInit, Handle, ParentCaContact, ParentCaReq, ParentHandle,
    PublisherHandle, PublisherList, RepositoryUpdate, RoaDefinitionUpdates, UpdateChildRequest,
};
use crate::commons::error::Error;
use crate::commons::remote::{rfc6492, rfc8181, rfc8183};
use crate::daemon::auth::Auth;
use crate::daemon::http::server::AppServer;

//------------ Support Functions ---------------------------------------------

/// Helper function to render json output.
fn render_json<O: Serialize>(object: O) -> HttpResponse {
    match serde_json::to_string(&object) {
        Ok(enc) => HttpResponse::Ok()
            .content_type("application/json")
            .body(enc),
        Err(e) => server_error(Error::JsonError(e)),
    }
}

/// Helper function to render server side errors. Also responsible for
/// logging the errors.
fn server_error(error: Error) -> HttpResponse {
    error!("{}", error);
    HttpResponse::build(error.status())
        .body(serde_json::to_string(&error.to_error_response()).unwrap())
}

fn render_empty_res(res: Result<(), Error>) -> HttpResponse {
    match res {
        Ok(()) => api_ok(),
        Err(e) => server_error(e),
    }
}

fn render_json_res<O: Serialize>(res: Result<O, Error>) -> HttpResponse {
    match res {
        Ok(o) => render_json(o),
        Err(e) => server_error(e),
    }
}

/// A clean 404 result for the API (no content, not for humans)
fn api_not_found() -> HttpResponse {
    server_error(Error::ApiUnknownResource)
}

pub fn api_bad_request() -> HttpResponse {
    server_error(Error::ApiUnknownMethod)
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

    let info = server.read().server_info();
    res.push_str("# HELP krill_server_start timestamp of last krill server start\n");
    res.push_str("# TYPE krill_server_start gauge\n");
    res.push_str(&format!("krill_server_start {}\n", info.started()));
    res.push_str("\n");

    if let Ok(stats) = server.read().repo_stats() {
        let publishers = stats.get_publishers();

        res.push_str("# HELP krill_repo_publisher number of publishers in repository\n");
        res.push_str("# TYPE krill_repo_publisher gauge\n");
        res.push_str(&format!("krill_repo_publisher {}\n", publishers.len()));

        if let Some(last_update) = stats.last_update() {
            res.push_str("\n");
            res.push_str(
                "# HELP krill_repo_rrdp_last_update timestamp of last update by any publisher\n",
            );
            res.push_str("# TYPE krill_repo_rrdp_last_update gauge\n");
            res.push_str(&format!(
                "krill_repo_rrdp_last_update {}\n",
                last_update.timestamp()
            ));
        }

        res.push_str("\n");
        res.push_str("# HELP krill_repo_rrdp_serial RRDP serial\n");
        res.push_str("# TYPE krill_repo_rrdp_serial counter\n");
        res.push_str(&format!("krill_repo_rrdp_serial {}\n", stats.serial()));

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
        res.push_str("# HELP krill_repo_last_update timestamp of last update for publisher\n");
        res.push_str("# TYPE krill_repo_last_update gauge\n");
        for (publisher, stats) in publishers {
            if let Some(last_update) = stats.last_update() {
                res.push_str(&format!(
                    "krill_repo_last_update{{publisher=\"{}\"}} {}\n",
                    publisher,
                    last_update.timestamp()
                ));
            }
        }
    }

    let cas_status = server.read().cas_stats();

    let number_cas = cas_status.len();
    res.push_str("\n");
    res.push_str("# HELP krill_cas number of cas in krill\n");
    res.push_str("# TYPE krill_cas gauge\n");
    res.push_str(&format!("krill_cas {}\n", number_cas));

    res.push_str("\n");
    res.push_str("# HELP krill_cas_roas number of roas for CA\n");
    res.push_str("# TYPE krill_cas_roas gauge\n");
    for (ca, status) in cas_status.iter() {
        res.push_str(&format!(
            "krill_cas_roas{{ca=\"{}\"}} {}\n",
            ca,
            status.roa_count()
        ));
    }

    res.push_str("\n");
    res.push_str("# HELP krill_cas_children number of children for CA\n");
    res.push_str("# TYPE krill_cas_children gauge\n");
    for (ca, status) in cas_status.iter() {
        res.push_str(&format!(
            "krill_cas_children{{ca=\"{}\"}} {}\n",
            ca,
            status.child_count()
        ));
    }

    HttpResponse::Ok().body(res)
}

// Return general server info
pub fn server_info(server: web::Data<AppServer>) -> HttpResponse {
    render_json(server.read().server_info())
}

//------------ Admin: Publishers ---------------------------------------------

pub fn repo_stats(server: web::Data<AppServer>) -> HttpResponse {
    render_json_res(server.read().repo_stats())
}

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub fn stale_publishers(server: web::Data<AppServer>, seconds: web::Path<i64>) -> HttpResponse {
    render_json_res(server.read().repo_stats().map(|stats| {
        PublisherList::build(
            &stats.stale_publishers(seconds.into_inner()),
            "/api/v1/publishers",
        )
    }))
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
        Err(e) => server_error(e),
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

            Err(e) => server_error(e),
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
            Err(e) => server_error(e),
        }
    })
}

fn repository_response(
    server: &web::Data<AppServer>,
    publisher: &Handle,
) -> Result<rfc8183::RepositoryResponse, Error> {
    server.read().repository_response(publisher)
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

            Err(e) => server_error(e),
        }
    })
}

//------------ Admin: CertAuth -----------------------------------------------

pub fn all_ca_issues(server: web::Data<AppServer>) -> HttpResponse {
    render_json_res(server.read().all_ca_issues())
}

/// Returns the health (state) for a given CA.
pub fn ca_issues(server: web::Data<AppServer>, ca: Path<Handle>) -> HttpResponse {
    render_json_res(server.read().ca_issues(&ca.into_inner()))
}

pub fn cas_stats(server: web::Data<AppServer>) -> HttpResponse {
    render_json(server.read().cas_stats())
}

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
        Err(e) => server_error(e),
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
        Err(e) => server_error(e),
    })
}

fn ca_child_req(
    server: &web::Data<AppServer>,
    handle: &Handle,
) -> Result<rfc8183::ChildRequest, Error> {
    server.read().ca_child_req(handle)
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

fn extract_repository_update(handle: &Handle, bytes: Bytes) -> Result<RepositoryUpdate, Error> {
    let string = String::from_utf8(bytes.to_vec()).map_err(Error::custom)?;

    // TODO: Switch based on Content-Type header
    if string.starts_with('<') {
        if string.contains("<parent_response") {
            Err(Error::CaRepoResponseWrongXml(handle.clone()))
        } else {
            let response = rfc8183::RepositoryResponse::validate(string.as_bytes())
                .map_err(|e| Error::CaRepoResponseInvalidXml(handle.clone(), e.to_string()))?;
            Ok(RepositoryUpdate::Rfc8181(response))
        }
    } else {
        serde_json::from_str(&string).map_err(Error::JsonError)
    }
}

pub fn ca_repo_update(
    server: web::Data<AppServer>,
    auth: Auth,
    handle: Path<Handle>,
    bytes: Bytes,
) -> HttpResponse {
    let handle = handle.into_inner();
    let update = match extract_repository_update(&handle, bytes) {
        Ok(update) => update,
        Err(e) => return server_error(e),
    };

    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_update_repo(handle, update))
    })
}

pub fn ca_add_parent(
    server: web::Data<AppServer>,
    auth: Auth,
    ca: Path<Handle>,
    req: Json<ParentCaReq>,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(
            server
                .read()
                .ca_parent_add(ca.into_inner(), req.into_inner()),
        )
    })
}

pub fn ca_add_parent_xml(
    server: web::Data<AppServer>,
    auth: Auth,
    ca_and_parent: Path<(Handle, Handle)>,
    bytes: Bytes,
) -> HttpResponse {
    let (ca, parent) = ca_and_parent.into_inner();
    let string = match String::from_utf8(bytes.to_vec()).map_err(Error::custom) {
        Ok(string) => string,
        Err(e) => return server_error(e),
    };

    let req = if string.starts_with("<repository") {
        return server_error(Error::CaParentResponseWrongXml(ca));
    } else {
        let res = match rfc8183::ParentResponse::validate(string.as_bytes())
            .map_err(|e| Error::CaParentResponseInvalidXml(ca.clone(), e.to_string()))
        {
            Ok(res) => res,
            Err(e) => return server_error(e),
        };
        let contact = ParentCaContact::Rfc6492(res);

        ParentCaReq::new(parent, contact)
    };

    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_add(ca, req))
    })
}

fn extract_parent_ca_contact(ca: &Handle, bytes: Bytes) -> Result<ParentCaContact, Error> {
    let string = String::from_utf8(bytes.to_vec()).map_err(Error::custom)?;

    // TODO: Switch based on Content-Type header
    if string.starts_with('<') {
        if string.starts_with("<repository") {
            Err(Error::CaParentResponseWrongXml(ca.clone()))
        } else {
            let res = rfc8183::ParentResponse::validate(string.as_bytes())
                .map_err(|e| Error::CaParentResponseInvalidXml(ca.clone(), e.to_string()))?;
            Ok(ParentCaContact::Rfc6492(res))
        }
    } else {
        serde_json::from_str(&string).map_err(Error::JsonError)
    }
}

pub fn ca_update_parent(
    server: web::Data<AppServer>,
    auth: Auth,
    ca_and_parent: Path<(Handle, Handle)>,
    bytes: Bytes,
) -> HttpResponse {
    let (ca, parent) = ca_and_parent.into_inner();
    let contact = match extract_parent_ca_contact(&ca, bytes) {
        Ok(contact) => contact,
        Err(e) => return server_error(e),
    };
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_update(ca, parent, contact))
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
        Err(e) => server_error(e),
    }
}
