//! Process requests received, delegate, and wrap up the responses.
use bytes::Bytes;
use serde::Serialize;

use crate::commons::api::{
    AddChildRequest, CertAuthInit, ChildHandle, Handle, ParentCaContact, ParentCaReq, ParentHandle,
    PublisherHandle, PublisherList, RepositoryUpdate, RoaDefinitionUpdates, UpdateChildRequest,
};
use crate::commons::error::Error;
use crate::commons::remote::rfc8183;
use crate::daemon::auth::Auth;
use crate::daemon::http::server::State;
use crate::daemon::http::{HttpResponse, Request};

//------------ Support Functions ---------------------------------------------

fn render_empty_res(res: Result<(), Error>) -> HttpResponse {
    match res {
        Ok(()) => api_ok(),
        Err(e) => HttpResponse::error(e),
    }
}

fn render_json_res<O: Serialize>(res: Result<O, Error>) -> HttpResponse {
    match res {
        Ok(o) => HttpResponse::json(&o),
        Err(e) => HttpResponse::error(e),
    }
}

/// A clean 404 result for the API (no content, not for humans)
fn api_not_found() -> HttpResponse {
    HttpResponse::error(Error::ApiUnknownResource)
}

pub fn api_bad_request() -> HttpResponse {
    HttpResponse::error(Error::ApiUnknownMethod)
}

/// A clean 200 result for the API (no content, not for humans)
pub fn api_ok() -> HttpResponse {
    HttpResponse::ok()
}

/// A clean 404 response
pub fn not_found(_req: Request) -> Result<HttpResponse, Request> {
    Ok(HttpResponse::not_found())
}

/// Returns the server health.
pub fn health(req: Request) -> Result<HttpResponse, Request> {
    if req.path().segment() == "health" {
        Ok(api_ok())
    } else {
        Err(req)
    }
}

/// Returns the server health.
pub fn api_authorized(server: State, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, api_ok)
}

fn if_allowed<F>(allowed: bool, op: F) -> HttpResponse
where
    F: FnOnce() -> HttpResponse,
{
    if allowed {
        op()
    } else {
        HttpResponse::forbidden()
    }
}

fn if_api_allowed<F>(server: &State, auth: &Auth, op: F) -> HttpResponse
where
    F: FnOnce() -> HttpResponse,
{
    let allowed = server.read().is_api_allowed(auth);
    if_allowed(allowed, op)
}

/// Produce prometheus style metrics
pub fn metrics(server: State) -> HttpResponse {
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

    HttpResponse::text(res.into_bytes())
}

// Return general server info
pub fn server_info(server: State) -> HttpResponse {
    HttpResponse::json(&server.read().server_info())
}

//------------ Admin: Publishers ---------------------------------------------

pub fn repo_stats(server: State) -> HttpResponse {
    render_json_res(server.read().repo_stats())
}

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub fn stale_publishers(server: State, seconds: i64) -> HttpResponse {
    render_json_res(
        server.read().repo_stats().map(|stats| {
            PublisherList::build(&stats.stale_publishers(seconds), "/api/v1/publishers")
        }),
    )
}

/// Returns a json structure with all publishers in it.
pub fn list_pbl(server: State, auth: Auth) -> HttpResponse {
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
pub fn add_pbl(server: State, auth: Auth, pbl: rfc8183::PublisherRequest) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.write().add_publisher(pbl))
    })
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::needless_pass_by_value)]
pub fn remove_pbl(server: State, auth: Auth, publisher: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().remove_publisher(publisher))
    })
}

/// Returns a json structure with publisher details
#[allow(clippy::needless_pass_by_value)]
pub fn show_pbl(server: State, auth: Auth, publisher: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().get_publisher(&publisher))
    })
}

//------------ Publication ---------------------------------------------------

/// Processes an RFC8181 query and returns the appropriate response.
pub fn rfc8181(server: State, publisher: PublisherHandle, msg_bytes: Bytes) -> HttpResponse {
    match server.read().rfc8181(publisher, msg_bytes) {
        Ok(bytes) => HttpResponse::rfc8181(bytes.to_vec()),
        Err(e) => HttpResponse::error(e),
    }
}

//------------ repository_response ---------------------------------------------

pub fn repository_response_xml(server: State, auth: Auth, publisher: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match repository_response(&server, &publisher) {
            Ok(res) => HttpResponse::xml(res.encode_vec()),
            Err(e) => HttpResponse::error(e),
        }
    })
}

pub fn repository_response_json(server: State, auth: Auth, publisher: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match repository_response(&server, &publisher) {
            Ok(res) => HttpResponse::json(&res),
            Err(e) => HttpResponse::error(e),
        }
    })
}

fn repository_response(
    server: &State,
    publisher: &Handle,
) -> Result<rfc8183::RepositoryResponse, Error> {
    server.read().repository_response(publisher)
}

//------------ Admin: TrustAnchor --------------------------------------------

pub fn tal(server: State) -> HttpResponse {
    match server.read().ta() {
        Ok(ta) => HttpResponse::text(format!("{}", ta.tal()).into_bytes()),
        Err(_) => api_not_found(),
    }
}

pub fn ta_cer(server: State) -> HttpResponse {
    match server.read().trust_anchor_cert() {
        Some(cert) => HttpResponse::cert(cert.to_captured().to_vec()),
        None => api_not_found(),
    }
}

pub fn ca_add_child(
    server: State,
    parent: ParentHandle,
    req: AddChildRequest,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_add_child(&parent, req))
    })
}

pub fn ca_child_update(
    server: State,
    ca: Handle,
    child: ChildHandle,
    req: UpdateChildRequest,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_child_update(&ca, child, req))
    })
}

pub fn ca_child_remove(server: State, ca: Handle, child: ChildHandle, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_child_remove(&ca, child))
    })
}

pub fn ca_show_child(server: State, ca: Handle, child: ChildHandle, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_show_child(&ca, &child))
    })
}

pub fn ca_parent_contact(
    server: State,
    ca: Handle,
    child: ChildHandle,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_parent_contact(&ca, child.clone()))
    })
}

pub fn ca_parent_res_json(
    server: State,
    ca: Handle,
    child: ChildHandle,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_parent_response(&ca, child.clone()))
    })
}

pub fn ca_parent_res_xml(
    server: State,
    ca: Handle,
    child: ChildHandle,
    auth: Auth,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_parent_response(&ca, child.clone()) {
            Ok(res) => HttpResponse::xml(res.encode_vec()),
            Err(e) => HttpResponse::error(e),
        }
    })
}

//------------ Admin: CertAuth -----------------------------------------------

pub fn all_ca_issues(server: State) -> HttpResponse {
    render_json_res(server.read().all_ca_issues())
}

/// Returns the health (state) for a given CA.
pub fn ca_issues(server: State, ca: Handle) -> HttpResponse {
    render_json_res(server.read().ca_issues(&ca))
}

pub fn cas_stats(server: State) -> HttpResponse {
    HttpResponse::json(&server.read().cas_stats())
}

pub fn cas(server: State, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || HttpResponse::json(&server.read().cas()))
}

pub fn ca_init(server: State, auth: Auth, ca_init: CertAuthInit) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().ca_init(ca_init))
    })
}

pub fn ca_regenerate_id(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_update_id(handle))
    })
}

pub fn ca_info(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_info(&handle))
    })
}

pub fn ca_my_parent_contact(
    server: State,
    auth: Auth,
    ca: Handle,
    parent: ParentHandle,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_my_parent_contact(&ca, &parent))
    })
}

pub fn ca_history(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || match server.read().ca_history(&handle) {
        Some(history) => HttpResponse::json(&history),
        None => api_not_found(),
    })
}

pub fn ca_child_req_xml(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || match ca_child_req(&server, &handle) {
        Ok(req) => HttpResponse::xml(req.encode_vec()),
        Err(e) => HttpResponse::error(e),
    })
}

pub fn ca_child_req_json(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || match ca_child_req(&server, &handle) {
        Ok(req) => HttpResponse::json(&req),
        Err(e) => HttpResponse::error(e),
    })
}

fn ca_child_req(server: &State, handle: &Handle) -> Result<rfc8183::ChildRequest, Error> {
    server.read().ca_child_req(handle)
}

pub fn ca_publisher_req_json(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_publisher_req(&handle) {
            Some(req) => HttpResponse::json(&req),
            None => api_not_found(),
        }
    })
}

pub fn ca_publisher_req_xml(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_publisher_req(&handle) {
            Some(req) => HttpResponse::xml(req.encode_vec()),
            None => api_not_found(),
        }
    })
}

pub fn ca_repo_details(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_repo_details(&handle))
    })
}

pub fn ca_repo_state(server: State, auth: Auth, handle: Handle) -> HttpResponse {
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

pub fn ca_repo_update(server: State, auth: Auth, handle: Handle, bytes: Bytes) -> HttpResponse {
    let update = match extract_repository_update(&handle, bytes) {
        Ok(update) => update,
        Err(e) => return HttpResponse::error(e),
    };

    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_update_repo(handle, update))
    })
}

pub fn ca_add_parent(server: State, auth: Auth, ca: Handle, req: ParentCaReq) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_add(ca, req))
    })
}

pub fn ca_add_parent_xml(
    server: State,
    auth: Auth,
    ca_and_parent: (Handle, Handle),
    bytes: Bytes,
) -> HttpResponse {
    let (ca, parent) = ca_and_parent;
    let string = match String::from_utf8(bytes.to_vec()).map_err(Error::custom) {
        Ok(string) => string,
        Err(e) => return HttpResponse::error(e),
    };

    let req = if string.starts_with("<repository") {
        return HttpResponse::error(Error::CaParentResponseWrongXml(ca));
    } else {
        let res = match rfc8183::ParentResponse::validate(string.as_bytes())
            .map_err(|e| Error::CaParentResponseInvalidXml(ca.clone(), e.to_string()))
        {
            Ok(res) => res,
            Err(e) => return HttpResponse::error(e),
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
    server: State,
    auth: Auth,
    ca: Handle,
    parent: Handle,
    bytes: Bytes,
) -> HttpResponse {
    let contact = match extract_parent_ca_contact(&ca, bytes) {
        Ok(contact) => contact,
        Err(e) => return HttpResponse::error(e),
    };
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_update(ca, parent, contact))
    })
}

pub fn ca_remove_parent(server: State, auth: Auth, ca: Handle, parent: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_remove(ca, parent))
    })
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
pub fn ca_kr_init(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_keyroll_init(handle))
    })
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
pub fn ca_kr_activate(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_keyroll_activate(handle))
    })
}

//------------ Admin: Force republish ----------------------------------------

/// Update the route authorizations for this CA
pub fn ca_routes_update(
    server: State,
    auth: Auth,
    handle: Handle,
    updates: RoaDefinitionUpdates,
) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_routes_update(handle, updates))
    })
}

/// show the route authorizations for this CA
pub fn ca_routes_show(server: State, auth: Auth, handle: Handle) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_routes_show(&handle) {
            Ok(roas) => HttpResponse::json(&roas),
            Err(_) => api_not_found(),
        }
    })
}

//------------ Admin: Force republish ----------------------------------------

pub fn republish_all(server: State, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().republish_all())
    })
}

pub fn resync_all(server: State, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().resync_all())
    })
}

/// Refresh all CAs
pub fn refresh_all(server: State, auth: Auth) -> HttpResponse {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().refresh_all())
    })
}

//------------ Provisioning (RFC6492) ----------------------------------------

/// Process an RFC 6492 request
///
pub fn rfc6492(server: State, parent: ParentHandle, msg_bytes: Bytes) -> HttpResponse {
    match server.read().rfc6492(parent, msg_bytes) {
        Ok(bytes) => HttpResponse::rfc6492(bytes.to_vec()),
        Err(e) => HttpResponse::error(e),
    }
}
