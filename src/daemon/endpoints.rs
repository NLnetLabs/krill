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
use crate::daemon::http::{HttpResponse, Request, RequestPath};
use std::str::FromStr;

pub type RoutingResult = Result<HttpResponse, Request>;

//------------ Support Functions ---------------------------------------------

fn render_empty_res(res: Result<(), Error>) -> RoutingResult {
    match res {
        Ok(()) => render_ok(),
        Err(e) => render_error(e),
    }
}

fn render_error(e: Error) -> RoutingResult {
    Ok(HttpResponse::error(e))
}

fn render_json<O: Serialize>(obj: O) -> RoutingResult {
    Ok(HttpResponse::json(&obj))
}

fn render_json_res<O: Serialize>(res: Result<O, Error>) -> RoutingResult {
    match res {
        Ok(o) => render_json(o),
        Err(e) => render_error(e),
    }
}

fn render_json_res_res<O: Serialize>(res: Result<Result<O, Error>, Error>) -> RoutingResult {
    match res {
        Ok(res) => render_json_res(res),
        Err(e) => render_error(e),
    }
}

/// A clean 404 result for the API (no content, not for humans)
fn render_unknown_resource() -> RoutingResult {
    Ok(HttpResponse::error(Error::ApiUnknownResource))
}

/// A clean 200 result for the API (no content, not for humans)
pub fn render_ok() -> RoutingResult {
    Ok(HttpResponse::ok())
}

fn render_unknown_method() -> RoutingResult {
    Ok(HttpResponse::error(Error::ApiUnknownMethod))
}

/// A clean 404 response
pub async fn render_not_found(_req: Request) -> RoutingResult {
    Ok(HttpResponse::not_found())
}

/// Returns the server health.
pub async fn health(req: Request) -> RoutingResult {
    if req.is_get() && req.path().segment() == "health" {
        render_ok()
    } else {
        Err(req)
    }
}

/// Produce prometheus style metrics
pub async fn metrics(req: Request) -> RoutingResult {
    if req.is_get() && req.path().segment().starts_with("metrics") {
        let server = req.read();

        let mut res = String::new();

        let info = server.server_info();
        res.push_str("# HELP krill_server_start timestamp of last krill server start\n");
        res.push_str("# TYPE krill_server_start gauge\n");
        res.push_str(&format!("krill_server_start {}\n", info.started()));
        res.push_str("\n");

        if let Ok(stats) = server.repo_stats() {
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
            res.push_str(
                "# HELP krill_repo_objects number of objects in repository for publisher\n",
            );
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

        let cas_status = server.cas_stats();

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

        Ok(HttpResponse::text(res.into_bytes()))
    } else {
        Err(req)
    }
}

/// Return various stats as json
pub async fn stats(req: Request) -> RoutingResult {
    if !req.is_get() {
        Err(req)
    } else if req.path().full() == "/stats/info" {
        render_json(req.read().server_info())
    } else if req.path().full() == "/stats/repo" {
        render_json_res(req.read().repo_stats())
    } else if req.path().full() == "/stats/cas" {
        render_json(req.read().cas_stats())
    } else {
        Err(req)
    }
}

/// Maps the API methods
pub async fn api(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/api/v1") {
        Err(req) // Not for us
    } else {
        // Make sure access is allowed
        if !req.is_authorized() {
            return Ok(HttpResponse::forbidden());
        }

        // Eat the first two segments of the path "api/v1"
        let mut path = req.path().clone();
        path.next(); // gets 'v1' and drops it.

        match path.next() {
            Some("authorized") => api_authorized(req),
            Some("publishers") => api_publishers(req, &mut path).await,
            _ => render_unknown_method(),
        }
    }
}

fn api_authorized(req: Request) -> RoutingResult {
    if req.is_get() {
        render_ok()
    } else {
        render_unknown_method()
    }
}

async fn api_publishers(req: Request, path: &mut RequestPath) -> RoutingResult {
    if req.is_get() {
        if let Some(publisher_str) = path.next() {
            let publisher = match PublisherHandle::from_str(publisher_str) {
                Ok(handle) => handle,
                Err(e) => return render_error(Error::ApiInvalidHandle),
            };

            match path.next() {
                None => show_pbl(req, publisher),
                Some("response.xml") => repository_response_xml(req, publisher),
                Some("response.json") => repository_response_json(req, publisher),
                Some("stale") => stale_publishers(req, path.next()),
                _ => render_unknown_method(),
            }
        } else {
            list_pbl(req)
        }
    } else if req.is_post() {
        match path.next() {
            None => add_pbl(req).await,
            _ => render_unknown_method(),
        }
    } else {
        render_unknown_method()
    }
}

//------------ Admin: Publishers ---------------------------------------------

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub fn stale_publishers(req: Request, seconds: Option<&str>) -> RoutingResult {
    let seconds = seconds.unwrap_or("");
    match i64::from_str(seconds) {
        Ok(seconds) => render_json_res(req.read().repo_stats().map(|stats| {
            PublisherList::build(&stats.stale_publishers(seconds), "/api/v1/publishers")
        })),
        Err(_) => render_error(Error::ApiInvalidSeconds),
    }
}

/// Returns a json structure with all publishers in it.
pub fn list_pbl(req: Request) -> RoutingResult {
    render_json_res(
        req.read()
            .publishers()
            .map(|publishers| PublisherList::build(&publishers, "/api/v1/publishers")),
    )
}

/// Adds a publisher
async fn add_pbl(req: Request) -> RoutingResult {
    let server = req.state().clone();
    render_json_res_res(
        req.json()
            .await
            .map(|pbl| server.write().add_publisher(pbl)),
    )
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::needless_pass_by_value)]
pub fn remove_pbl(req: Request, publisher: Handle) -> RoutingResult {
    render_empty_res(req.write().remove_publisher(publisher))
}

/// Returns a json structure with publisher details
#[allow(clippy::needless_pass_by_value)]
pub fn show_pbl(req: Request, publisher: Handle) -> RoutingResult {
    render_json_res(req.read().get_publisher(&publisher))
}

//------------ Publication ---------------------------------------------------

/// Processes an RFC8181 query and returns the appropriate response.
pub fn rfc8181(req: Request, publisher: PublisherHandle, msg_bytes: Bytes) -> RoutingResult {
    match req.read().rfc8181(publisher, msg_bytes) {
        Ok(bytes) => Ok(HttpResponse::rfc8181(bytes.to_vec())),
        Err(e) => render_error(e),
    }
}

//------------ repository_response ---------------------------------------------

pub fn repository_response_xml(req: Request, publisher: Handle) -> RoutingResult {
    match repository_response(&req, &publisher) {
        Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
        Err(e) => render_error(e),
    }
}

pub fn repository_response_json(req: Request, publisher: Handle) -> RoutingResult {
    match repository_response(&req, &publisher) {
        Ok(res) => render_json(res),
        Err(e) => render_error(e),
    }
}

fn repository_response(
    req: &Request,
    publisher: &Handle,
) -> Result<rfc8183::RepositoryResponse, Error> {
    req.read().repository_response(publisher)
}

//------------ Admin: TrustAnchor --------------------------------------------

pub fn tal(req: Request) -> RoutingResult {
    match req.read().ta() {
        Ok(ta) => Ok(HttpResponse::text(format!("{}", ta.tal()).into_bytes())),
        Err(_) => render_unknown_resource(),
    }
}

pub fn ta_cer(req: Request) -> RoutingResult {
    match req.read().trust_anchor_cert() {
        Some(cert) => Ok(HttpResponse::cert(cert.to_captured().to_vec())),
        None => render_unknown_resource(),
    }
}

pub fn ca_add_child(
    req: Request,
    parent: ParentHandle,
    child_req: AddChildRequest,
) -> RoutingResult {
    render_json_res(req.read().ca_add_child(&parent, child_req))
}

pub fn ca_child_update(
    req: Request,
    ca: Handle,
    child: ChildHandle,
    child_req: UpdateChildRequest,
) -> RoutingResult {
    render_empty_res(req.read().ca_child_update(&ca, child, child_req))
}

pub fn ca_child_remove(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_empty_res(req.read().ca_child_remove(&ca, child))
}

pub fn ca_show_child(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_json_res(req.read().ca_show_child(&ca, &child))
}

pub fn ca_parent_contact(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_json_res(req.read().ca_parent_contact(&ca, child.clone()))
}

pub fn ca_parent_res_json(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_json_res(req.read().ca_parent_response(&ca, child.clone()))
}

pub fn ca_parent_res_xml(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    match req.read().ca_parent_response(&ca, child.clone()) {
        Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
        Err(e) => render_error(e),
    }
}

//------------ Admin: CertAuth -----------------------------------------------

pub fn all_ca_issues(req: Request) -> RoutingResult {
    render_json_res(req.read().all_ca_issues())
}

/// Returns the health (state) for a given CA.
pub fn ca_issues(req: Request, ca: Handle) -> RoutingResult {
    render_json_res(req.read().ca_issues(&ca))
}

pub fn cas(req: Request) -> RoutingResult {
    render_json(req.read().cas())
}

pub fn ca_init(req: Request, ca_init: CertAuthInit) -> RoutingResult {
    render_empty_res(req.write().ca_init(ca_init))
}

pub fn ca_regenerate_id(req: Request, handle: Handle) -> RoutingResult {
    render_empty_res(req.read().ca_update_id(handle))
}

pub fn ca_info(req: Request, handle: Handle) -> RoutingResult {
    render_json_res(req.read().ca_info(&handle))
}

pub fn ca_my_parent_contact(req: Request, ca: Handle, parent: ParentHandle) -> RoutingResult {
    render_json_res(req.read().ca_my_parent_contact(&ca, &parent))
}

pub fn ca_history(req: Request, handle: Handle) -> RoutingResult {
    match req.read().ca_history(&handle) {
        Some(history) => render_json(history),
        None => render_unknown_resource(),
    }
}

pub fn ca_child_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match ca_child_req(&req, &handle) {
        Ok(req) => Ok(HttpResponse::xml(req.encode_vec())),
        Err(e) => render_error(e),
    }
}

pub fn ca_child_req_json(req: Request, handle: Handle) -> RoutingResult {
    match ca_child_req(&req, &handle) {
        Ok(req) => render_json(req),
        Err(e) => render_error(e),
    }
}

fn ca_child_req(req: &Request, handle: &Handle) -> Result<rfc8183::ChildRequest, Error> {
    req.read().ca_child_req(handle)
}

pub fn ca_publisher_req_json(req: Request, handle: Handle) -> RoutingResult {
    match req.read().ca_publisher_req(&handle) {
        Some(req) => render_json(req),
        None => render_unknown_resource(),
    }
}

pub fn ca_publisher_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match req.read().ca_publisher_req(&handle) {
        Some(req) => Ok(HttpResponse::xml(req.encode_vec())),
        None => render_unknown_resource(),
    }
}

pub fn ca_repo_details(req: Request, handle: Handle) -> RoutingResult {
    render_json_res(req.read().ca_repo_details(&handle))
}

pub fn ca_repo_state(req: Request, handle: Handle) -> RoutingResult {
    render_json_res(req.read().ca_repo_state(&handle))
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

pub fn ca_repo_update(req: Request, handle: Handle, bytes: Bytes) -> RoutingResult {
    let update = match extract_repository_update(&handle, bytes) {
        Ok(update) => update,
        Err(e) => return render_error(e),
    };

    render_empty_res(req.read().ca_update_repo(handle, update))
}

pub fn ca_add_parent(req: Request, ca: Handle, parent_req: ParentCaReq) -> RoutingResult {
    render_empty_res(req.read().ca_parent_add(ca, parent_req))
}

pub fn ca_add_parent_xml(
    req: Request,
    ca: Handle,
    parent: ParentHandle,
    bytes: Bytes,
) -> RoutingResult {
    let string = match String::from_utf8(bytes.to_vec()).map_err(Error::custom) {
        Ok(string) => string,
        Err(e) => return render_error(e),
    };

    let parent_req = if string.starts_with("<repository") {
        return render_error(Error::CaParentResponseWrongXml(ca));
    } else {
        let res = match rfc8183::ParentResponse::validate(string.as_bytes())
            .map_err(|e| Error::CaParentResponseInvalidXml(ca.clone(), e.to_string()))
        {
            Ok(res) => res,
            Err(e) => return render_error(e),
        };
        let contact = ParentCaContact::Rfc6492(res);

        ParentCaReq::new(parent, contact)
    };

    render_empty_res(req.read().ca_parent_add(ca, parent_req))
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
    req: Request,
    ca: Handle,
    parent: ParentHandle,
    bytes: Bytes,
) -> RoutingResult {
    match extract_parent_ca_contact(&ca, bytes) {
        Ok(contact) => render_empty_res(req.read().ca_parent_update(ca, parent, contact)),
        Err(e) => return render_error(e),
    }
}

pub fn ca_remove_parent(req: Request, ca: Handle, parent: Handle) -> RoutingResult {
    render_empty_res(req.read().ca_parent_remove(ca, parent))
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
pub fn ca_kr_init(req: Request, handle: Handle) -> RoutingResult {
    render_empty_res(req.read().ca_keyroll_init(handle))
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
pub fn ca_kr_activate(req: Request, handle: Handle) -> RoutingResult {
    render_empty_res(req.read().ca_keyroll_activate(handle))
}

//------------ Admin: Force republish ----------------------------------------

/// Update the route authorizations for this CA
pub fn ca_routes_update(
    req: Request,
    handle: Handle,
    updates: RoaDefinitionUpdates,
) -> RoutingResult {
    render_empty_res(req.read().ca_routes_update(handle, updates))
}

/// show the route authorizations for this CA
pub fn ca_routes_show(req: Request, handle: Handle) -> RoutingResult {
    match req.read().ca_routes_show(&handle) {
        Ok(roas) => render_json(roas),
        Err(_) => render_unknown_resource(),
    }
}

//------------ Admin: Force republish ----------------------------------------

pub fn republish_all(req: Request) -> RoutingResult {
    render_empty_res(req.read().republish_all())
}

pub fn resync_all(req: Request) -> RoutingResult {
    render_empty_res(req.read().resync_all())
}

/// Refresh all CAs
pub fn refresh_all(req: Request) -> RoutingResult {
    render_empty_res(req.read().refresh_all())
}

//------------ Provisioning (RFC6492) ----------------------------------------

/// Process an RFC 6492 request
///
pub fn rfc6492(req: Request, parent: ParentHandle, msg_bytes: Bytes) -> RoutingResult {
    match req.read().rfc6492(parent, msg_bytes) {
        Ok(bytes) => Ok(HttpResponse::rfc6492(bytes.to_vec())),
        Err(e) => render_error(e),
    }
}
