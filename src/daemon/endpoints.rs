//! Process requests received, delegate, and wrap up the responses.
use hyper::{Body, StatusCode};
// use actix_web::web::{self, Json, Path};
// use actix_web::Response;
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
use crate::daemon::http::Response;
use commons::api::ChildHandle;

//------------ Support Functions ---------------------------------------------

/// Helper function to render json output.
fn render_json<O: Serialize>(object: O) -> Response {
    match serde_json::to_string(&object) {
        Ok(enc) => unimplemented!("#189"), // Response::Ok().content_type("application/json").body(enc),
        Err(e) => server_error(Error::JsonError(e)),
    }
}

/// Helper function to render server side errors. Also responsible for
/// logging the errors.
fn server_error(error: Error) -> Response {
    error!("{}", error);
    // Response::build(error.status()).body(serde_json::to_string(&error.to_error_response()).unwrap())
    unimplemented!("#189")
}

fn render_empty_res(res: Result<(), Error>) -> Response {
    match res {
        Ok(()) => api_ok(),
        Err(e) => server_error(e),
    }
}

fn render_json_res<O: Serialize>(res: Result<O, Error>) -> Response {
    match res {
        Ok(o) => render_json(o),
        Err(e) => server_error(e),
    }
}

/// A clean 404 result for the API (no content, not for humans)
fn api_not_found() -> Response {
    server_error(Error::ApiUnknownResource)
}

pub fn api_bad_request() -> Response {
    server_error(Error::ApiUnknownMethod)
}

pub fn not_found() -> Response {
    // Response::build(StatusCode::NOT_FOUND).body("NOT_FOUND")
    unimplemented!("#189")
}

/// A clean 200 result for the API (no content, not for humans)
pub fn api_ok() -> Response {
    // Response::Ok().finish()
    unimplemented!("#189")
}

/// Returns the server health.
pub fn health() -> Response {
    api_ok()
}

/// Returns the server health.
pub fn api_authorized(server: AppServer, auth: Auth) -> Response {
    if_api_allowed(&server, &auth, api_ok)
}

fn if_allowed<F>(allowed: bool, op: F) -> Response
where
    F: FnOnce() -> Response,
{
    if allowed {
        op()
    } else {
        // Response::Forbidden().finish()
        unimplemented!("#189")
    }
}

fn if_api_allowed<F>(server: &AppServer, auth: &Auth, op: F) -> Response
where
    F: FnOnce() -> Response,
{
    let allowed = server.read().is_api_allowed(auth);
    if_allowed(allowed, op)
}

/// Produce prometheus style metrics
pub fn metrics(server: AppServer) -> Response {
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

    // Response::Ok().body(res)
    unimplemented!("#189")
}

// Return general server info
pub fn server_info(server: AppServer) -> Response {
    render_json(server.read().server_info())
}

//------------ Admin: Publishers ---------------------------------------------

pub fn repo_stats(server: AppServer) -> Response {
    render_json_res(server.read().repo_stats())
}

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub fn stale_publishers(server: AppServer, seconds: i64) -> Response {
    render_json_res(
        server.read().repo_stats().map(|stats| {
            PublisherList::build(&stats.stale_publishers(seconds), "/api/v1/publishers")
        }),
    )
}

/// Returns a json structure with all publishers in it.
pub fn list_pbl(server: AppServer, auth: Auth) -> Response {
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
pub fn add_pbl(server: AppServer, auth: Auth, pbl: rfc8183::PublisherRequest) -> Response {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.write().add_publisher(pbl))
    })
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::needless_pass_by_value)]
pub fn remove_pbl(server: AppServer, auth: Auth, publisher: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.write().remove_publisher(publisher))
    })
}

/// Returns a json structure with publisher details
#[allow(clippy::needless_pass_by_value)]
pub fn show_pbl(server: AppServer, auth: Auth, publisher: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().get_publisher(&publisher))
    })
}

//------------ Publication ---------------------------------------------------

/// Processes an RFC8181 query and returns the appropriate response.
pub fn rfc8181(server: AppServer, publisher: PublisherHandle, msg_bytes: Bytes) -> Response {
    // match server.read().rfc8181(publisher.into_inner(), msg_bytes) {
    //     Ok(bytes) => Response::build(StatusCode::OK)
    //         .content_type(rfc8181::CONTENT_TYPE)
    //         .body(bytes),
    //     Err(e) => server_error(e),
    // }
    unimplemented!("#189")
}

//------------ repository_response ---------------------------------------------

pub fn repository_response_xml(server: AppServer, auth: Auth, publisher: Handle) -> Response {
    // if_api_allowed(&server, &auth, || {
    //     match repository_response(&server, &publisher.into_inner()) {
    //         Ok(res) => Response::Ok()
    //             .content_type("application/xml")
    //             .body(res.encode_vec()),
    //
    //         Err(e) => server_error(e),
    //     }
    // })
    unimplemented!("#189")
}

pub fn repository_response_json(server: AppServer, auth: Auth, publisher: Handle) -> Response {
    // if_api_allowed(&server, &auth, || {
    //     match repository_response(&server, &publisher.into_inner()) {
    //         Ok(res) => render_json(res),
    //         Err(e) => server_error(e),
    //     }
    // })
    unimplemented!("#189")
}

fn repository_response(
    server: &AppServer,
    publisher: &Handle,
) -> Result<rfc8183::RepositoryResponse, Error> {
    server.read().repository_response(publisher)
}

//------------ Admin: TrustAnchor --------------------------------------------

pub fn tal(server: AppServer) -> Response {
    match server.read().ta() {
        Ok(ta) => {
            // Response::Ok()
            //     .content_type("text/plain")
            //     .body(format!("{}", ta.tal()))
            unimplemented!("#189")
        }
        Err(_) => api_not_found(),
    }
}

pub fn ta_cer(server: AppServer) -> Response {
    match server.read().trust_anchor_cert() {
        Some(cert) => unimplemented!("#189"), // Response::Ok().body(cert.to_captured().to_vec()),
        None => api_not_found(),
    }
}

pub fn ca_add_child(
    server: AppServer,
    parent: ParentHandle,
    req: AddChildRequest,
    auth: Auth,
) -> Response {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_add_child(&parent, req))
    })
}

pub fn ca_child_update(
    server: AppServer,
    ca: Handle,
    child: ChildHandle,
    req: UpdateChildRequest,
    auth: Auth,
) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_child_update(&ca, child, req))
    })
}

pub fn ca_child_remove(server: AppServer, ca: Handle, child: ChildHandle, auth: Auth) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_child_remove(&ca, child))
    })
}

pub fn ca_show_child(server: AppServer, ca_and_child: (Handle, Handle), auth: Auth) -> Response {
    // let ca_and_child = ca_and_child.into_inner();
    // let ca = ca_and_child.0;
    // let child = ca_and_child.1;
    //
    // if_api_allowed(&server, &auth, || {
    //     render_json_res(server.read().ca_show_child(&ca, &child))
    // })
    unimplemented!("#189")
}

pub fn ca_parent_contact(
    server: AppServer,
    ca_and_child: (Handle, Handle),
    auth: Auth,
) -> Response {
    // let ca_and_child = ca_and_child.into_inner();
    // let ca = ca_and_child.0;
    // let child = ca_and_child.1;
    //
    // if_api_allowed(&server, &auth, || {
    //     render_json_res(server.read().ca_parent_contact(&ca, child.clone()))
    // })
    unimplemented!("#189")
}

pub fn ca_parent_res_json(
    server: AppServer,
    ca_and_child: (Handle, Handle),
    auth: Auth,
) -> Response {
    // let ca_and_child = ca_and_child.into_inner();
    // let ca = ca_and_child.0;
    // let child = ca_and_child.1;
    //
    // if_api_allowed(&server, &auth, || {
    //     render_json_res(server.read().ca_parent_response(&ca, child.clone()))
    // })
    unimplemented!("#189")
}

pub fn ca_parent_res_xml(
    server: AppServer,
    ca_and_child: (Handle, Handle),
    auth: Auth,
) -> Response {
    // let ca_and_child = ca_and_child.into_inner();
    // let ca = ca_and_child.0;
    // let child = ca_and_child.1;
    //
    // if_api_allowed(&server, &auth, || {
    //     match server.read().ca_parent_response(&ca, child.clone()) {
    //         Ok(res) => Response::Ok()
    //             .content_type("application/xml")
    //             .body(res.encode_vec()),
    //
    //         Err(e) => server_error(e),
    //     }
    // })
    unimplemented!("#189")
}

//------------ Admin: CertAuth -----------------------------------------------

pub fn all_ca_issues(server: AppServer) -> Response {
    render_json_res(server.read().all_ca_issues())
}

/// Returns the health (state) for a given CA.
pub fn ca_issues(server: AppServer, ca: Handle) -> Response {
    render_json_res(server.read().ca_issues(&ca))
}

pub fn cas_stats(server: AppServer) -> Response {
    render_json(server.read().cas_stats())
}

pub fn cas(server: AppServer, auth: Auth) -> Response {
    if_api_allowed(&server, &auth, || render_json(server.read().cas()))
}

pub fn ca_init(server: AppServer, auth: Auth, ca_init: CertAuthInit) -> Response {
    // if_api_allowed(&server, &auth, || {
    //     render_empty_res(server.write().ca_init(ca_init.into_inner()))
    // })
    unimplemented!("#189")
}

pub fn ca_regenerate_id(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // if_api_allowed(&server, &auth, || {
    //     render_empty_res(server.read().ca_update_id(handle.into_inner()))
    // })
    unimplemented!("#189")
}

pub fn ca_info(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // if_api_allowed(&server, &auth, || {
    //     render_json_res(server.read().ca_info(&handle.into_inner()))
    // })
    unimplemented!("#189")
}

pub fn ca_my_parent_contact(
    server: AppServer,
    auth: Auth,
    ca_and_parent: (Handle, Handle),
) -> Response {
    // let (ca, parent) = ca_and_parent.into_inner();
    // if_api_allowed(&server, &auth, || {
    //     render_json_res(server.read().ca_my_parent_contact(&ca, &parent))
    // })
    unimplemented!("#189")
}

pub fn ca_history(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // if_api_allowed(&server, &auth, || {
    //     match server.read().ca_history(&handle.into_inner()) {
    //         Some(history) => render_json(history),
    //         None => api_not_found(),
    //     }
    // })
    unimplemented!("#189")
}

pub fn ca_child_req_xml(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // let handle = handle.into_inner();
    // if_api_allowed(&server, &auth, || match ca_child_req(&server, &handle) {
    //     Ok(req) => Response::Ok()
    //         .content_type("application/xml")
    //         .body(req.encode_vec()),
    //     Err(e) => server_error(e),
    // })
    unimplemented!("#189")
}

pub fn ca_child_req_json(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // let handle = handle.into_inner();
    // if_api_allowed(&server, &auth, || match ca_child_req(&server, &handle) {
    //     Ok(req) => render_json(req),
    //     Err(e) => server_error(e),
    // })
    unimplemented!("#189")
}

fn ca_child_req(server: &AppServer, handle: &Handle) -> Result<rfc8183::ChildRequest, Error> {
    server.read().ca_child_req(handle)
}

pub fn ca_publisher_req_json(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // let handle = handle.into_inner();
    // if_api_allowed(&server, &auth, || {
    //     match server.read().ca_publisher_req(&handle) {
    //         Some(req) => render_json(req),
    //         None => api_not_found(),
    //     }
    // })
    unimplemented!("#189")
}

pub fn ca_publisher_req_xml(server: AppServer, auth: Auth, handle: Handle) -> Response {
    // let handle = handle.into_inner();
    // if_api_allowed(&server, &auth, || {
    //     match server.read().ca_publisher_req(&handle) {
    //         Some(req) => Response::Ok()
    //             .content_type("application/xml")
    //             .body(req.encode_vec()),
    //         None => api_not_found(),
    //     }
    // })
    unimplemented!("#189")
}

pub fn ca_repo_details(server: AppServer, auth: Auth, handle: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        render_json_res(server.read().ca_repo_details(&handle))
    })
}

pub fn ca_repo_state(server: AppServer, auth: Auth, handle: Handle) -> Response {
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

pub fn ca_repo_update(server: AppServer, auth: Auth, handle: Handle, bytes: Bytes) -> Response {
    let update = match extract_repository_update(&handle, bytes) {
        Ok(update) => update,
        Err(e) => return server_error(e),
    };

    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_update_repo(handle, update))
    })
}

pub fn ca_add_parent(server: AppServer, auth: Auth, ca: Handle, req: ParentCaReq) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_add(ca, req))
    })
}

pub fn ca_add_parent_xml(
    server: AppServer,
    auth: Auth,
    ca_and_parent: (Handle, Handle),
    bytes: Bytes,
) -> Response {
    let (ca, parent) = ca_and_parent;
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
    server: AppServer,
    auth: Auth,
    ca: Handle,
    parent: Handle,
    bytes: Bytes,
) -> Response {
    let contact = match extract_parent_ca_contact(&ca, bytes) {
        Ok(contact) => contact,
        Err(e) => return server_error(e),
    };
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_update(ca, parent, contact))
    })
}

pub fn ca_remove_parent(server: AppServer, auth: Auth, ca: Handle, parent: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_parent_remove(ca, parent))
    })
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
pub fn ca_kr_init(server: AppServer, auth: Auth, handle: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_keyroll_init(handle))
    })
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
pub fn ca_kr_activate(server: AppServer, auth: Auth, handle: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_keyroll_activate(handle))
    })
}

//------------ Admin: Force republish ----------------------------------------

/// Update the route authorizations for this CA
pub fn ca_routes_update(
    server: AppServer,
    auth: Auth,
    handle: Handle,
    updates: RoaDefinitionUpdates,
) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().ca_routes_update(handle, updates))
    })
}

/// show the route authorizations for this CA
pub fn ca_routes_show(server: AppServer, auth: Auth, handle: Handle) -> Response {
    if_api_allowed(&server, &auth, || {
        match server.read().ca_routes_show(&handle) {
            Ok(roas) => render_json(roas),
            Err(_) => api_not_found(),
        }
    })
}

//------------ Admin: Force republish ----------------------------------------

pub fn republish_all(server: AppServer, auth: Auth) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().republish_all())
    })
}

pub fn resync_all(server: AppServer, auth: Auth) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().resync_all())
    })
}

/// Refresh all CAs
pub fn refresh_all(server: AppServer, auth: Auth) -> Response {
    if_api_allowed(&server, &auth, || {
        render_empty_res(server.read().refresh_all())
    })
}

//------------ Provisioning (RFC6492) ----------------------------------------

/// Process an RFC 6492 request
///
pub fn rfc6492(server: AppServer, parent: ParentHandle, msg_bytes: Bytes) -> Response {
    match server.read().rfc6492(parent, msg_bytes) {
        Ok(bytes) => {
            // Response::build(StatusCode::OK)
            //     .content_type(rfc6492::CONTENT_TYPE)
            //     .body(bytes)
            unimplemented!("#189")
        }
        Err(e) => server_error(e),
    }
}
