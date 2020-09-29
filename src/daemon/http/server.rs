//! Hyper based HTTP server for Krill.
//!
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use serde::Serialize;

use tokio::sync::RwLock;

use futures::TryFutureExt;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::Method;

use crate::commons::api::{
    BgpStats, ChildHandle, CommandHistoryCriteria, Handle, ParentCaContact, ParentCaReq, ParentHandle, PublisherList,
    RepositoryUpdate, RoaDefinitionUpdates, RtaName,
};
use crate::commons::bgp::BgpAnalysisAdvice;
use crate::commons::error::Error;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::constants::{KRILL_ENV_UPGRADE_ONLY, KRILL_VERSION_MAJOR, KRILL_VERSION_MINOR, KRILL_VERSION_PATCH};
use crate::daemon::ca::RouteAuthorizationUpdates;
use crate::daemon::ca::{ta_handle, testbed_ca_handle};
use crate::daemon::config::CONFIG;
use crate::daemon::http::statics::statics;
use crate::daemon::http::{tls, tls_keys, HttpResponse, Request, RequestPath, RoutingResult};
use crate::daemon::krillserver::KrillServer;
use crate::upgrades::{post_start_upgrade, pre_start_upgrade};

//------------ State -----------------------------------------------------

pub type State = Arc<RwLock<KrillServer>>;

pub async fn start() -> Result<(), Error> {
    let pid_file = CONFIG.pid_file();
    if let Err(e) = file::save(process::id().to_string().as_bytes(), &pid_file) {
        eprintln!("Could not write PID file: {}", e);
        ::std::process::exit(1);
    }

    // Call upgrade, this will only do actual work if needed.
    pre_start_upgrade(&CONFIG.data_dir).map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))?;

    // Create the server, this will create the necessary data sub-directories if needed
    let krill = KrillServer::build().await?;

    post_start_upgrade(&CONFIG.data_dir, &krill)
        .map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))
        .await?;

    if env::var(KRILL_ENV_UPGRADE_ONLY).is_ok() {
        println!("Krill upgrade successful");
        ::std::process::exit(0);
    }

    let state = Arc::new(RwLock::new(krill));

    let service = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: hyper::Request<hyper::Body>| {
                let state = state.clone();
                map_requests(req, state)
            }))
        }
    });

    tls_keys::create_key_cert_if_needed(&CONFIG.data_dir).map_err(|e| Error::HttpsSetup(format!("{}", e)))?;

    let server_config_builder = tls::TlsConfigBuilder::new()
        .cert_path(tls_keys::cert_file_path(&CONFIG.data_dir))
        .key_path(tls_keys::key_file_path(&CONFIG.data_dir));
    let server_config = server_config_builder.build().unwrap();

    let acceptor = tls::TlsAcceptor::new(server_config, AddrIncoming::bind(&CONFIG.socket_addr()).unwrap());

    let server = hyper::Server::builder(acceptor)
        .serve(service)
        .map_err(|e| eprintln!("Server error: {}", e));

    if server.await.is_err() {
        eprintln!("Krill failed to start");
        ::std::process::exit(1);
    }

    Ok(())
}

async fn map_requests(req: hyper::Request<hyper::Body>, state: State) -> Result<hyper::Response<hyper::Body>, Error> {
    let req = Request::new(req, state);

    let log_req = format!("{} {}", req.method(), req.path.full());

    let res = api(req)
        .or_else(health)
        .or_else(metrics)
        .or_else(stats)
        .or_else(rfc8181)
        .or_else(rfc6492)
        .or_else(statics)
        .or_else(ta)
        .or_else(rrdp)
        .or_else(testbed)
        .or_else(render_not_found)
        .map_err(|_| Error::custom("should have received not found response"))
        .await;

    match res {
        Ok(routing_result) => {
            let response = routing_result.response();
            info!("{} {}", log_req, response.status(),);
            trace!("Response body: {:?}", response.body());
            Ok(response)
        }
        Err(e) => {
            error!("{} Error: {}", log_req, e);
            Err(e)
        }
    }
}

//------------ Support Functions ---------------------------------------------

fn render_empty_res(res: Result<(), Error>) -> RoutingResult {
    match res {
        Ok(()) => render_ok(),
        Err(e) => render_error(e),
    }
}

fn render_error(e: Error) -> RoutingResult {
    error!("Respond with error: {}", e);
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
        let server = req.state();
        let server = server.read().await;

        struct AllBgpStats {
            announcements_valid: HashMap<Handle, usize>,
            announcements_invalid_asn: HashMap<Handle, usize>,
            announcements_invalid_length: HashMap<Handle, usize>,
            announcements_not_found: HashMap<Handle, usize>,
            roas_too_permissive: HashMap<Handle, usize>,
            roas_redundant: HashMap<Handle, usize>,
            roas_stale: HashMap<Handle, usize>,
            roas_total: HashMap<Handle, usize>,
        }

        impl AllBgpStats {
            fn add_ca(&mut self, ca: &Handle, stats: &BgpStats) {
                self.announcements_valid.insert(ca.clone(), stats.announcements_valid);
                self.announcements_invalid_asn
                    .insert(ca.clone(), stats.announcements_invalid_asn);
                self.announcements_invalid_length
                    .insert(ca.clone(), stats.announcements_invalid_length);
                self.announcements_not_found
                    .insert(ca.clone(), stats.announcements_not_found);
                self.roas_too_permissive.insert(ca.clone(), stats.roas_too_permissive);
                self.roas_redundant.insert(ca.clone(), stats.roas_redundant);
                self.roas_stale.insert(ca.clone(), stats.roas_stale);
                self.roas_total.insert(ca.clone(), stats.roas_total);
            }
        }

        let mut res = String::new();

        let info = server.server_info();
        res.push_str("# HELP krill_server_start timestamp of last krill server start\n");
        res.push_str("# TYPE krill_server_start gauge\n");
        res.push_str(&format!("krill_server_start {}\n", info.started()));
        res.push_str("\n");

        res.push_str("# HELP krill_version_major krill server major version number\n");
        res.push_str("# TYPE krill_version_major gauge\n");
        res.push_str(&format!("krill_version_major {}\n", KRILL_VERSION_MAJOR));
        res.push_str("\n");

        res.push_str("# HELP krill_version_minor krill server minor version number\n");
        res.push_str("# TYPE krill_version_minor gauge\n");
        res.push_str(&format!("krill_version_minor {}\n", KRILL_VERSION_MINOR));
        res.push_str("\n");

        res.push_str("# HELP krill_version_patch krill server patch version number\n");
        res.push_str("# TYPE krill_version_patch gauge\n");
        res.push_str(&format!("krill_version_patch {}\n", KRILL_VERSION_PATCH));
        res.push_str("\n");

        if let Ok(stats) = server.repo_stats() {
            let publishers = stats.get_publishers();

            res.push_str("# HELP krill_repo_publisher number of publishers in repository\n");
            res.push_str("# TYPE krill_repo_publisher gauge\n");
            res.push_str(&format!("krill_repo_publisher {}\n", publishers.len()));

            if let Some(last_update) = stats.last_update() {
                res.push_str("\n");
                res.push_str("# HELP krill_repo_rrdp_last_update timestamp of last update by any publisher\n");
                res.push_str("# TYPE krill_repo_rrdp_last_update gauge\n");
                res.push_str(&format!("krill_repo_rrdp_last_update {}\n", last_update.timestamp()));
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
            res.push_str("# HELP krill_repo_size size of objects in bytes in repository for publisher\n");
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

        let cas_status = server.cas_stats().await;

        let number_cas = cas_status.len();
        res.push_str("\n");
        res.push_str("# HELP krill_cas number of cas in krill\n");
        res.push_str("# TYPE krill_cas gauge\n");
        res.push_str(&format!("krill_cas {}\n", number_cas));

        res.push_str("\n");
        res.push_str("# HELP krill_cas_roas number of roas for CA\n");
        res.push_str("# TYPE krill_cas_roas gauge\n");
        for (ca, status) in cas_status.iter() {
            res.push_str(&format!("krill_cas_roas{{ca=\"{}\"}} {}\n", ca, status.roa_count()));
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

        // Aggregate ROA vs BGP stats per status
        let mut all_bgp_stats = AllBgpStats {
            announcements_valid: HashMap::new(),
            announcements_invalid_asn: HashMap::new(),
            announcements_invalid_length: HashMap::new(),
            announcements_not_found: HashMap::new(),
            roas_too_permissive: HashMap::new(),
            roas_redundant: HashMap::new(),
            roas_stale: HashMap::new(),
            roas_total: HashMap::new(),
        };
        for (ca, status) in cas_status.iter() {
            all_bgp_stats.add_ca(ca, status.bgp_stats());
        }

        res.push_str("\n");
        res.push_str("# HELP krill_cas_bgp_announcements_valid number of announcements seen for CA resources with RPKI state VALID\n");
        res.push_str("# TYPE krill_cas_bgp_announcements_valid gauge\n");
        for (ca, nr) in all_bgp_stats.announcements_valid.iter() {
            res.push_str(&format!("krill_cas_bgp_announcements_valid{{ca=\"{}\"}} {}\n", ca, nr));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_cas_bgp_announcements_invalid_asn number of announcements seen for CA resources with RPKI state INVALID (ASN mismatch)\n",
        );
        res.push_str("# TYPE krill_cas_bgp_announcements_invalid_asn gauge\n");
        for (ca, nr) in all_bgp_stats.announcements_invalid_asn.iter() {
            res.push_str(&format!(
                "krill_cas_bgp_announcements_invalid_asn{{ca=\"{}\"}} {}\n",
                ca, nr
            ));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_cas_bgp_announcements_invalid_length number of announcements seen for CA resources with RPKI state INVALID (prefix exceeds max length)\n",
        );
        res.push_str("# TYPE krill_cas_bgp_announcements_invalid_length gauge\n");
        for (ca, nr) in all_bgp_stats.announcements_invalid_length.iter() {
            res.push_str(&format!(
                "krill_cas_bgp_announcements_invalid_length{{ca=\"{}\"}} {}\n",
                ca, nr
            ));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_cas_bgp_announcements_not_found number of announcements seen for CA resources with RPKI state NOT FOUND (none of the CA's ROAs cover this)\n",
        );
        res.push_str("# TYPE krill_cas_bgp_announcements_not_found gauge\n");
        for (ca, nr) in all_bgp_stats.announcements_not_found.iter() {
            res.push_str(&format!(
                "krill_cas_bgp_announcements_not_found{{ca=\"{}\"}} {}\n",
                ca, nr
            ));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_cas_bgp_roas_too_permissive number of ROAs for this CA which allow excess announcements (0 may also indicate that no BGP info is available)\n",
        );
        res.push_str("# TYPE krill_cas_bgp_roas_too_permissive gauge\n");
        for (ca, nr) in all_bgp_stats.roas_too_permissive.iter() {
            res.push_str(&format!("krill_cas_bgp_roas_too_permissive{{ca=\"{}\"}} {}\n", ca, nr));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_cas_bgp_roas_redundant number of ROAs for this CA which are redundant (0 may also indicate that no BGP info is available)\n",
        );
        res.push_str("# TYPE krill_cas_bgp_roas_redundant gauge\n");
        for (ca, nr) in all_bgp_stats.roas_redundant.iter() {
            res.push_str(&format!("krill_cas_bgp_roas_redundant{{ca=\"{}\"}} {}\n", ca, nr));
        }

        res.push_str("\n");
        res.push_str(
            "# HELP krill_cas_bgp_roas_stale number of ROAs for this CA for which no announcements are seen (0 may also indicate that no BGP info is available)\n",
        );
        res.push_str("# TYPE krill_cas_bgp_roas_stale gauge\n");
        for (ca, nr) in all_bgp_stats.roas_stale.iter() {
            res.push_str(&format!("krill_cas_bgp_roas_stale{{ca=\"{}\"}} {}\n", ca, nr));
        }

        res.push_str("\n");
        res.push_str("# HELP krill_cas_bgp_roas_total total number of ROAs for this CA\n");
        res.push_str("# TYPE krill_cas_bgp_roas_stale gauge\n");
        for (ca, nr) in all_bgp_stats.roas_total.iter() {
            res.push_str(&format!("krill_cas_bgp_roas_total{{ca=\"{}\"}} {}\n", ca, nr));
        }

        Ok(HttpResponse::text(res.into_bytes()))
    } else {
        Err(req)
    }
}

//------------ Publication ---------------------------------------------------

/// Handle RFC8181 queries and return the appropriate response.
pub async fn rfc8181(req: Request) -> RoutingResult {
    if req.path().segment() == "rfc8181" {
        let mut path = req.path().clone();
        let publisher = match path.path_arg() {
            Some(publisher) => publisher,
            None => return render_error(Error::ApiInvalidHandle),
        };

        let state = req.state().clone();

        let bytes = match req.rfc8181_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };

        let read = state.read().await;
        match read.rfc8181(publisher, bytes) {
            Ok(bytes) => Ok(HttpResponse::rfc8181(bytes.to_vec())),
            Err(e) => render_error(e),
        }
    } else {
        Err(req)
    }
}

//------------ Embedded TA  --------------------------------------------------
async fn ta(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => match req.path.full() {
            "/ta/ta.tal" => tal(req).await,
            "/testbed.tal" if CONFIG.testbed_enabled => tal(req).await,
            "/ta/ta.cer" => ta_cer(req).await,
            _ => Err(req),
        },
        _ => Err(req),
    }
}

pub async fn tal(req: Request) -> RoutingResult {
    match req.state().read().await.ta().await {
        Ok(ta) => Ok(HttpResponse::text(format!("{}", ta.tal()).into_bytes())),
        Err(_) => render_unknown_resource(),
    }
}

pub async fn ta_cer(req: Request) -> RoutingResult {
    match req.state().read().await.trust_anchor_cert().await {
        Some(cert) => Ok(HttpResponse::cert(cert.to_captured().to_vec())),
        None => render_unknown_resource(),
    }
}

//------------ Provisioning (RFC6492) ----------------------------------------

/// Process an RFC 6492 request
///
pub async fn rfc6492(req: Request) -> RoutingResult {
    if req.path().segment() == "rfc6492" {
        let mut path = req.path().clone();
        let ca = match path.path_arg() {
            Some(ca) => ca,
            None => return render_error(Error::ApiInvalidHandle),
        };

        let state = req.state().clone();

        let bytes = match req.rfc6492_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };
        let lock = state.read().await;
        match lock.rfc6492(ca, bytes).await {
            Ok(bytes) => Ok(HttpResponse::rfc6492(bytes.to_vec())),
            Err(e) => render_error(e),
        }
    } else {
        Err(req)
    }
}

/// Return various stats as json
async fn stats(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => match req.path().full() {
            "/stats/info" => render_json(req.state().read().await.server_info()),
            "/stats/repo" => render_json_res(req.state().read().await.repo_stats()),
            "/stats/cas" => render_json(req.state().read().await.cas_stats().await),
            _ => Err(req),
        },
        _ => Err(req),
    }
}

/// Maps the API methods
async fn api(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/api/v1") {
        Err(req) // Not for us
    } else {
        // Make sure access is allowed
        if !req.is_authorized().await {
            return Ok(HttpResponse::forbidden());
        }

        // Eat the first two segments of the path "api/v1"
        let mut path = req.path().clone();
        path.next(); // gets 'v1' and drops it.

        match path.next() {
            Some("authorized") => api_authorized(req),
            Some("bulk") => api_bulk(req, &mut path).await,
            Some("cas") => api_cas(req, &mut path).await,
            Some("publishers") => api_publishers(req, &mut path).await,
            _ => render_unknown_method(),
        }
    }
}

fn api_authorized(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => render_ok(),
        _ => render_unknown_method(),
    }
}

async fn api_bulk(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.full() {
        "/api/v1/bulk/cas/issues" => all_ca_issues(req).await,
        "/api/v1/bulk/cas/sync/parent" => refresh_all(req).await,
        "/api/v1/bulk/cas/sync/repo" => resync_all(req).await,
        "/api/v1/bulk/cas/publish" => republish_all(req).await,
        _ => render_unknown_method(),
    }
}

async fn api_cas(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.path_arg() {
        Some(ca) => match path.next() {
            None => ca_info(req, ca).await,
            Some("child_request.xml") => ca_child_req_xml(req, ca).await,
            Some("child_request.json") => ca_child_req_json(req, ca).await,
            Some("children") => ca_children(req, path, ca).await,
            Some("history") => ca_history(req, path, ca).await,
            Some("command") => ca_command_details(req, path, ca).await,
            Some("id") => ca_regenerate_id(req, ca).await,
            Some("issues") => ca_issues(req, ca).await,
            Some("keys") => ca_keys(req, path, ca).await,
            Some("parents") => api_ca_parents(req, path, ca).await,
            Some("parents-xml") => ca_add_parent_xml(req, path, ca).await,
            Some("repo") => api_ca_repo(req, path, ca).await,
            Some("routes") => api_ca_routes(req, path, ca).await,
            Some("rta") => api_ca_rta(req, path, ca).await,
            _ => render_unknown_method(),
        },
        None => match *req.method() {
            Method::GET => cas(req).await,
            Method::POST => ca_init(req).await,
            _ => render_unknown_method(),
        },
    }
}

async fn ca_keys(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::POST => match path.next() {
            Some("roll_init") => ca_kr_init(req, ca).await,
            Some("roll_activate") => ca_kr_activate(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_ca_parents(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    if let Some(parent) = path.path_arg() {
        match *req.method() {
            Method::GET => ca_my_parent_contact(req, ca, parent).await,
            Method::POST => ca_update_parent(req, ca, parent).await,
            Method::DELETE => ca_remove_parent(req, ca, parent).await,
            _ => render_unknown_method(),
        }
    } else {
        match *req.method() {
            Method::GET => ca_my_parent_statuses(req, ca).await,
            Method::POST => ca_add_parent(req, ca).await,
            _ => render_unknown_method(),
        }
    }
}

async fn api_ca_repo(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => ca_repo_details(req, ca).await,
            Method::POST => ca_repo_update(req, ca).await,
            _ => render_unknown_method(),
        },
        Some("request.json") => ca_publisher_req_json(req, ca).await,
        Some("request.xml") => ca_publisher_req_xml(req, ca).await,
        Some("status") => ca_repo_status(req, ca).await,
        _ => render_unknown_method(),
    }
}

async fn api_ca_routes(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => ca_routes_show(req, ca).await,
            Method::POST => ca_routes_update(req, ca).await,
            _ => render_unknown_method(),
        },
        Some("try") => match *req.method() {
            Method::POST => ca_routes_try_update(req, ca).await,
            _ => render_unknown_method(),
        },
        Some("analysis") => ca_routes_analysis(req, path, ca).await,
        _ => render_unknown_method(),
    }
}

async fn api_publishers(req: Request, path: &mut RequestPath) -> RoutingResult {
    match *req.method() {
        Method::GET => match path.path_arg() {
            Some(publisher) => match path.next() {
                None => show_pbl(req, publisher).await,
                Some("response.xml") => repository_response_xml(req, publisher).await,
                Some("response.json") => repository_response_json(req, publisher).await,
                Some("stale") => stale_publishers(req, path.next()).await,
                _ => render_unknown_method(),
            },
            None => list_pbl(req).await,
        },
        Method::POST => match path.next() {
            None => add_pbl(req).await,
            _ => render_unknown_method(),
        },
        Method::DELETE => match path.path_arg() {
            Some(publisher) => remove_pbl(req, publisher).await,
            None => render_error(Error::ApiInvalidHandle),
        },
        _ => render_unknown_method(),
    }
}

//------------ Admin: Publishers ---------------------------------------------

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub async fn stale_publishers(req: Request, seconds: Option<&str>) -> RoutingResult {
    let seconds = seconds.unwrap_or("");
    match i64::from_str(seconds) {
        Ok(seconds) => render_json_res(
            req.state()
                .read()
                .await
                .repo_stats()
                .map(|stats| PublisherList::build(&stats.stale_publishers(seconds), "/api/v1/publishers")),
        ),
        Err(_) => render_error(Error::ApiInvalidSeconds),
    }
}

/// Returns a json structure with all publishers in it.
pub async fn list_pbl(req: Request) -> RoutingResult {
    render_json_res(
        req.state()
            .read()
            .await
            .publishers()
            .map(|publishers| PublisherList::build(&publishers, "/api/v1/publishers")),
    )
}

/// Adds a publisher
async fn add_pbl(req: Request) -> RoutingResult {
    let server = req.state().clone();
    match req.json().await {
        Ok(pbl) => render_json_res(server.write().await.add_publisher(pbl)),
        Err(e) => render_error(e),
    }
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
pub async fn remove_pbl(req: Request, publisher: Handle) -> RoutingResult {
    render_empty_res(req.state().write().await.remove_publisher(publisher))
}

/// Returns a json structure with publisher details
pub async fn show_pbl(req: Request, publisher: Handle) -> RoutingResult {
    render_json_res(req.state().read().await.get_publisher(&publisher))
}

//------------ repository_response ---------------------------------------------

pub async fn repository_response_xml(req: Request, publisher: Handle) -> RoutingResult {
    match repository_response(&req, &publisher).await {
        Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
        Err(e) => render_error(e),
    }
}

pub async fn repository_response_json(req: Request, publisher: Handle) -> RoutingResult {
    match repository_response(&req, &publisher).await {
        Ok(res) => render_json(res),
        Err(e) => render_error(e),
    }
}

async fn repository_response(req: &Request, publisher: &Handle) -> Result<rfc8183::RepositoryResponse, Error> {
    req.state().read().await.repository_response(publisher)
}

async fn ca_add_child(req: Request, parent: ParentHandle) -> RoutingResult {
    let server = req.state().clone();
    match req.json().await {
        Ok(child_req) => render_json_res(server.read().await.ca_add_child(&parent, child_req).await),
        Err(e) => render_error(e),
    }
}

async fn ca_child_update(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    let server = req.state().clone();
    match req.json().await {
        Ok(child_req) => render_empty_res(server.read().await.ca_child_update(&ca, child, child_req).await),
        Err(e) => render_error(e),
    }
}

async fn ca_child_remove(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_empty_res(req.state().read().await.ca_child_remove(&ca, child).await)
}

async fn ca_child_show(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_json_res(req.state().read().await.ca_child_show(&ca, &child).await)
}

async fn ca_parent_contact(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_json_res(req.state().read().await.ca_parent_contact(&ca, child.clone()).await)
}

async fn ca_parent_res_json(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    render_json_res(req.state().read().await.ca_parent_response(&ca, child.clone()).await)
}

async fn ca_parent_res_xml(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    match req.state().read().await.ca_parent_response(&ca, child.clone()).await {
        Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
        Err(e) => render_error(e),
    }
}

//------------ Admin: CertAuth -----------------------------------------------

async fn all_ca_issues(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => render_json_res(req.state().read().await.all_ca_issues().await),
        _ => render_unknown_method(),
    }
}

/// Returns the health (state) for a given CA.
async fn ca_issues(req: Request, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => render_json_res(req.state().read().await.ca_issues(&ca).await),
        _ => render_unknown_method(),
    }
}

async fn cas(req: Request) -> RoutingResult {
    render_json(req.state().read().await.ca_list().await)
}

pub async fn ca_init(req: Request) -> RoutingResult {
    let state = req.state().clone();

    match req.json().await {
        Ok(ca_init) => render_empty_res(state.write().await.ca_init(ca_init).await),
        Err(e) => render_error(e),
    }
}

async fn ca_regenerate_id(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::POST => render_empty_res(req.state().read().await.ca_update_id(handle).await),
        _ => render_unknown_method(),
    }
}

async fn ca_info(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => render_json_res(req.state().read().await.ca_info(&handle).await),
        _ => render_unknown_method(),
    }
}

async fn ca_my_parent_contact(req: Request, ca: Handle, parent: ParentHandle) -> RoutingResult {
    render_json_res(req.state().read().await.ca_my_parent_contact(&ca, &parent).await)
}

async fn ca_my_parent_statuses(req: Request, ca: Handle) -> RoutingResult {
    render_json_res(req.state().read().await.ca_my_parent_statuses(&ca).await)
}

async fn ca_children(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.path_arg() {
        Some(child) => match path.next() {
            None => match *req.method() {
                Method::GET => ca_child_show(req, ca, child).await,
                Method::POST => ca_child_update(req, ca, child).await,
                Method::DELETE => ca_child_remove(req, ca, child).await,
                _ => render_unknown_method(),
            },
            Some("contact") => ca_parent_contact(req, ca, child).await,
            Some("parent_response.json") => ca_parent_res_json(req, ca, child).await,
            Some("parent_response.xml") => ca_parent_res_xml(req, ca, child).await,
            _ => render_unknown_method(),
        },
        None => match *req.method() {
            Method::POST => ca_add_child(req, ca).await,
            _ => render_unknown_method(),
        },
    }
}

async fn ca_history(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    let crit = match parse_history_path(path) {
        Some(crit) => crit,
        None => return render_unknown_method(),
    };

    match *req.method() {
        Method::GET => match req.state().read().await.ca_history(&handle, crit).await {
            Some(history) => render_json(history),
            None => render_unknown_resource(),
        },
        _ => render_unknown_method(),
    }
}

fn parse_history_path(path: &mut RequestPath) -> Option<CommandHistoryCriteria> {
    // /api/v1/cas/{ca}/history/short|full/<rows>/<offset>/<after>/<before>
    let mut crit = CommandHistoryCriteria::default();

    match path.next() {
        Some("short") => crit.set_excludes(&["cmd-ca-publish"]),
        Some("full") => {}
        _ => return None,
    };

    if let Some(rows) = path.path_arg() {
        crit.set_rows(rows);
    } else {
        return Some(crit);
    }

    if let Some(offset) = path.path_arg() {
        crit.set_offset(offset);
    } else {
        return Some(crit);
    }

    if let Some(after) = path.path_arg() {
        crit.set_after(after);
    } else {
        return Some(crit);
    }

    if let Some(before) = path.path_arg() {
        crit.set_before(before);
    }

    Some(crit)
}

async fn ca_command_details(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    // /api/v1/cas/{ca}/command/<command-key>
    match path.path_arg() {
        Some(key) => match *req.method() {
            Method::GET => match req.state().read().await.ca_command_details(&handle, key) {
                Ok(Some(details)) => render_json(details),
                Ok(None) => render_unknown_resource(),
                Err(e) => render_error(e),
            },
            _ => render_unknown_method(),
        },
        None => render_unknown_resource(),
    }
}

async fn ca_child_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => match ca_child_req(&req, &handle).await {
            Ok(req) => Ok(HttpResponse::xml(req.encode_vec())),
            Err(e) => render_error(e),
        },
        _ => render_unknown_method(),
    }
}

async fn ca_child_req_json(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => match ca_child_req(&req, &handle).await {
            Ok(req) => render_json(req),
            Err(e) => render_error(e),
        },
        _ => render_unknown_method(),
    }
}

async fn ca_child_req(req: &Request, handle: &Handle) -> Result<rfc8183::ChildRequest, Error> {
    req.state().read().await.ca_child_req(handle).await
}

async fn ca_publisher_req_json(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => match req.state().read().await.ca_publisher_req(&handle).await {
            Some(req) => render_json(req),
            None => render_unknown_resource(),
        },
        _ => render_unknown_method(),
    }
}

async fn ca_publisher_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => match req.state().read().await.ca_publisher_req(&handle).await {
            Some(req) => Ok(HttpResponse::xml(req.encode_vec())),
            None => render_unknown_resource(),
        },
        _ => render_unknown_method(),
    }
}

async fn ca_repo_details(req: Request, handle: Handle) -> RoutingResult {
    render_json_res(req.state().read().await.ca_repo_details(&handle).await)
}

async fn ca_repo_status(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => render_json_res(req.state().read().await.ca_repo_status(&handle).await),
        _ => render_unknown_method(),
    }
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

pub async fn ca_repo_update(req: Request, handle: Handle) -> RoutingResult {
    let server = req.state().clone();

    match req
        .api_bytes()
        .await
        .map(|bytes| extract_repository_update(&handle, bytes))
    {
        Ok(Ok(update)) => render_empty_res(server.read().await.ca_update_repo(handle, update).await),
        Ok(Err(e)) | Err(e) => render_error(e),
    }
}

async fn ca_add_parent(req: Request, ca: Handle) -> RoutingResult {
    let server = req.state().clone();

    let parent_req = match req.json().await {
        Ok(req) => req,
        Err(e) => return render_error(e),
    };

    match ca_parent_add(server, ca, parent_req).await {
        Ok(()) => render_ok(),
        Err(e) => render_error(e),
    }
}

async fn ca_add_parent_xml(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    let server = req.state().clone();

    let parent = match path.path_arg() {
        Some(parent) => parent,
        None => return render_error(Error::ApiInvalidHandle),
    };

    let bytes = match req.api_bytes().await {
        Ok(bytes) => bytes,
        Err(e) => return render_error(e),
    };

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

    {
        match ca_parent_add(server, ca, parent_req).await {
            Ok(()) => render_ok(),
            Err(e) => render_error(e),
        }
    }
}

async fn ca_parent_add(server: State, ca: Handle, parent_req: ParentCaReq) -> Result<(), Error> {
    server.read().await.ca_parent_add(ca, parent_req).await
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

async fn ca_update_parent(req: Request, ca: Handle, parent: ParentHandle) -> RoutingResult {
    let server = req.state().clone();

    let bytes = match req.api_bytes().await {
        Ok(bytes) => bytes,
        Err(e) => return render_error(e),
    };

    match extract_parent_ca_contact(&ca, bytes) {
        Ok(contact) => {
            let res = server.read().await.ca_parent_update(ca, parent, contact).await;
            render_empty_res(res)
        }
        Err(e) => render_error(e),
    }
}

async fn ca_remove_parent(req: Request, ca: Handle, parent: Handle) -> RoutingResult {
    render_empty_res(req.state().read().await.ca_parent_remove(ca, parent).await)
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
async fn ca_kr_init(req: Request, handle: Handle) -> RoutingResult {
    render_empty_res(req.state().read().await.ca_keyroll_init(handle).await)
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
async fn ca_kr_activate(req: Request, handle: Handle) -> RoutingResult {
    render_empty_res(req.state().read().await.ca_keyroll_activate(handle).await)
}

/// Update the route authorizations for this CA
async fn ca_routes_update(req: Request, handle: Handle) -> RoutingResult {
    let state = req.state().clone();

    match req.json().await {
        Err(e) => render_error(e),
        Ok(updates) => render_empty_res(state.read().await.ca_routes_update(handle, updates).await),
    }
}

/// Tries an update. If the dry-run for it would be successful, and the analysis
/// for the resources in the update have no remaining invalids, apply it. Otherwise
/// return the analysis and a suggestion.
async fn ca_routes_try_update(req: Request, ca: Handle) -> RoutingResult {
    let state = req.state().clone();

    match req.json::<RoaDefinitionUpdates>().await {
        Err(e) => render_error(e),
        Ok(updates) => {
            let server = state.read().await;
            match server.ca_routes_bgp_dry_run(&ca, updates.clone()).await {
                Err(e) => {
                    // update was rejected, return error
                    render_error(e)
                }
                Ok(effect) => {
                    if !effect.contains_invalids() {
                        // no issues found, apply
                        render_empty_res(server.ca_routes_update(ca, updates).await)
                    } else {
                        // remaining invalids exist, advise user
                        let updates: RouteAuthorizationUpdates = updates.into();
                        let updates = updates.into_explicit();
                        let resources = updates.affected_prefixes();

                        match server.ca_routes_bgp_suggest(&ca, Some(resources)).await {
                            Err(e) => render_error(e), // should not fail after dry run, but hey..
                            Ok(suggestion) => render_json(BgpAnalysisAdvice::new(effect, suggestion)),
                        }
                    }
                }
            }
        }
    }
}

/// show the route authorizations for this CA
async fn ca_routes_show(req: Request, handle: Handle) -> RoutingResult {
    match req.state().read().await.ca_routes_show(&handle).await {
        Ok(roas) => render_json(roas),
        Err(_) => render_unknown_resource(),
    }
}

/// Show the state of ROAs vs BGP for this CA
async fn ca_routes_analysis(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    match path.next() {
        Some("full") => render_json_res(req.state().read().await.ca_routes_bgp_analysis(&handle).await),
        Some("dryrun") => match *req.method() {
            Method::POST => {
                let state = req.state.clone();
                match req.json().await {
                    Err(e) => render_error(e),
                    Ok(updates) => render_json_res(state.read().await.ca_routes_bgp_dry_run(&handle, updates).await),
                }
            }
            _ => render_unknown_method(),
        },
        Some("suggest") => match *req.method() {
            Method::GET => render_json_res(req.state().read().await.ca_routes_bgp_suggest(&handle, None).await),
            Method::POST => {
                let server = req.state().clone();
                match req.json().await {
                    Err(e) => render_error(e),
                    Ok(resources) => render_json_res(
                        server
                            .read()
                            .await
                            .ca_routes_bgp_suggest(&handle, Some(resources))
                            .await,
                    ),
                }
            }
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

//------------ Admin: Force republish ----------------------------------------

async fn republish_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => render_empty_res(req.state().read().await.republish_all().await),
        _ => render_unknown_method(),
    }
}

async fn resync_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => render_empty_res(req.state().read().await.resync_all().await),
        _ => render_unknown_method(),
    }
}

/// Refresh all CAs
async fn refresh_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => render_empty_res(req.state().read().await.refresh_all().await),
        _ => render_unknown_method(),
    }
}

//------------ Serve RRDP Files ----------------------------------------------

async fn rrdp(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/rrdp/") {
        Err(req) // Not for us
    } else {
        let mut full_path: PathBuf = req.state.read().await.rrdp_base_path();
        let (_, path) = req.path.remaining().split_at(1);
        let cache_seconds = if path.ends_with("notification.xml") { 60 } else { 86400 };
        full_path.push(path);

        match File::open(full_path) {
            Ok(mut file) => {
                use std::io::Read;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).unwrap();

                Ok(HttpResponse::xml_with_cache(buffer, cache_seconds))
            }
            _ => Ok(HttpResponse::not_found()),
        }
    }
}

//------------ Support Resource Tagged Attestations (RTA) ----------------------

async fn api_ca_rta(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.path_arg() {
        Some(name) => match *req.method() {
            Method::POST => match path.next() {
                Some("sign") => api_ca_rta_sign(req, ca, name).await,
                Some("multi") => match path.next() {
                    Some("prep") => api_ca_rta_multi_prep(req, ca, name).await,
                    Some("cosign") => api_ca_rta_multi_sign(req, ca, name).await,
                    _ => render_unknown_method(),
                },
                _ => render_unknown_method(),
            },
            Method::GET => {
                if name.is_empty() {
                    api_ca_rta_list(req, ca).await
                } else {
                    api_ca_rta_show(req, ca, name).await
                }
            }
            _ => render_unknown_method(),
        },
        None => match *req.method() {
            Method::GET => api_ca_rta_list(req, ca).await,
            _ => render_unknown_method(),
        },
    }
}

async fn api_ca_rta_list(req: Request, ca: Handle) -> RoutingResult {
    render_json_res(req.state().read().await.rta_list(ca).await)
}

async fn api_ca_rta_show(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    render_json_res(req.state().read().await.rta_show(ca, name).await)
}

async fn api_ca_rta_sign(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    let state = req.state().clone();
    match req.json().await {
        Err(e) => render_error(e),
        Ok(request) => render_empty_res(state.read().await.rta_sign(ca, name, request).await),
    }
}

async fn api_ca_rta_multi_prep(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    let state = req.state().clone();

    match req.json().await {
        Ok(resources) => render_json_res(state.read().await.rta_multi_prep(ca, name, resources).await),
        Err(e) => render_error(e),
    }
}

//------------ Support acting as a testbed -------------------------------------
//
// Testbed mode enables Krill to run as an open root of a test RPKI hierarchy
// with web-UI based self-service ability for other RPKI certificate authorities
// to integrate themselves into the test RPKI hierarchy, both as children whose
// resources are delegated from the testbed and as publishers into the testbed
// repository. This feature is very similar to existing web-UI based
// self-service RPKI test hierarchies such as the RIPE NCC RPKI Test Environment
// and the APNIC RPKI Testbed.
//
// Krill can already do this via a combination of use_ta=true and the existing
// Krill API _but_ crucially the other RPKI certificate authorities would need
// to know the Krill API token in order to register themselves with the Krill
// testbed, giving them far too much power over the testbed. Testbed mode
// exposes *open* /testbed/xxx wrapper API endpoints for exchanging the RFC 8183
// XMLs, e.g.:
//
//   /testbed/enabled:    should the web-UI show the testbed UI page?
//   /testbed/children:   <client_request/> in, <parent_response/> out
//   /testbed/publishers: <publisher_request/> in, <repository_response/> out
//
// This feature assumes the existence of a built-in "testbed" CA and publisher
// when testbed mode is enabled.

async fn testbed(req: Request) -> RoutingResult {
    if !CONFIG.testbed_enabled {
        Err(req) // Not for us
    } else {
        let mut path = req.path().clone();
        match path.next() {
            Some("enabled") => testbed_enabled(req).await,
            Some("children") => testbed_children(req, &mut path).await,
            Some("publishers") => testbed_publishers(req, &mut path).await,
            _ => render_unknown_method(),
        }
    }
}

// Is the testbed feature enabled or not? used by the web-UI to conditionally
// enable the testbed web-UI.
async fn testbed_enabled(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => render_ok(),
        _ => render_unknown_method(),
    }
}

// Open (token-less) addition/removal of child CAs under the testbed CA.
// Note: Anyone can request any resources irrespective of the resources they
// have the rights to in the real global RPKI hierarchy and anyone can
// unregister any child CA even if not "owned" by them.
async fn testbed_children(req: Request, path: &mut RequestPath) -> RoutingResult {
    match (req.method().clone(), path.path_arg()) {
        (Method::GET, Some(child)) => match path.next() {
            Some("parent_response.xml") => ca_parent_res_xml(req, testbed_ca_handle(), child).await,
            _ => render_unknown_method(),
        },
        (Method::DELETE, Some(child)) => ca_child_remove(req, testbed_ca_handle(), child).await,
        (Method::POST, None) => ca_add_child(req, testbed_ca_handle()).await,
        _ => render_unknown_method(),
    }
}

// Open (token-less) addition/removal of publishers to the testbed repository.
// Note: Anyone can become a publisher and anyone can unregister a publisher
// even if not "owned" by them.
async fn testbed_publishers(req: Request, path: &mut RequestPath) -> RoutingResult {
    match (req.method().clone(), path.path_arg()) {
        (Method::GET, Some(publisher)) => match path.next() {
            Some("response.xml") => repository_response_xml(req, publisher).await,
            _ => render_unknown_method(),
        },
        (Method::DELETE, Some(publisher)) => testbed_remove_pbl(req, publisher).await,
        (Method::POST, None) => add_pbl(req).await,
        _ => render_unknown_method(),
    }
}

// Prevent deletion of the built-in TA and testbed repositories.
async fn testbed_remove_pbl(req: Request, publisher: Handle) -> RoutingResult {
    if publisher == ta_handle() || publisher == testbed_ca_handle() {
        Ok(HttpResponse::forbidden())
    } else {
        remove_pbl(req, publisher).await
    }
}

async fn api_ca_rta_multi_sign(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    let state = req.state().clone();
    match req.json().await {
        Ok(rta) => render_empty_res(state.read().await.rta_multi_cosign(ca, name, rta).await),
        Err(_) => render_error(Error::custom("Cannot decode RTA for co-signing")),
    }
}

//------------ Tests ---------------------------------------------------------
#[cfg(test)]
mod tests {

    // NOTE: This is extensively tested through the functional and e2e tests found under
    //       the $project/tests dir

    use std::path::PathBuf;

    use crate::test;

    use super::*;
    use crate::constants::KRILL_ENV_TEST_UNIT_DATA;

    #[tokio::test]
    async fn start_tls_server() {
        let dir = test::sub_dir(&PathBuf::from("work"));

        let data_dir = test::sub_dir(&dir);
        env::set_var(KRILL_ENV_TEST_UNIT_DATA, data_dir.to_string_lossy().to_string());

        tokio::spawn(super::start());

        assert!(test::server_ready().await);
    }
}
