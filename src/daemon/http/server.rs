//! Hyper based HTTP server for Krill.
//!
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use serde::Serialize;

use futures::TryFutureExt;
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::Method;

use crate::commons::api::{ParentCaReq, ParentStatuses, RepoStatus, RepositoryContact};
use crate::commons::bgp::BgpAnalysisAdvice;
use crate::commons::error::Error;
use crate::commons::eventsourcing::AggregateStoreError;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::commons::KrillResult;
use crate::constants::{
    KRILL_ENV_UPGRADE_ONLY, KRILL_VERSION_MAJOR, KRILL_VERSION_MINOR, KRILL_VERSION_PATCH, NO_RESOURCE,
};
use crate::daemon::auth::common::permissions::Permission;
use crate::daemon::auth::Auth;
use crate::daemon::ca::{RouteAuthorizationUpdates, TA_NAME};
use crate::daemon::config::Config;
use crate::daemon::http::auth::auth;
use crate::daemon::http::statics::statics;
use crate::daemon::http::testbed::testbed;
use crate::daemon::http::{tls, tls_keys, HttpResponse, Request, RequestPath, RoutingResult};
use crate::daemon::krillserver::KrillServer;
use crate::upgrades::{pre_start_upgrade, update_storage_version};
use crate::{
    commons::api::{
        BgpStats, ChildHandle, CommandHistoryCriteria, Handle, ParentCaContact, ParentHandle, PublisherList,
        RoaDefinitionUpdates, RtaName, Token,
    },
    constants::KRILL_ENV_HTTP_LOG_INFO,
};

//------------ State -----------------------------------------------------

pub type State = Arc<KrillServer>;

pub fn parse_config() -> KrillResult<Config> {
    Config::create().map_err(|e| Error::Custom(format!("Could not parse config: {}", e)))
}

fn print_write_error_hint_and_die(error_msg: String) {
    eprintln!("{}", error_msg);
    eprintln!();
    eprintln!("Hint: if you use systemd you may need to override the allowed ReadWritePaths,");
    eprintln!("the easiest way may be by doing 'systemctl edit krill' and add a section like:");
    eprintln!();
    eprintln!("[Service]");
    eprintln!("ReadWritePaths=/local/path1 /local/path2 ...");
}

fn write_pid_file_or_die(config: &Config) {
    let pid_file = config.pid_file();
    if let Err(e) = file::save(process::id().to_string().as_bytes(), &pid_file) {
        print_write_error_hint_and_die(format!("Could not write PID file: {}", e));
    }
}

fn test_data_dir_or_die(config_item: &str, dir: &Path) {
    let test_file = dir.join("test");

    if let Err(e) = file::save(b"test", &test_file) {
        print_write_error_hint_and_die(format!(
            "Cannot write to dir '{}' for configuration setting '{}', Error: {}",
            dir.to_string_lossy(),
            config_item,
            e
        ));
    } else if let Err(e) = file::delete_file(&test_file) {
        print_write_error_hint_and_die(format!(
            "Cannot delete test file '{}' in dir for configuration setting '{}', Error: {}",
            test_file.to_string_lossy(),
            config_item,
            e
        ));
    }
}

fn test_data_dirs_or_die(config: &Config) {
    test_data_dir_or_die("data_dir", &config.data_dir);
    if let Some(rfc8181_log_dir) = &config.rfc8181_log_dir {
        test_data_dir_or_die("rfc8181_log_dir", rfc8181_log_dir);
    }
    if let Some(rfc6492_log_dir) = &config.rfc6492_log_dir {
        test_data_dir_or_die("rfc6492_log_dir", rfc6492_log_dir);
    }
}

pub async fn start_krill_daemon(config: Arc<Config>) -> Result<(), Error> {
    write_pid_file_or_die(&config);
    test_data_dirs_or_die(&config);

    // Call upgrade, this will only do actual work if needed.
    pre_start_upgrade(config.clone()).map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))?;

    // Create the server, this will create the necessary data sub-directories if needed
    let krill = KrillServer::build(config.clone()).await?;

    // Update the version identifiers for the storage dirs
    update_storage_version(&config.data_dir)
        .map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))
        .await?;

    // If the operator wanted to do the upgrade only, now is a good time to report success and stop
    if env::var(KRILL_ENV_UPGRADE_ONLY).is_ok() {
        println!("Krill upgrade successful");
    }

    // Reset the RRDP session after a restart.
    krill.repository_session_reset()?;

    let state = Arc::new(krill);

    let service = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: hyper::Request<hyper::Body>| {
                let state = state.clone();
                map_requests(req, state)
            }))
        }
    });

    tls_keys::create_key_cert_if_needed(&config.data_dir).map_err(|e| Error::HttpsSetup(format!("{}", e)))?;

    let server_config_builder = tls::TlsConfigBuilder::new()
        .cert_path(tls_keys::cert_file_path(&config.data_dir))
        .key_path(tls_keys::key_file_path(&config.data_dir));
    let server_config = server_config_builder.build().unwrap();

    let incoming = AddrIncoming::bind(&config.socket_addr()).map_err(|e| {
        Error::Custom(format!(
            "Could not bind to address and port: {}, Error: {}",
            &config.socket_addr(),
            e
        ))
    })?;

    let acceptor = tls::TlsAcceptor::new(server_config, incoming);

    let server = hyper::Server::builder(acceptor)
        .serve(service)
        .map_err(|e| eprintln!("Server error: {}", e));

    if server.await.is_err() {
        eprintln!("Krill failed to start");
    }

    Ok(())
}

struct RequestLogger {
    req_method: hyper::Method,
    req_path: String,
}

impl RequestLogger {
    fn begin(req: &hyper::Request<hyper::Body>) -> Self {
        let req_method = req.method().clone();
        let req_path = RequestPath::from_request(req).full().to_string();

        if log_enabled!(log::Level::Trace) {
            trace!(
                "Request: method={} path={} headers={:?}",
                &req_method,
                &req_path,
                &req.headers()
            );
        }

        RequestLogger { req_method, req_path }
    }

    fn end(&self, res: Result<&HttpResponse, &Error>) {
        match res {
            Ok(response) => {
                match (response.status(), response.benign(), response.cause()) {
                    (s, false, Some(cause)) if s.is_client_error() => warn!("HTTP {}: {}", s.as_u16(), cause),
                    (s, false, Some(cause)) if s.is_server_error() => error!("HTTP {}: {}", s.as_u16(), cause),
                    _ => {}
                }

                if env::var(KRILL_ENV_HTTP_LOG_INFO).is_ok() {
                    info!("{} {} {}", self.req_method, self.req_path, response.status());
                } else {
                    debug!("{} {} {}", self.req_method, self.req_path, response.status());
                }
                if response.loggable() && log_enabled!(log::Level::Trace) {
                    trace!("Response: headers={:?} body={:?}", response.headers(), response.body());
                }
            }
            Err(err) => {
                error!("{} {} Error: {}", self.req_method, self.req_path, err);
            }
        }
    }
}

async fn map_requests(req: hyper::Request<hyper::Body>, state: State) -> Result<hyper::Response<hyper::Body>, Error> {
    let logger = RequestLogger::begin(&req);

    let req = Request::new(req, state).await;

    // Save any updated auth details, e.g. if an OpenID Connect token needed
    // refreshing.
    let new_auth = req.actor().new_auth();

    // We used to use .or_else() here but that causes a large recursive call
    // tree due to these calls being to async functions, large enough with the
    // given Request object passed each time that it eventually resulted in
    // stack overflow. By doing it by hand like this we avoid the use of the
    // macros that cause the recursion. We could also look at putting less data
    // on the stack.
    let mut res = api(req).await;
    if let Err(req) = res {
        res = auth(req).await;
    }
    if let Err(req) = res {
        res = health(req).await;
    }
    if let Err(req) = res {
        res = metrics(req).await;
    }
    if let Err(req) = res {
        res = stats(req).await;
    }
    if let Err(req) = res {
        res = rfc8181(req).await;
    }
    if let Err(req) = res {
        res = rfc6492(req).await;
    }
    if let Err(req) = res {
        res = statics(req).await;
    }
    if let Err(req) = res {
        res = ta(req).await;
    }
    if let Err(req) = res {
        res = rrdp(req).await;
    }
    if let Err(req) = res {
        res = testbed(req).await;
    }
    if let Err(req) = res {
        res = render_not_found(req).await;
    }

    let res = res.map_err(|_| Error::custom("should have received not found response"));

    // Augment the response with any updated auth details that were determined
    // above.
    let res = add_new_auth_to_response(res, new_auth);

    // Log the request and the response.
    logger.end(res.as_ref());

    res.map(|res| res.response())
}

//------------ Support Functions ---------------------------------------------

/// HTTP redirects cannot have a response body and so we cannot render the error
/// to be displayed in Lagosta as a JSON body, instead we must package the JSON
/// as a query parameter.
pub fn render_error_redirect(err: Error) -> RoutingResult {
    let response = err.to_error_response();
    let json = serde_json::to_string(&response).or_else(|err| {
        Ok(format!(
            "JSON serialization error while processing internal error: {}",
            err
        ))
    })?;
    let b64 = base64::encode(json);
    let location = format!("/index.html#/login?error={}", b64);
    Ok(HttpResponse::found(&location))
}

pub fn render_empty_res(res: Result<(), Error>) -> RoutingResult {
    match res {
        Ok(()) => render_ok(),
        Err(e) => render_error(e),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn render_error(e: Error) -> RoutingResult {
    debug!("Server Error: {}", e);
    Ok(HttpResponse::response_from_error(e))
}

#[allow(clippy::unnecessary_wraps)]
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
#[allow(clippy::unnecessary_wraps)]
fn render_unknown_resource() -> RoutingResult {
    Ok(HttpResponse::response_from_error(Error::ApiUnknownResource))
}

/// A clean 200 result for the API (no content, not for humans)
#[allow(clippy::unnecessary_wraps)]
pub fn render_ok() -> RoutingResult {
    Ok(HttpResponse::ok())
}

#[allow(clippy::unnecessary_wraps)]
pub fn render_unknown_method() -> RoutingResult {
    Ok(HttpResponse::response_from_error(Error::ApiUnknownMethod))
}

/// A clean 404 response
#[allow(clippy::unnecessary_wraps)]
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
        res.push('\n');

        res.push_str("# HELP krill_version_major krill server major version number\n");
        res.push_str("# TYPE krill_version_major gauge\n");
        res.push_str(&format!("krill_version_major {}\n", KRILL_VERSION_MAJOR));
        res.push('\n');

        res.push_str("# HELP krill_version_minor krill server minor version number\n");
        res.push_str("# TYPE krill_version_minor gauge\n");
        res.push_str(&format!("krill_version_minor {}\n", KRILL_VERSION_MINOR));
        res.push('\n');

        res.push_str("# HELP krill_version_patch krill server patch version number\n");
        res.push_str("# TYPE krill_version_patch gauge\n");
        res.push_str(&format!("krill_version_patch {}\n", KRILL_VERSION_PATCH));

        if let Ok(stats) = server.repo_stats() {
            let publishers = stats.get_publishers();

            res.push('\n');
            res.push_str("# HELP krill_repo_publisher number of publishers in repository\n");
            res.push_str("# TYPE krill_repo_publisher gauge\n");
            res.push_str(&format!("krill_repo_publisher {}\n", publishers.len()));

            if let Some(last_update) = stats.last_update() {
                res.push('\n');
                res.push_str("# HELP krill_repo_rrdp_last_update timestamp of last update by any publisher\n");
                res.push_str("# TYPE krill_repo_rrdp_last_update gauge\n");
                res.push_str(&format!("krill_repo_rrdp_last_update {}\n", last_update.timestamp()));
            }

            res.push('\n');
            res.push_str("# HELP krill_repo_rrdp_serial RRDP serial\n");
            res.push_str("# TYPE krill_repo_rrdp_serial counter\n");
            res.push_str(&format!("krill_repo_rrdp_serial {}\n", stats.serial()));

            res.push('\n');
            res.push_str("# HELP krill_repo_objects number of objects in repository for publisher\n");
            res.push_str("# TYPE krill_repo_objects gauge\n");
            for (publisher, stats) in publishers {
                res.push_str(&format!(
                    "krill_repo_objects{{publisher=\"{}\"}} {}\n",
                    publisher,
                    stats.objects()
                ));
            }

            res.push('\n');
            res.push_str("# HELP krill_repo_size size of objects in bytes in repository for publisher\n");
            res.push_str("# TYPE krill_repo_size gauge\n");
            for (publisher, stats) in publishers {
                res.push_str(&format!(
                    "krill_repo_size{{publisher=\"{}\"}} {}\n",
                    publisher,
                    stats.size()
                ));
            }

            res.push('\n');
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

        if let Ok(cas_status) = server.cas_stats().await {
            let number_cas = cas_status.len();

            res.push('\n');
            res.push_str("# HELP krill_cas number of cas in krill\n");
            res.push_str("# TYPE krill_cas gauge\n");
            res.push_str(&format!("krill_cas {}\n", number_cas));

            res.push('\n');
            res.push_str("# HELP krill_cas_roas number of roas for CA\n");
            res.push_str("# TYPE krill_cas_roas gauge\n");
            for (ca, status) in cas_status.iter() {
                res.push_str(&format!("krill_cas_roas{{ca=\"{}\"}} {}\n", ca, status.roa_count()));
            }

            res.push('\n');
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

            let mut ca_parent_statuses: HashMap<Handle, ParentStatuses> = HashMap::new();
            let mut ca_repo_status: HashMap<Handle, RepoStatus> = HashMap::new();

            for (ca, status) in cas_status.iter() {
                all_bgp_stats.add_ca(ca, status.bgp_stats());

                if let Ok(parent_statuses) = server.ca_my_parent_statuses(ca).await {
                    ca_parent_statuses.insert(ca.clone(), parent_statuses);
                }

                if let Ok(repo_status) = server.ca_repo_status(ca).await {
                    ca_repo_status.insert(ca.clone(), repo_status);
                }
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_announcements_valid number of announcements seen for CA resources with RPKI state VALID\n");
            res.push_str("# TYPE krill_cas_bgp_announcements_valid gauge\n");
            for (ca, nr) in all_bgp_stats.announcements_valid.iter() {
                res.push_str(&format!("krill_cas_bgp_announcements_valid{{ca=\"{}\"}} {}\n", ca, nr));
            }

            res.push('\n');
            res.push_str("# HELP krill_ca_parent_success status of last ca-parent connection (0=issue, 1=success)\n");
            res.push_str("# TYPE krill_ca_parent_success gauge\n");
            for (ca, parent_statuses) in ca_parent_statuses.iter() {
                if ca.as_str() != TA_NAME {
                    for (parent, status) in parent_statuses.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.
                        if let Some(exchange) = status.last_exchange() {
                            let value = if exchange.was_success() { 1 } else { 0 };
                            res.push_str(&format!(
                                "krill_ca_parent_success{{ca=\"{}\", parent=\"{}\"}} {}\n",
                                ca, parent, value
                            ));
                        }
                    }
                }
            }

            res.push('\n');
            res.push_str(
                "# HELP krill_ca_parent_last_success_time timestamp of last successful ca-parent connection\n",
            );
            res.push_str("# TYPE krill_ca_parent_last_success_time gauge\n");

            for (ca, parent_statuses) in ca_parent_statuses.iter() {
                if ca.as_str() != TA_NAME {
                    for (parent, status) in parent_statuses.iter() {
                        // skip the ones for which we have no successful connection at all. Most likely
                        // they were just added (in which case it will come) - or were never successful
                        // in which case the metric above will say that the status is 0
                        if let Some(last_success) = status.last_success() {
                            res.push_str(&format!(
                                "krill_ca_parent_last_success_time{{ca=\"{}\", parent=\"{}\"}} {}\n",
                                ca,
                                parent,
                                last_success.timestamp()
                            ));
                        }
                    }
                }
            }

            {
                // CA -> Repository status

                res.push('\n');
                res.push_str("# HELP krill_ca_repo_success status of last ca to publication server connection (0=issue, 1=success)\n");
                res.push_str("# TYPE krill_ca_repo_success gauge\n");
                for (ca, status) in ca_repo_status.iter() {
                    // skip the ones for which we have no status yet, i.e it was really only just added
                    // and no attempt to connect has yet been made.
                    if let Some(exchange) = status.last_exchange() {
                        let value = if exchange.was_success() { 1 } else { 0 };
                        res.push_str(&format!("krill_ca_repo_success{{ca=\"{}\"}} {}\n", ca, value));
                    }
                }

                res.push('\n');
                res.push_str("# HELP krill_ca_repo_last_success_time timestamp of last successful ca to publication server connection\n");
                res.push_str("# TYPE krill_ca_repo_last_success_time gauge\n");
                for (ca, status) in ca_repo_status.iter() {
                    // skip the ones for which we have no status yet, i.e it was really only just added
                    // and no attempt to connect has yet been made.
                    if let Some(last_success) = status.last_success() {
                        res.push_str(&format!(
                            "krill_ca_repo_last_success_time{{ca=\"{}\"}} {}\n",
                            ca,
                            last_success.timestamp()
                        ));
                    }
                }

                res.push('\n');
                res.push_str("# HELP krill_ca_repo_next_before_time timestamp of next planned ca to publication server connection\n");
                res.push_str("# TYPE krill_ca_repo_next_before_time gauge\n");
                for (ca, status) in ca_repo_status.iter() {
                    // skip the ones for which we have no status yet, i.e it was really only just added
                    // and no attempt to connect has yet been made.
                    let timestamp = status.next_exchange_before().timestamp();
                    res.push_str(&format!(
                        "krill_ca_repo_next_before_time{{ca=\"{}\"}} {}\n",
                        ca, timestamp
                    ));
                }
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_announcements_invalid_asn number of announcements seen for CA resources with RPKI state INVALID (ASN mismatch)\n");
            res.push_str("# TYPE krill_cas_bgp_announcements_invalid_asn gauge\n");
            for (ca, nr) in all_bgp_stats.announcements_invalid_asn.iter() {
                res.push_str(&format!(
                    "krill_cas_bgp_announcements_invalid_asn{{ca=\"{}\"}} {}\n",
                    ca, nr
                ));
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_announcements_invalid_length number of announcements seen for CA resources with RPKI state INVALID (prefix exceeds max length)\n");
            res.push_str("# TYPE krill_cas_bgp_announcements_invalid_length gauge\n");
            for (ca, nr) in all_bgp_stats.announcements_invalid_length.iter() {
                res.push_str(&format!(
                    "krill_cas_bgp_announcements_invalid_length{{ca=\"{}\"}} {}\n",
                    ca, nr
                ));
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_announcements_not_found number of announcements seen for CA resources with RPKI state NOT FOUND (none of the CA's ROAs cover this)\n");
            res.push_str("# TYPE krill_cas_bgp_announcements_not_found gauge\n");
            for (ca, nr) in all_bgp_stats.announcements_not_found.iter() {
                res.push_str(&format!(
                    "krill_cas_bgp_announcements_not_found{{ca=\"{}\"}} {}\n",
                    ca, nr
                ));
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_roas_too_permissive number of ROAs for this CA which allow excess announcements (0 may also indicate that no BGP info is available)\n");
            res.push_str("# TYPE krill_cas_bgp_roas_too_permissive gauge\n");
            for (ca, nr) in all_bgp_stats.roas_too_permissive.iter() {
                res.push_str(&format!("krill_cas_bgp_roas_too_permissive{{ca=\"{}\"}} {}\n", ca, nr));
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_roas_redundant number of ROAs for this CA which are redundant (0 may also indicate that no BGP info is available)\n");
            res.push_str("# TYPE krill_cas_bgp_roas_redundant gauge\n");
            for (ca, nr) in all_bgp_stats.roas_redundant.iter() {
                res.push_str(&format!("krill_cas_bgp_roas_redundant{{ca=\"{}\"}} {}\n", ca, nr));
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_roas_stale number of ROAs for this CA for which no announcements are seen (0 may also indicate that no BGP info is available)\n");
            res.push_str("# TYPE krill_cas_bgp_roas_stale gauge\n");
            for (ca, nr) in all_bgp_stats.roas_stale.iter() {
                res.push_str(&format!("krill_cas_bgp_roas_stale{{ca=\"{}\"}} {}\n", ca, nr));
            }

            res.push('\n');
            res.push_str("# HELP krill_cas_bgp_roas_total total number of ROAs for this CA\n");
            res.push_str("# TYPE krill_cas_bgp_roas_stale gauge\n");
            for (ca, nr) in all_bgp_stats.roas_total.iter() {
                res.push_str(&format!("krill_cas_bgp_roas_total{{ca=\"{}\"}} {}\n", ca, nr));
            }
        }

        #[cfg(feature = "multi-user")]
        {
            res.push('\n');
            res.push_str("# HELP krill_auth_session_cache_size total number of cached login session tokens\n");
            res.push_str("# TYPE krill_auth_session_cache_size gauge\n");
            res.push_str(&format!(
                "krill_auth_session_cache_size {}\n",
                server.login_session_cache_size()
            ));
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

        match state.rfc8181(publisher, bytes) {
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
            "/testbed.tal" => tal(req).await,
            "/ta/ta.cer" => ta_cer(req).await,
            _ => Err(req),
        },
        _ => Err(req),
    }
}

pub async fn tal(req: Request) -> RoutingResult {
    match req.state().ta().await {
        Ok(ta) => Ok(HttpResponse::text(format!("{}", ta.tal()).into_bytes())),
        Err(_) => render_unknown_resource(),
    }
}

pub async fn ta_cer(req: Request) -> RoutingResult {
    match req.state().trust_anchor_cert().await {
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

        let actor = req.actor();
        let state = req.state().clone();
        let user_agent = req.user_agent();

        let bytes = match req.rfc6492_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };
        let krill_server = state;
        match krill_server.rfc6492(ca, bytes, user_agent, &actor).await {
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
            "/stats/info" => render_json(req.state().server_info()),
            "/stats/repo" => render_json_res(req.state().repo_stats()),
            "/stats/cas" => render_json_res(req.state().cas_stats().await),
            _ => Err(req),
        },
        _ => Err(req),
    }
}

// Suppress any error in the unlikely event that we fail to inject the
// Authorization header into the HTTP response as this is an internal error that
// we should shield the user from, but log a warning as this is very unexpected.
fn add_authorization_headers_to_response(org_response: HttpResponse, token: Token) -> HttpResponse {
    let mut new_header_names = Vec::new();
    let mut new_header_values = Vec::new();

    new_header_names.push(HeaderName::from_str("Authorization"));
    new_header_values.push(HeaderValue::from_str(&format!("Bearer {}", &token)));

    let okay = !new_header_names
        .iter()
        .zip(new_header_values.iter())
        .any(|(n, v)| n.is_err() | v.is_err());

    if okay {
        let (parts, body) = org_response.response().into_parts();
        let mut augmented_response = hyper::Response::from_parts(parts, body);
        let headers = augmented_response.headers_mut();
        for (name, value) in new_header_names.into_iter().zip(new_header_values.into_iter()) {
            headers.insert(name.unwrap(), value.unwrap());
        }
        HttpResponse::new(augmented_response)
    } else {
        let mut conversion_errors = Vec::new();
        conversion_errors.extend(
            new_header_names
                .into_iter()
                .filter(|result| result.is_err())
                .map(|i| i.unwrap_err().to_string()),
        );
        conversion_errors.extend(
            new_header_values
                .into_iter()
                .filter(|result| result.is_err())
                .map(|i| i.unwrap_err().to_string()),
        );
        warn!(
            "Internal error: unable to add refreshed auth token to the response: {:?}",
            conversion_errors.join(", ")
        );
        org_response
    }
}

fn add_new_auth_to_response(res: Result<HttpResponse, Error>, opt_auth: Option<Auth>) -> Result<HttpResponse, Error> {
    if let Some(Auth::Bearer(token)) = opt_auth {
        res.map(|ok_res| add_authorization_headers_to_response(ok_res, token))
    } else {
        res
    }
}

// aa! macro aka if-authorized-then-run-the-given-code-else-return-http-403
// ------------------------------------------------------------------------
// This macro handles returning from API handler functions if the request is not
// Authenticated or lacks sufficient Authorization. We don't use a normal fn for
// this as then each API handler function would have to also test for success or
// failure and also return the forbidden response to the caller, That would be
// both verbose and repetitive. We also can't use the ? operator to return Err
// as Err is used to propagate the request to the next handler in the chain. If
// we had a child crate we could use a proc macro instead so that we could
// "annotate" each API handler function with something like:
//   #[require_permission(CA_CREATE)]
// Which would insert the generated code at the start of the function body,
// similar to how this macro is used in each function.
macro_rules! aa {
    (no_warn $req:ident, $perm:expr, $action:expr) => {{
        aa!($req, $perm, NO_RESOURCE, $action, true)
    }};
    ($req:ident, $perm:expr, $action:expr) => {{
        aa!($req, $perm, NO_RESOURCE, $action, false)
    }};
    (no_warn $req:ident, $perm:expr, $resource:expr, $action:expr) => {{
        aa!($req, $perm, $resource, $action, true)
    }};
    ($req:ident, $perm:expr, $resource:expr, $action:expr) => {{
        aa!($req, $perm, $resource, $action, false)
    }};
    ($req:ident, $perm:expr, $resource:expr, $action:expr, $benign:expr) => {{
        match $req.actor().is_allowed($perm, $resource) {
            Ok(true) => $action,
            Ok(false) => {
                let msg = format!(
                    "User '{}' does not have permission '{}' on resource '{}'",
                    $req.actor().name(),
                    $perm,
                    $resource
                );
                Ok(HttpResponse::forbidden(msg).with_benign($benign))
            }
            Err(err) => {
                // Avoid an extra round of error -> string -> error conversion
                // which causes the error message to nest, e.g.
                //   "Invalid credentials: Invalid credentials: Session expired"
                match err {
                    Error::ApiInvalidCredentials(_)
                    | Error::ApiInsufficientRights(_)
                    | Error::ApiAuthPermanentError(_)
                    | Error::ApiAuthTransientError(_)
                    | Error::ApiAuthSessionExpired(_)
                    | Error::ApiLoginError(_) => Ok(HttpResponse::response_from_error(err).with_benign($benign)),
                    _ => Ok(HttpResponse::forbidden(format!("{}", err)).with_benign($benign)),
                }
            }
        }
    }};
}

/// Maps the API methods
async fn api(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/api/v1") {
        Err(req) // Not for us
    } else {
        // Eat the first two segments of the path "api/v1"
        let mut path = req.path().clone();
        path.next(); // gets 'v1' and drops it.

        match path.next() {
            Some("authorized") => api_authorized(req).await,
            restricted_endpoint => {
                // Make sure access is allowed
                aa!(req, Permission::LOGIN, {
                    match restricted_endpoint {
                        Some("bulk") => api_bulk(req, &mut path).await,
                        Some("cas") => api_cas(req, &mut path).await,
                        Some("pubd") => aa!(req, Permission::PUB_ADMIN, api_publication_server(req, &mut path).await),
                        _ => render_unknown_method(),
                    }
                })
            }
        }
    }
}

async fn api_authorized(req: Request) -> RoutingResult {
    // Use 'no_warn' to prevent the log being filled with warnings about
    // insufficient user rights as this API endpoint is invoked by Lagosta on
    // every view transition, and not being authorized is a valid state that
    // triggers Lagosta to show a login form, not something to warn about!
    aa!(no_warn
        req,
        Permission::LOGIN,
        match *req.method() {
            Method::GET => render_ok(),
            _ => render_unknown_method(),
        }
    )
}

async fn api_bulk(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.full() {
        "/api/v1/bulk/cas/issues" => api_all_ca_issues(req).await,
        "/api/v1/bulk/cas/sync/parent" => api_refresh_all(req).await,
        "/api/v1/bulk/cas/sync/repo" => api_resync_all(req).await,
        "/api/v1/bulk/cas/publish" => api_republish_all(req).await,
        _ => render_unknown_method(),
    }
}

async fn api_cas(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.path_arg::<Handle>() {
        Some(ca) => aa!(req, Permission::CA_READ, ca.clone(), {
            match path.next() {
                None => match *req.method() {
                    Method::GET => api_ca_info(req, ca).await,
                    Method::DELETE => api_ca_delete(req, ca).await,
                    _ => render_unknown_method(),
                },
                Some("children") => api_ca_children(req, path, ca).await,
                Some("history") => api_ca_history(req, path, ca).await,

                Some("id") => api_ca_id(req, path, ca).await,
                Some("issues") => api_ca_issues(req, ca).await,
                Some("keys") => api_ca_keys(req, path, ca).await,
                Some("parents") => api_ca_parents(req, path, ca).await,
                Some("repo") => api_ca_repo(req, path, ca).await,
                Some("routes") => api_ca_routes(req, path, ca).await,
                Some("stats") => api_ca_stats(req, path, ca).await,

                Some("rta") => api_ca_rta(req, path, ca).await,

                _ => render_unknown_method(),
            }
        }),
        None => match *req.method() {
            Method::GET => api_cas_list(req).await,
            Method::POST => api_ca_init(req).await,
            _ => render_unknown_method(),
        },
    }
}

async fn api_ca_keys(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::POST => match path.next() {
            Some("roll_init") => api_ca_kr_init(req, ca).await,
            Some("roll_activate") => api_ca_kr_activate(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_ca_parents(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    if let Some(parent) = path.path_arg() {
        match *req.method() {
            Method::GET => api_ca_my_parent_contact(req, ca, parent).await,
            Method::POST => api_ca_parent_add_or_update(req, ca, Some(parent)).await,
            Method::DELETE => api_ca_remove_parent(req, ca, parent).await,
            _ => render_unknown_method(),
        }
    } else {
        match *req.method() {
            Method::GET => api_ca_my_parent_statuses(req, ca).await,
            Method::POST => api_ca_parent_add_or_update(req, ca, None).await,
            _ => render_unknown_method(),
        }
    }
}

async fn api_ca_repo(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => api_ca_repo_details(req, ca).await,
            Method::POST => api_ca_repo_update(req, ca).await,
            _ => render_unknown_method(),
        },
        Some("status") => api_ca_repo_status(req, ca).await,
        _ => render_unknown_method(),
    }
}

async fn api_ca_routes(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => api_ca_routes_show(req, ca).await,
            Method::POST => api_ca_routes_update(req, ca).await,
            _ => render_unknown_method(),
        },
        Some("try") => match *req.method() {
            Method::POST => api_ca_routes_try_update(req, ca).await,
            _ => render_unknown_method(),
        },
        Some("analysis") => api_ca_routes_analysis(req, path, ca).await,
        _ => render_unknown_method(),
    }
}

async fn api_ca_stats(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        Some("children") => match path.next() {
            Some("connections") => api_ca_stats_child_connections(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_publication_server(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.next() {
        Some("publishers") => api_publishers(req, path).await,
        Some("stale") => api_stale_publishers(req, path.next()).await,
        Some("init") => match *req.method() {
            Method::POST => {
                let state = req.state.clone();
                match req.json().await {
                    Ok(uris) => render_empty_res(state.repository_init(uris)),
                    Err(e) => render_error(e),
                }
            }
            Method::DELETE => render_empty_res(req.state.repository_clear()),
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_publishers(req: Request, path: &mut RequestPath) -> RoutingResult {
    match *req.method() {
        Method::GET => match path.path_arg() {
            Some(publisher) => match path.next() {
                None => api_show_pbl(req, publisher).await,
                Some("response.xml") => api_repository_response_xml(req, publisher).await,
                Some("response.json") => api_repository_response_json(req, publisher).await,

                _ => render_unknown_method(),
            },
            None => api_list_pbl(req).await,
        },
        Method::POST => match path.next() {
            None => api_add_pbl(req).await,
            _ => render_unknown_method(),
        },
        Method::DELETE => match path.path_arg() {
            Some(publisher) => api_remove_pbl(req, publisher).await,
            None => render_error(Error::ApiInvalidHandle),
        },
        _ => render_unknown_method(),
    }
}

//------------ Admin: Publishers ---------------------------------------------

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub async fn api_stale_publishers(req: Request, seconds: Option<&str>) -> RoutingResult {
    aa!(req, Permission::PUB_LIST, {
        let seconds = seconds.unwrap_or("");
        match i64::from_str(seconds) {
            Ok(seconds) => render_json_res(
                req.state()
                    .repo_stats()
                    .map(|stats| PublisherList::build(&stats.stale_publishers(seconds))),
            ),
            Err(_) => render_error(Error::ApiInvalidSeconds),
        }
    })
}

/// Returns a json structure with all publishers in it.
pub async fn api_list_pbl(req: Request) -> RoutingResult {
    aa!(req, Permission::PUB_LIST, {
        render_json_res(
            req.state()
                .publishers()
                .map(|publishers| PublisherList::build(&publishers)),
        )
    })
}

/// Adds a publisher
pub async fn api_add_pbl(req: Request) -> RoutingResult {
    aa!(req, Permission::PUB_CREATE, {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(pbl) => render_json_res(server.add_publisher(pbl, &actor)),
            Err(e) => render_error(e),
        }
    })
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
#[allow(clippy::redundant_clone)] // false positive
pub async fn api_remove_pbl(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, Permission::PUB_DELETE, publisher.clone(), {
        let actor = req.actor();
        render_empty_res(req.state().remove_publisher(publisher, &actor))
    })
}

/// Returns a json structure with publisher details
#[allow(clippy::redundant_clone)] // false positive
pub async fn api_show_pbl(req: Request, publisher: Handle) -> RoutingResult {
    aa!(
        req,
        Permission::PUB_READ,
        publisher.clone(),
        render_json_res(req.state().get_publisher(&publisher))
    )
}

//------------ repository_response ---------------------------------------------

#[allow(clippy::redundant_clone)] // false positive
pub async fn api_repository_response_xml(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, Permission::PUB_READ, publisher.clone(), {
        match repository_response(&req, &publisher).await {
            Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
            Err(e) => render_error(e),
        }
    })
}

#[allow(clippy::redundant_clone)] // false positive
pub async fn api_repository_response_json(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, Permission::PUB_READ, publisher.clone(), {
        match repository_response(&req, &publisher).await {
            Ok(res) => render_json(res),
            Err(e) => render_error(e),
        }
    })
}

async fn repository_response(req: &Request, publisher: &Handle) -> Result<rfc8183::RepositoryResponse, Error> {
    req.state().repository_response(publisher)
}

pub async fn api_ca_add_child(req: Request, parent: ParentHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, parent.clone(), {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(child_req) => render_json_res(server.ca_add_child(&parent, child_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_child_update(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, child.clone(), {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(child_req) => render_empty_res(server.ca_child_update(&ca, child, child_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

pub async fn api_ca_child_remove(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, ca.clone(), {
        let actor = req.actor();
        render_empty_res(req.state().ca_child_remove(&ca, child, &actor).await)
    })
}

async fn api_ca_child_show(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        ca.clone(),
        render_json_res(req.state().ca_child_show(&ca, &child).await)
    )
}

async fn api_ca_stats_child_connections(req: Request, ca: Handle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        ca.clone(),
        render_json_res(req.state().ca_stats_child_connections(&ca).await)
    )
}

async fn api_ca_parent_contact(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        ca.clone(),
        render_json_res(req.state().ca_parent_contact(&ca, child.clone()).await)
    )
}

async fn api_ca_parent_res_json(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        ca.clone(),
        render_json_res(req.state().ca_parent_response(&ca, child.clone()).await)
    )
}

pub async fn api_ca_parent_res_xml(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, Permission::CA_READ, ca.clone(), {
        match req.state().ca_parent_response(&ca, child.clone()).await {
            Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
            Err(e) => render_error(e),
        }
    })
}

//------------ Admin: CertAuth -----------------------------------------------

async fn api_all_ca_issues(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, Permission::CA_READ, {
            let actor = req.actor();
            render_json_res(req.state().all_ca_issues(&actor).await)
        }),
        _ => render_unknown_method(),
    }
}

/// Returns the health (state) for a given CA.
async fn api_ca_issues(req: Request, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            ca.clone(),
            render_json_res(req.state().ca_issues(&ca).await)
        ),
        _ => render_unknown_method(),
    }
}

async fn api_cas_list(req: Request) -> RoutingResult {
    aa!(req, Permission::CA_LIST, {
        let actor = req.actor();
        render_json_res(req.state().ca_list(&actor))
    })
}

pub async fn api_ca_init(req: Request) -> RoutingResult {
    aa!(req, Permission::CA_CREATE, {
        let state = req.state().clone();

        match req.json().await {
            Ok(ca_init) => render_empty_res(state.ca_init(ca_init)),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_id(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_UPDATE, ca.clone(), {
            let actor = req.actor();
            render_empty_res(req.state().ca_update_id(ca, &actor).await)
        }),
        Method::GET => match path.next() {
            Some("child_request.xml") => api_ca_child_req_xml(req, ca).await,
            Some("child_request.json") => api_ca_child_req_json(req, ca).await,
            Some("publisher_request.json") => api_ca_publisher_req_json(req, ca).await,
            Some("publisher_request.xml") => api_ca_publisher_req_xml(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_ca_info(req: Request, handle: Handle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        handle.clone(),
        render_json_res(req.state().ca_info(&handle).await)
    )
}

async fn api_ca_delete(req: Request, handle: Handle) -> RoutingResult {
    let actor = req.actor();
    aa!(
        req,
        Permission::CA_DELETE,
        handle.clone(),
        render_json_res(req.state().ca_delete(&handle, &actor).await)
    )
}

async fn api_ca_my_parent_contact(req: Request, ca: Handle, parent: ParentHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        ca.clone(),
        render_json_res(req.state().ca_my_parent_contact(&ca, &parent).await)
    )
}

async fn api_ca_my_parent_statuses(req: Request, ca: Handle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        ca.clone(),
        render_json_res(req.state().ca_my_parent_statuses(&ca).await)
    )
}

async fn api_ca_children(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.path_arg() {
        Some(child) => match path.next() {
            None => match *req.method() {
                Method::GET => api_ca_child_show(req, ca, child).await,
                Method::POST => api_ca_child_update(req, ca, child).await,
                Method::DELETE => api_ca_child_remove(req, ca, child).await,
                _ => render_unknown_method(),
            },
            Some("contact") => api_ca_parent_contact(req, ca, child).await,
            Some("parent_response.json") => api_ca_parent_res_json(req, ca, child).await,
            Some("parent_response.xml") => api_ca_parent_res_xml(req, ca, child).await,
            _ => render_unknown_method(),
        },
        None => match *req.method() {
            Method::POST => api_ca_add_child(req, ca).await,
            _ => render_unknown_method(),
        },
    }
}

async fn api_ca_history_commands(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, Permission::CA_READ, handle.clone(), {
            // /api/v1/cas/{ca}/history/commands  /<rows>/<offset>/<after>/<before>
            let mut crit = CommandHistoryCriteria::default();

            if let Some(rows) = path.path_arg() {
                crit.set_rows(rows);
            }

            if let Some(offset) = path.path_arg() {
                crit.set_offset(offset);
            }

            if let Some(after) = path.path_arg() {
                crit.set_after(after);
            }

            if let Some(before) = path.path_arg() {
                crit.set_before(before);
            }
            match req.state().ca_history(&handle, crit).await {
                Ok(history) => render_json(history),
                Err(e) => render_error(e),
            }
        }),
        _ => render_unknown_method(),
    }
}

async fn api_ca_history(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        Some("details") => api_ca_command_details(req, path, ca).await,
        Some("commands") => api_ca_history_commands(req, path, ca).await,
        _ => render_unknown_method(),
    }
}

#[allow(clippy::redundant_clone)] // false positive
async fn api_ca_command_details(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    // /api/v1/cas/{ca}/command/<command-key>
    match path.path_arg() {
        Some(key) => match *req.method() {
            Method::GET => aa!(req, Permission::CA_READ, handle.clone(), {
                match req.state().ca_command_details(&handle, key) {
                    Ok(details) => render_json(details),
                    Err(e) => match e {
                        Error::AggregateStoreError(AggregateStoreError::UnknownCommand(_, _)) => {
                            render_unknown_resource()
                        }
                        _ => render_error(e),
                    },
                }
            }),
            _ => render_unknown_method(),
        },
        None => render_unknown_resource(),
    }
}

async fn api_ca_child_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            handle.clone(),
            match ca_child_req(&req, &handle).await {
                Ok(req) => Ok(HttpResponse::xml(req.encode_vec())),
                Err(e) => render_error(e),
            }
        ),
        _ => render_unknown_method(),
    }
}

async fn api_ca_child_req_json(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            handle.clone(),
            match ca_child_req(&req, &handle).await {
                Ok(req) => render_json(req),
                Err(e) => render_error(e),
            }
        ),
        _ => render_unknown_method(),
    }
}

async fn ca_child_req(req: &Request, handle: &Handle) -> Result<rfc8183::ChildRequest, Error> {
    req.state().ca_child_req(handle).await
}

async fn api_ca_publisher_req_json(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            handle.clone(),
            render_json_res(req.state().ca_publisher_req(&handle).await)
        ),
        _ => render_unknown_method(),
    }
}

async fn api_ca_publisher_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            handle.clone(),
            match req.state().ca_publisher_req(&handle).await {
                Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
                Err(e) => render_error(e),
            }
        ),
        _ => render_unknown_method(),
    }
}

async fn api_ca_repo_details(req: Request, handle: Handle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        handle.clone(),
        render_json_res(req.state().ca_repo_details(&handle).await)
    )
}

async fn api_ca_repo_status(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            handle.clone(),
            render_json_res(req.state().ca_repo_status(&handle).await)
        ),
        _ => render_unknown_method(),
    }
}

fn extract_repository_contact(handle: &Handle, bytes: Bytes) -> Result<RepositoryContact, Error> {
    let string = String::from_utf8(bytes.to_vec()).map_err(Error::custom)?;

    // TODO: Switch based on Content-Type header
    if string.starts_with('<') {
        if string.contains("<parent_response") {
            Err(Error::CaRepoResponseWrongXml(handle.clone()))
        } else {
            let response = rfc8183::RepositoryResponse::validate(string.as_bytes())
                .map_err(|e| Error::CaRepoResponseInvalidXml(handle.clone(), e.to_string()))?;
            Ok(RepositoryContact::new(response))
        }
    } else {
        serde_json::from_str(&string).map_err(Error::JsonError)
    }
}

async fn api_ca_repo_update(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, handle.clone(), {
        let actor = req.actor();
        let server = req.state().clone();

        match req
            .api_bytes()
            .await
            .map(|bytes| extract_repository_contact(&handle, bytes))
        {
            Ok(Ok(update)) => render_empty_res(server.ca_repo_update(handle, update, &actor).await),
            Ok(Err(e)) | Err(e) => render_error(e),
        }
    })
}

async fn api_ca_parent_add_or_update(req: Request, ca: Handle, parent_override: Option<Handle>) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, ca.clone(), {
        let actor = req.actor();
        let server = req.state().clone();

        let bytes = match req.api_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };

        match extract_parent_ca_req(&ca, bytes, parent_override) {
            Ok(parent_req) => render_empty_res(server.ca_parent_add_or_update(ca, parent_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

fn extract_parent_ca_req(ca: &Handle, bytes: Bytes, parent_override: Option<Handle>) -> Result<ParentCaReq, Error> {
    let string = String::from_utf8(bytes.to_vec()).map_err(Error::custom)?;

    // TODO: Switch based on Content-Type header
    let req = if string.starts_with('<') {
        if string.starts_with("<repository") {
            return Err(Error::CaParentResponseWrongXml(ca.clone()));
        } else {
            let res = rfc8183::ParentResponse::validate(string.as_bytes())
                .map_err(|e| Error::CaParentResponseInvalidXml(ca.clone(), e.to_string()))?;

            let parent_name = parent_override.unwrap_or_else(|| res.parent_handle().clone());
            let contact = ParentCaContact::for_rfc6492(res);
            ParentCaReq::new(parent_name, contact)
        }
    } else {
        let req: ParentCaReq = serde_json::from_str(&string).map_err(Error::JsonError)?;
        if let Some(parent_override) = parent_override {
            if req.handle() != &parent_override {
                return Err(Error::Custom(format!(
                    "Used different parent names on path ({}) and submitted JSON ({}) for adding/updating a parent",
                    parent_override,
                    req.handle()
                )));
            }
        }
        req
    };

    Ok(req)
}

async fn api_ca_remove_parent(req: Request, ca: Handle, parent: Handle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, ca.clone(), {
        let actor = req.actor();
        render_empty_res(req.state().ca_parent_remove(ca, parent, &actor).await)
    })
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
async fn api_ca_kr_init(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, ca.clone(), {
        let actor = req.actor();
        render_empty_res(req.state().ca_keyroll_init(ca, &actor).await)
    })
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
async fn api_ca_kr_activate(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, ca.clone(), {
        let actor = req.actor();
        render_empty_res(req.state().ca_keyroll_activate(ca, &actor).await)
    })
}

/// Update the route authorizations for this CA
async fn api_ca_routes_update(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, Permission::ROUTES_UPDATE, ca.clone(), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Err(e) => render_error(e),
            Ok(updates) => render_empty_res(state.ca_routes_update(ca, updates, &actor).await),
        }
    })
}

/// Tries an update. If the dry-run for it would be successful, and the analysis
/// for the resources in the update have no remaining invalids, apply it. Otherwise
/// return the analysis and a suggestion.
async fn api_ca_routes_try_update(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, Permission::ROUTES_UPDATE, ca.clone(), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json::<RoaDefinitionUpdates>().await {
            Err(e) => render_error(e),
            Ok(updates) => {
                let server = state;
                match server.ca_routes_bgp_dry_run(&ca, updates.clone()).await {
                    Err(e) => {
                        // update was rejected, return error
                        render_error(e)
                    }
                    Ok(effect) => {
                        if !effect.contains_invalids() {
                            // no issues found, apply
                            render_empty_res(server.ca_routes_update(ca, updates, &actor).await)
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
    })
}

/// show the route authorizations for this CA
async fn api_ca_routes_show(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, Permission::ROUTES_READ, ca.clone(), {
        match req.state().ca_routes_show(&ca).await {
            Ok(roas) => render_json(roas),
            Err(_) => render_unknown_resource(),
        }
    })
}

/// Show the state of ROAs vs BGP for this CA
async fn api_ca_routes_analysis(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    aa!(req, Permission::ROUTES_ANALYSIS, ca.clone(), {
        match path.next() {
            Some("full") => render_json_res(req.state().ca_routes_bgp_analysis(&ca).await),
            Some("dryrun") => match *req.method() {
                Method::POST => {
                    let state = req.state.clone();
                    match req.json().await {
                        Err(e) => render_error(e),
                        Ok(updates) => render_json_res(state.ca_routes_bgp_dry_run(&ca, updates).await),
                    }
                }
                _ => render_unknown_method(),
            },
            Some("suggest") => match *req.method() {
                Method::GET => render_json_res(req.state().ca_routes_bgp_suggest(&ca, None).await),
                Method::POST => {
                    let server = req.state().clone();
                    match req.json().await {
                        Err(e) => render_error(e),
                        Ok(resources) => render_json_res(server.ca_routes_bgp_suggest(&ca, Some(resources)).await),
                    }
                }
                _ => render_unknown_method(),
            },
            _ => render_unknown_method(),
        }
    })
}

//------------ Admin: Force republish ----------------------------------------

async fn api_republish_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            render_empty_res(req.state().republish_all().await)
        }),
        _ => render_unknown_method(),
    }
}

async fn api_resync_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            let actor = req.actor();
            render_empty_res(req.state().resync_all(&actor).await)
        }),
        _ => render_unknown_method(),
    }
}

/// Refresh all CAs
async fn api_refresh_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            let actor = req.actor();
            render_empty_res(req.state().cas_refresh_all(&actor).await)
        }),
        _ => render_unknown_method(),
    }
}

//------------ Serve RRDP Files ----------------------------------------------

async fn rrdp(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/rrdp/") {
        Err(req) // Not for us
    } else {
        let mut full_path: PathBuf = req.state.rrdp_base_path();
        let (_, path) = req.path.remaining().split_at(1);
        let cache_seconds = if path.ends_with("notification.xml") { 60 } else { 86400 };
        full_path.push(path);

        match File::open(full_path) {
            Ok(mut file) => {
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
    aa!(
        req,
        Permission::RTA_LIST,
        ca.clone(),
        render_json_res(req.state().rta_list(ca).await)
    )
}

async fn api_ca_rta_show(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(
        req,
        Permission::RTA_READ,
        ca.clone(),
        render_json_res(req.state().rta_show(ca, name).await)
    )
}

async fn api_ca_rta_sign(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, Permission::RTA_UPDATE, ca.clone(), {
        let actor = req.actor();
        let state = req.state().clone();
        match req.json().await {
            Err(e) => render_error(e),
            Ok(request) => render_empty_res(state.rta_sign(ca, name, request, &actor).await),
        }
    })
}

async fn api_ca_rta_multi_prep(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, Permission::RTA_UPDATE, ca.clone(), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Ok(resources) => render_json_res(state.rta_multi_prep(ca, name, resources, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_rta_multi_sign(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, Permission::RTA_UPDATE, ca.clone(), {
        let actor = req.actor();
        let state = req.state().clone();
        match req.json().await {
            Ok(rta) => render_empty_res(state.rta_multi_cosign(ca, name, rta, &actor).await),
            Err(_) => render_error(Error::custom("Cannot decode RTA for co-signing")),
        }
    })
}

//------------ Tests ---------------------------------------------------------
#[cfg(test)]
mod tests {

    // NOTE: This is extensively tested through the functional and e2e tests found under
    //       the $project/tests dir
    use crate::test;
    use std::fs;

    #[tokio::test]
    async fn start_krill_daemon() {
        let dir = test::start_krill_with_default_test_config(false, false).await;
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn start_krill_pubd_daemon() {
        let dir = test::start_krill_pubd().await;
        let _ = fs::remove_dir_all(dir);
    }
}
