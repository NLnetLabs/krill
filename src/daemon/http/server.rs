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
use hyper::header::HeaderName;
use hyper::http::HeaderValue;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::Method;

use crate::commons::api::{
    BgpStats, ChildHandle, CommandHistoryCriteria, Handle, ParentCaContact, ParentCaReq, ParentHandle, PublisherList,
    RepositoryUpdate, RoaDefinitionUpdates, RtaName, Token,
};
use crate::commons::actor::Actor;
use crate::commons::bgp::BgpAnalysisAdvice;
use crate::commons::error::Error;
use crate::commons::eventsourcing::AggregateStoreError;
use crate::commons::remote::rfc8183;
use crate::commons::util::file;
use crate::constants::{KRILL_ENV_UPGRADE_ONLY, KRILL_VERSION_MAJOR, KRILL_VERSION_MINOR, KRILL_VERSION_PATCH};
use crate::daemon::auth::Auth;
// use crate::daemon::auth::Permissions;
use crate::daemon::ca::RouteAuthorizationUpdates;
use crate::daemon::http::auth::auth;
use crate::daemon::config::Config;
use crate::daemon::http::statics::statics;
use crate::daemon::http::testbed::testbed;
use crate::daemon::http::{tls, tls_keys, HttpResponse, Request, RequestPath, RoutingResult};
use crate::daemon::krillserver::KrillServer;
use crate::upgrades::{post_start_upgrade, pre_start_upgrade, update_storage_version};

//------------ State -----------------------------------------------------

pub type State = Arc<RwLock<KrillServer>>;

pub async fn start(config: Option<Config>) -> Result<(), Error> {
    let config = Arc::new(match config {
        Some(config) => config,
        None => Config::create().map_err(|e| Error::Custom(format!("Could not parse config: {}", e)))?
    });
    let pid_file = config.pid_file();
    if let Err(e) = file::save(process::id().to_string().as_bytes(), &pid_file) {
        eprintln!("Could not write PID file: {}", e);
        ::std::process::exit(1);
    }

    // Check data dir can be written to
    {
        let mut test_file = config.data_dir.clone();
        test_file.push("test");

        if let Err(e) = file::save(b"test", &test_file) {
            eprintln!(
                "Cannot write to data dir: {}, Error: {}",
                config.data_dir.to_string_lossy(),
                e
            );
            ::std::process::exit(1);
        } else if let Err(e) = file::delete(&test_file) {
            eprintln!(
                "Cannot delete test file in data dir: {}, Error: {}",
                test_file.to_string_lossy(),
                e
            );
            ::std::process::exit(1);
        }
    }

    // Call upgrade, this will only do actual work if needed.
    pre_start_upgrade(&config.data_dir).map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))?;

    // Create the server, this will create the necessary data sub-directories if needed
    let krill = KrillServer::build(config.clone()).await?;

    // Perform upgrades that need a running krill server (e.g. clean up ROAs)
    post_start_upgrade(&config.data_dir, &krill)
        .map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))
        .await?;

    // Update the version identifiers for the storage dirs
    update_storage_version(&config.data_dir)
        .map_err(|e| Error::Custom(format!("Could not upgrade Krill: {}", e)))
        .await?;

    // If the operator wanted to do the upgrade only, now is a good time to report success and stop
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

    tls_keys::create_key_cert_if_needed(&config.data_dir).map_err(|e| Error::HttpsSetup(format!("{}", e)))?;

    let server_config_builder = tls::TlsConfigBuilder::new()
        .cert_path(tls_keys::cert_file_path(&config.data_dir))
        .key_path(tls_keys::key_file_path(&config.data_dir));
    let server_config = server_config_builder.build().unwrap();

    let incoming = AddrIncoming::bind(&config.socket_addr()).map_err(|e| {
        Error::Custom(format!(
            "Could not bing to address and port: {}, Error: {}",
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
        ::std::process::exit(1);
    }

    Ok(())
}

struct ResultLogger {
    req_method: hyper::Method,
    req_path: String,
}

impl ResultLogger {
    fn new(req: &Request) -> Self {
        ResultLogger {
            req_method: req.method().clone(),
            req_path: req.path.full().to_string(),
        }
    }

    fn log(&self, res: Result<&HttpResponse, &Error>) {
        match res {
            Ok(response) => {
                info!("{} {} {}", self.req_method, self.req_path, response.status());

                if log_enabled!(log::Level::Trace) {
                    match response.loggable() {
                        false => trace!("Response body: <filtered>"),
                        true  => trace!("Response body: {:?}", response.body()),
                    }
                }
            },
            Err(err) => {
                error!("{} {} Error: {}", self.req_method, self.req_path, err);
            }
        }
    }
}

async fn map_requests(req: hyper::Request<hyper::Body>, state: State) -> Result<hyper::Response<hyper::Body>, Error> {
    let req = Request::new(req, state).await?;

    // Save any updated auth details, e.g. if an OpenID Connect token needed
    // refreshing.
    let new_auth = req.actor().new_auth();

    // Make a logger that we can use to skip logging of very large static
    // responses as they are not helpful when diagnosing issues (you can get
    // the same information from your browser in an easier to use form) and they
    // just make the trace log unusable.
    let logger = ResultLogger::new(&req);

    let res = api(req)
        .or_else(auth)
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

    // Augment the response with any updated auth details that were determined
    // above.
    let res = add_new_auth_to_response(res, new_auth);

    // Log the request and the response.
    logger.log(res.as_ref());

    res.map(|res| res.response())
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

pub fn render_unknown_method() -> RoutingResult {
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

        #[cfg(feature = "multi-user")]
        {
            res.push_str("\n");
            res.push_str("# HELP krill_auth_session_cache_size total number of cached login session tokens\n");
            res.push_str("# TYPE krill_auth_session_cache_size gauge\n");
            res.push_str(&format!("krill_auth_session_cache_size {}\n", server.login_session_cache_size()));
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

        let actor = req.actor();
        let state = req.state().clone();

        let bytes = match req.rfc8181_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };

        let read = state.read().await;
        match read.rfc8181(publisher, bytes, &actor) {
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

        let actor = req.actor();
        let state = req.state().clone();

        let bytes = match req.rfc6492_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };
        let lock = state.read().await;
        match lock.rfc6492(ca, bytes, &actor).await {
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

// Suppress any error in the unlikely event that we fail to inject the
// Authorization header into the HTTP response as this is an internal error that
// we should shield the user from, but log a warning as this is very unexpected.
fn add_authorization_headers_to_response(org_response: HttpResponse, token: Token) -> HttpResponse
{
    let mut new_header_names = Vec::new();
    let mut new_header_values = Vec::new();

    new_header_names.push(HeaderName::from_str("Authorization"));
    new_header_values.push(HeaderValue::from_str(&format!("Bearer {}", &token)));

    let okay = !new_header_names.iter().zip(new_header_values.iter()).any(|(n, v)| n.is_err() | v.is_err());
    
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
        conversion_errors.extend(new_header_names.into_iter().filter(|result| result.is_err()).map(|i| i.unwrap_err().to_string()));
        conversion_errors.extend(new_header_values.into_iter().filter(|result| result.is_err()).map(|i| i.unwrap_err().to_string()));
        warn!("Internal error: unable to add refreshed auth token to the response: {:?}", conversion_errors.join(", "));
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

// This macro handles returning from API handler functions if the request is not
// Authenticated or lacks sufficient Authorization. We don't use a normal fn for
// this as then each API handler function would have to also test for success or
// failure and also return the forbidden response to the caller. That would be
// both verbose and repetetive. If we had a child crate we could use a proc
// macro instead so that we could "annotate" each API handler function with
// something like:
//   #[require_permission(CA_CREATE)]
// Which would insert the generated code at the start of the function body,
// similar to how this macro is used in each function.
macro_rules! aa {
    ($req:ident, $perm:ident, $action:expr) => {{
        match $req.actor().is_allowed(stringify!($perm), $req.path().clone()) {
            true  => $action,
            false => Ok(HttpResponse::forbidden(
                format!("User '{}' does not have permission '{}' on resource '{}'",
                    $req.actor().name(), stringify!($perm), $req.path().clone())
            )),
        }
    }}
}

/// Maps the API methods
async fn api(req: Request) -> RoutingResult {
    if !req.path().full().starts_with("/api/v1") {
        Err(req) // Not for us
    } else {
        // Eat the first two segments of the path "api/v1"
        let mut path = req.path().clone();
        path.next(); // gets 'v1' and drops it.

        // TODO: require the caller to be permitted to use the API to enable
        // early abort here. In fact, why not lookup the relative API call path
        // in a matrix of path to required rights at this point and verify that
        // the caller has that right, rather than leave it to the API fns below,
        // as the latter approach leaves the door open to forgetting to add a
        // security check while with the former approach we can panic if no
        // mapping for the relative path exists and catch that during
        // development! OR, set a flag when the actor rights were checked and
        // prior to returning from this fn check that the flag was set? This
        // last approach would avoid duplicating the relative path checks in a 
        // separate security map and in the path walking done below.

        match path.next() {
            Some("authorized") => api_authorized(req).await,
            Some("bulk") => api_bulk(req, &mut path).await,
            Some("cas") => api_cas(req, &mut path).await,
            Some("publishers") => api_publishers(req, &mut path).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        }
    }
}

async fn api_authorized(req: Request) -> RoutingResult {
    aa!(req, LOGIN, match *req.method() {
        Method::GET => render_ok(),
        _ => render_unknown_method(),
    })
}

async fn api_bulk(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.full() {
        "/api/v1/bulk/cas/issues" => api_all_ca_issues(req).await,
        "/api/v1/bulk/cas/sync/parent" => api_refresh_all(req).await,
        "/api/v1/bulk/cas/sync/repo" => api_resync_all(req).await,
        "/api/v1/bulk/cas/publish" => api_republish_all(req).await,
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_cas(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.path_arg::<Handle>() {
        Some(ca) if req.actor().is_allowed("CA_READ", ca.clone()) => {
            match path.next() {
                None => api_ca_info(req, ca).await,
                Some("child_request.xml") => api_ca_child_req_xml(req, ca).await,
                Some("child_request.json") => api_ca_child_req_json(req, ca).await,
                Some("children") => api_ca_children(req, path, ca).await,
                Some("history") => api_ca_history(req, path, ca).await,
                Some("command") => api_ca_command_details(req, path, ca).await,
                Some("id") => api_ca_regenerate_id(req, ca).await,
                Some("issues") => api_ca_issues(req, ca).await,
                Some("keys") => api_ca_keys(req, path, ca).await,
                Some("parents") => api_ca_parents(req, path, ca).await,
                Some("parents-xml") => api_ca_add_parent_xml(req, path, ca).await,
                Some("repo") => api_ca_repo(req, path, ca).await,
                Some("routes") => api_ca_routes(req, path, ca).await,
                Some("rta") => api_ca_rta(req, path, ca).await,
                _ => aa!(req, LOGIN, render_unknown_method()),
            }
        },
        Some(ca) => {
            Ok(HttpResponse::forbidden(
                format!("User '{}' does not have permission '{}' on resource '{}'",
                    req.actor().name(), "CA_READ", ca)))
        },
        None => match *req.method() {
            Method::GET => api_cas_list(req).await,
            Method::POST => api_ca_init(req).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
    }
}

async fn api_ca_keys(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::POST => {
            match path.next() {
                Some("roll_init") => api_ca_kr_init(req, ca).await,
                Some("roll_activate") => api_ca_kr_activate(req, ca).await,
                _ => render_unknown_method(),
            }
        },
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_parents(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    if let Some(parent) = path.path_arg() {
        match *req.method() {
            Method::GET => api_ca_my_parent_contact(req, ca, parent).await,
            Method::POST => api_ca_update_parent(req, ca, parent).await,
            Method::DELETE => api_ca_remove_parent(req, ca, parent).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        }
    } else {
        match *req.method() {
            Method::GET => api_ca_my_parent_statuses(req, ca).await,
            Method::POST => api_ca_add_parent(req, ca).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        }
    }
}

async fn api_ca_repo(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => api_ca_repo_details(req, ca).await,
            Method::POST => api_ca_repo_update(req, ca).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        Some("request.json") => api_ca_publisher_req_json(req, ca).await,
        Some("request.xml") => api_ca_publisher_req_xml(req, ca).await,
        Some("status") => api_ca_repo_status(req, ca).await,
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_routes(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => api_ca_routes_show(req, ca).await,
            Method::POST => api_ca_routes_update(req, ca).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        Some("try") => match *req.method() {
            Method::POST => api_ca_routes_try_update(req, ca).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        Some("analysis") => api_ca_routes_analysis(req, path, ca).await,
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_publishers(req: Request, path: &mut RequestPath) -> RoutingResult {
    match *req.method() {
        Method::GET => match path.path_arg() {
            Some(publisher) => match path.next() {
                None => api_show_pbl(req, publisher).await,
                Some("response.xml") => api_repository_response_xml(req, publisher).await,
                Some("response.json") => api_repository_response_json(req, publisher).await,
                Some("stale") => api_stale_publishers(req, path.next()).await,
                _ => aa!(req, LOGIN, render_unknown_method()),
            },
            None => api_list_pbl(req).await,
        },
        Method::POST => match path.next() {
            None => api_add_pbl(req).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        Method::DELETE => match path.path_arg() {
            Some(publisher) => api_remove_pbl(req, publisher).await,
            None => render_error(Error::ApiInvalidHandle),
        },
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

//------------ Admin: Publishers ---------------------------------------------

/// Returns a list of publisher which have not updated for more
/// than the given number of seconds.
pub async fn api_stale_publishers(req: Request, seconds: Option<&str>) -> RoutingResult {
    aa!(req, PUB_LIST, {
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
    })
}

/// Returns a json structure with all publishers in it.
pub async fn api_list_pbl(req: Request) -> RoutingResult {
    aa!(req, PUB_LIST, {
        render_json_res(
            req.state()
                .read()
                .await
                .publishers()
                .map(|publishers| PublisherList::build(&publishers, "/api/v1/publishers")),
        )
    })
}

/// Adds a publisher
pub async fn api_add_pbl(req: Request) -> RoutingResult {
    aa!(req, PUB_CREATE, {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(pbl) => render_json_res(server.write().await.add_publisher(pbl, &actor)),
            Err(e) => render_error(e),
        }
    })
}

/// Removes a publisher. Should be idempotent! If if did not exist then
/// that's just fine.
pub async fn api_remove_pbl(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, PUB_DELETE, {
        let actor = req.actor();
        render_empty_res(req.state().write().await.remove_publisher(publisher, &actor))
    })
}

/// Returns a json structure with publisher details
pub async fn api_show_pbl(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, PUB_READ, render_json_res(req.state().read().await.get_publisher(&publisher)))
}

//------------ repository_response ---------------------------------------------

pub async fn api_repository_response_xml(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, PUB_ADMIN, {
        match repository_response(&req, &publisher).await {
            Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
            Err(e) => render_error(e),
        }
    })
}

pub async fn api_repository_response_json(req: Request, publisher: Handle) -> RoutingResult {
    aa!(req, PUB_ADMIN, {
        match repository_response(&req, &publisher).await {
            Ok(res) => render_json(res),
            Err(e) => render_error(e),
        }
    })
}

async fn repository_response(req: &Request, publisher: &Handle) -> Result<rfc8183::RepositoryResponse, Error> {
    req.state().read().await.repository_response(publisher)
}

pub async fn api_ca_add_child(req: Request, parent: ParentHandle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(child_req) => render_json_res(server.read().await.ca_add_child(&parent, child_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_child_update(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(child_req) => render_empty_res(server.read().await.ca_child_update(&ca, child, child_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

pub async fn api_ca_child_remove(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        render_empty_res(req.state().read().await.ca_child_remove(&ca, child, &actor).await)
    })
}

async fn api_ca_child_show(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, CA_READ, render_json_res(req.state().read().await.ca_child_show(&ca, &child).await))
}

async fn api_ca_parent_contact(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, CA_READ, render_json_res(req.state().read().await.ca_parent_contact(&ca, child.clone()).await))
}

async fn api_ca_parent_res_json(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, CA_READ, render_json_res(req.state().read().await.ca_parent_response(&ca, child.clone()).await))
}

pub async fn api_ca_parent_res_xml(req: Request, ca: Handle, child: ChildHandle) -> RoutingResult {
    aa!(req, CA_READ, {
        match req.state().read().await.ca_parent_response(&ca, child.clone()).await {
            Ok(res) => Ok(HttpResponse::xml(res.encode_vec())),
            Err(e) => render_error(e),
        }
    })
}

//------------ Admin: CertAuth -----------------------------------------------

async fn api_all_ca_issues(req: Request) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, CA_READ, {
            let actor = req.actor();
            render_json_res(req.state().read().await.all_ca_issues(&actor).await)
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

/// Returns the health (state) for a given CA.
async fn api_ca_issues(req: Request, ca: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, CA_READ, render_json_res(req.state().read().await.ca_issues(&ca).await)),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_cas_list(req: Request) -> RoutingResult {
    aa!(req, CA_LIST, {
        let actor = req.actor();
        render_json_res(req.state().read().await.ca_list(&actor))
    })
}

pub async fn api_ca_init(req: Request) -> RoutingResult {
    aa!(req, CA_CREATE, {
        let state = req.state().clone();

        match req.json().await {
            Ok(ca_init) => render_empty_res(state.write().await.ca_init(ca_init).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_regenerate_id(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, CA_UPDATE, {
            let actor = req.actor();
            render_empty_res(req.state().read().await.ca_update_id(handle, &actor).await)
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_info(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, CA_READ, render_json_res(req.state().read().await.ca_info(&handle).await)),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_my_parent_contact(req: Request, ca: Handle, parent: ParentHandle) -> RoutingResult {
    aa!(req, CA_READ, render_json_res(req.state().read().await.ca_my_parent_contact(&ca, &parent).await))
}

async fn api_ca_my_parent_statuses(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, CA_READ, render_json_res(req.state().read().await.ca_my_parent_statuses(&ca).await))
}

async fn api_ca_children(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    match path.path_arg() {
        Some(child) => match path.next() {
            None => match *req.method() {
                Method::GET => api_ca_child_show(req, ca, child).await,
                Method::POST => api_ca_child_update(req, ca, child).await,
                Method::DELETE => api_ca_child_remove(req, ca, child).await,
                _ => aa!(req, LOGIN, render_unknown_method()),
            },
            Some("contact") => api_ca_parent_contact(req, ca, child).await,
            Some("parent_response.json") => api_ca_parent_res_json(req, ca, child).await,
            Some("parent_response.xml") => api_ca_parent_res_xml(req, ca, child).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        None => match *req.method() {
            Method::POST => api_ca_add_child(req, ca).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
    }
}

async fn api_ca_history(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    let crit = match parse_history_path(path) {
        Some(crit) => crit,
        None => return aa!(req, LOGIN, render_unknown_method()),
    };

    match *req.method() {
        Method::GET => aa!(req, CA_READ, {
            match req.state().read().await.ca_history(&handle, crit).await {
                Some(history) => render_json(history),
                None => render_unknown_resource(),
            }
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
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

async fn api_ca_command_details(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    // /api/v1/cas/{ca}/command/<command-key>
    match path.path_arg() {
        Some(key) => match *req.method() {
            Method::GET => {
                aa!(req, CA_READ, { 
                    match req.state().read().await.ca_command_details(&handle, key) {
                        Ok(details) => render_json(details),
                        Err(e) => match e {
                        Error::AggregateStoreError(AggregateStoreError::UnknownCommand(_, _)) => render_unknown_resource(),
                        _ => render_error(e),
                        },
                    }
                })
            },
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        None => aa!(req, LOGIN, render_unknown_resource()),
    }
}

async fn api_ca_child_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => {
            aa!(req, CA_READ, match ca_child_req(&req, &handle).await {
                Ok(req) => Ok(HttpResponse::xml(req.encode_vec())),
                Err(e) => render_error(e),
            })
        },
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_child_req_json(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => {
            aa!(req, CA_READ, match ca_child_req(&req, &handle).await {
                Ok(req) => render_json(req),
                Err(e) => render_error(e),
            })
        },
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn ca_child_req(req: &Request, handle: &Handle) -> Result<rfc8183::ChildRequest, Error> {
    req.state().read().await.ca_child_req(handle).await
}

async fn api_ca_publisher_req_json(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, CA_READ, match req.state().read().await.ca_publisher_req(&handle).await {
            Some(req) => render_json(req),
            None => render_unknown_resource(),
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_publisher_req_xml(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, CA_READ, match req.state().read().await.ca_publisher_req(&handle).await {
            Some(req) => Ok(HttpResponse::xml(req.encode_vec())),
            None => render_unknown_resource(),
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_ca_repo_details(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, CA_READ, render_json_res(req.state().read().await.ca_repo_details(&handle).await))
}

async fn api_ca_repo_status(req: Request, handle: Handle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, CA_READ, render_json_res(req.state().read().await.ca_repo_status(&handle).await)),
        _ => aa!(req, LOGIN, render_unknown_method()),
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

pub async fn api_ca_repo_update(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        let server = req.state().clone();

        match req
            .api_bytes()
            .await
            .map(|bytes| extract_repository_update(&handle, bytes))
        {
            Ok(Ok(update)) => render_empty_res(server.read().await.ca_update_repo(handle, update, &actor).await),
            Ok(Err(e)) | Err(e) => render_error(e),
        }
    })
}

async fn api_ca_add_parent(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        let server = req.state().clone();

        let parent_req = match req.json().await {
            Ok(req) => req,
            Err(e) => return render_error(e),
        };

        match ca_parent_add(server, ca, parent_req, &actor).await {
            Ok(()) => render_ok(),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_add_parent_xml(req: Request, path: &mut RequestPath, ca: Handle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
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

        match ca_parent_add(server, ca, parent_req, &actor).await {
            Ok(()) => render_ok(),
            Err(e) => render_error(e),
        }
    })
}

async fn ca_parent_add(server: State, ca: Handle, parent_req: ParentCaReq, actor: &Actor) -> Result<(), Error> {
    server.read().await.ca_parent_add(ca, parent_req, actor).await
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

async fn api_ca_update_parent(req: Request, ca: Handle, parent: ParentHandle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        let server = req.state().clone();

        let bytes = match req.api_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => return render_error(e),
        };

        match extract_parent_ca_contact(&ca, bytes) {
            Ok(contact) => {
                let res = server.read().await.ca_parent_update(ca, parent, contact, &actor).await;
                render_empty_res(res)
            }
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_remove_parent(req: Request, ca: Handle, parent: Handle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        render_empty_res(req.state().read().await.ca_parent_remove(ca, parent, &actor).await)
    })
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
async fn api_ca_kr_init(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        render_empty_res(req.state().read().await.ca_keyroll_init(handle, &actor).await)
    })
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
async fn api_ca_kr_activate(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, CA_UPDATE, {
        let actor = req.actor();
        render_empty_res(req.state().read().await.ca_keyroll_activate(handle, &actor).await)
    })
}

/// Update the route authorizations for this CA
async fn api_ca_routes_update(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, ROUTES_UPDATE, {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Err(e) => render_error(e),
            Ok(updates) => render_empty_res(state.read().await.ca_routes_update(handle, updates, &actor).await),
        }
    })
}

/// Tries an update. If the dry-run for it would be successful, and the analysis
/// for the resources in the update have no remaining invalids, apply it. Otherwise
/// return the analysis and a suggestion.
async fn api_ca_routes_try_update(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, ROUTES_UPDATE, {
        let actor = req.actor();
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
async fn api_ca_routes_show(req: Request, handle: Handle) -> RoutingResult {
    aa!(req, ROUTES_READ, { 
        match req.state().read().await.ca_routes_show(&handle).await {
            Ok(roas) => render_json(roas),
            Err(_) => render_unknown_resource(),
        }
    })
}

/// Show the state of ROAs vs BGP for this CA
async fn api_ca_routes_analysis(req: Request, path: &mut RequestPath, handle: Handle) -> RoutingResult {
    aa!(req, ROUTES_ANALYSIS, { 
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
    })
}

//------------ Admin: Force republish ----------------------------------------

async fn api_republish_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, CA_UPDATE, {
            let actor = req.actor();
            render_empty_res(req.state().read().await.republish_all(&actor).await)
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

async fn api_resync_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, CA_UPDATE, {
            let actor = req.actor();
            render_empty_res(req.state().read().await.resync_all(&actor).await)
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
    }
}

/// Refresh all CAs
async fn api_refresh_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, CA_UPDATE, {
            let actor = req.actor();
            render_empty_res(req.state().read().await.refresh_all(&actor).await)
        }),
        _ => aa!(req, LOGIN, render_unknown_method()),
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
                    _ => aa!(req, LOGIN, render_unknown_method()),
                },
                _ => aa!(req, LOGIN, render_unknown_method()),
            },
            Method::GET => {
                if name.is_empty() {
                    api_ca_rta_list(req, ca).await
                } else {
                    api_ca_rta_show(req, ca, name).await
                }
            }
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
        None => match *req.method() {
            Method::GET => api_ca_rta_list(req, ca).await,
            _ => aa!(req, LOGIN, render_unknown_method()),
        },
    }
}

async fn api_ca_rta_list(req: Request, ca: Handle) -> RoutingResult {
    aa!(req, RTA_LIST, render_json_res(req.state().read().await.rta_list(ca).await))
}

async fn api_ca_rta_show(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, RTA_READ, render_json_res(req.state().read().await.rta_show(ca, name).await))
}

async fn api_ca_rta_sign(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, RTA_UPDATE, { 
        let actor = req.actor();
        let state = req.state().clone();
        match req.json().await {
            Err(e) => render_error(e),
            Ok(request) => render_empty_res(state.read().await.rta_sign(ca, name, request, &actor).await),
        }
    })
}

async fn api_ca_rta_multi_prep(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, RTA_UPDATE, {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Ok(resources) => render_json_res(state.read().await.rta_multi_prep(ca, name, resources, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_rta_multi_sign(req: Request, ca: Handle, name: RtaName) -> RoutingResult {
    aa!(req, RTA_UPDATE, { 
        let actor = req.actor();
        let state = req.state().clone();
        match req.json().await {
            Ok(rta) => render_empty_res(state.read().await.rta_multi_cosign(ca, name, rta, &actor).await),
            Err(_) => render_error(Error::custom("Cannot decode RTA for co-signing")),
        }
    })
}

//------------ Tests ---------------------------------------------------------
#[cfg(test)]
mod tests {

    // NOTE: This is extensively tested through the functional and e2e tests found under
    //       the $project/tests dir

    use std::path::PathBuf;

    use crate::test;

    use super::*;

    #[tokio::test]
    async fn start_tls_server() {
        let dir = test::sub_dir(&PathBuf::from("work"));

        let data_dir = test::sub_dir(&dir);
        let config = Config::test(&data_dir);
    
        tokio::spawn(super::start(Some(config)));

        assert!(test::server_ready().await);
    }
}