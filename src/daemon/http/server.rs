//! Hyper based HTTP server for Krill.
//!
use std::{
    collections::HashMap,
    convert::{Infallible, TryInto},
    env,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    sync::Arc,
};

use bytes::Bytes;
use serde::Serialize;

use hyper::{
    header::HeaderName,
    http::HeaderValue,
    server::conn::AddrIncoming,
    service::{make_service_fn, service_fn},
    Method,
};

use tokio::select;

use rpki::{
    ca::{
        idexchange,
        idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
    },
    repository::resources::Asn,
};

use crate::{
    commons::{
        api::{
            ApiRepositoryContact, AspaDefinitionUpdates, BgpStats, CommandHistoryCriteria, ParentCaReq, PublisherList,
            RepositoryContact, RoaConfigurationUpdates, RtaName, Token,
        },
        bgp::BgpAnalysisAdvice,
        error::Error,
        eventsourcing::AggregateStoreError,
        util::file,
    },
    constants::{
        KRILL_ENV_HTTP_LOG_INFO, KRILL_ENV_UPGRADE_ONLY, KRILL_VERSION_MAJOR, KRILL_VERSION_MINOR, KRILL_VERSION_PATCH,
        NO_RESOURCE,
    },
    daemon::{
        auth::common::permissions::Permission,
        auth::{Auth, Handle},
        ca::CaStatus,
        config::Config,
        http::{
            auth::auth, statics::statics, testbed::testbed, tls, tls_keys, HttpResponse, Request, RequestPath,
            RoutingResult,
        },
        krillserver::KrillServer,
        properties::PropertiesManager,
    },
    ta::{self, TA_NAME},
    upgrades::{
        finalise_data_migration, post_start_upgrade, prepare_upgrade_data_migrations, UpgradeError, UpgradeMode,
    },
};

//------------ State -----------------------------------------------------

pub type State = Arc<KrillServer>;

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
    if let Err(e) = file::save(process::id().to_string().as_bytes(), config.pid_file()) {
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
    test_data_dir_or_die("tls_keys_dir", config.tls_keys_dir());
    test_data_dir_or_die("repo_dir", config.repo_dir());
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

    // Set up the runtime properties manager, so that we can check
    // the version used for the current data in storage
    let properties_manager = PropertiesManager::create(&config.storage_uri, config.use_history_cache)?;

    // Call upgrade, this will only do actual work if needed.
    let upgrade_report = prepare_upgrade_data_migrations(UpgradeMode::PrepareToFinalise, &config, &properties_manager)
        .map_err(|e| match e {
            UpgradeError::CodeOlderThanData(_,_) => {
                Error::Custom(e.to_string())
            },
            _ => Error::Custom(format!("Upgrade data migration failed with error: {}\n\nNOTE: your data was not changed. Please downgrade your krill instance to your previous version.", e))
        })?;

    if let Some(report) = &upgrade_report {
        finalise_data_migration(report.versions(), &config, &properties_manager).map_err(|e| {
                Error::Custom(format!(
                    "Finishing prepared migration failed unexpectedly. Please check your data {}. If you find folders named 'arch-cas-{}' or 'arch-pubd-{}' there, then rename them to 'cas' and 'pubd' respectively and re-install krill version {}. Underlying error was: {}",
                    config.storage_uri,
                    report.versions().from(),
                    report.versions().from(),
                    report.versions().from(),
                    e
                ))
            })?;
    }

    // Create the server, this will create the necessary data sub-directories if needed
    let krill_server = KrillServer::build(config.clone()).await?;

    // Call post-start upgrades to trigger any upgrade related runtime actions, such as
    // re-issuing ROAs because subject name strategy has changed.
    if let Some(report) = upgrade_report {
        post_start_upgrade(report.versions(), &krill_server).await?;
    }

    // If the operator wanted to do the upgrade only, now is a good time to report success and stop
    if env::var(KRILL_ENV_UPGRADE_ONLY).is_ok() {
        println!("Krill upgrade successful");
        std::process::exit(0);
    }

    // Build the scheduler which will be responsible for executing planned/triggered tasks
    let scheduler = krill_server.build_scheduler();
    let scheduler_future = scheduler.run();

    // Start creating the server.
    let krill_server = Arc::new(krill_server);

    // Create self-signed HTTPS cert if configured and not generated earlier.
    if config.https_mode().is_generate_https_cert() {
        tls_keys::create_key_cert_if_needed(config.tls_keys_dir()).map_err(|e| Error::HttpsSetup(format!("{}", e)))?;
    }

    // Start a hyper server for the configured socket.
    let server_futures = futures_util::future::select_all(
        config
            .socket_addresses()
            .into_iter()
            .map(|socket_addr| tokio::spawn(single_http_listener(krill_server.clone(), socket_addr, config.clone()))),
    );

    select!(
        _ = server_futures => error!("http server stopped unexpectedly"),
        _ = scheduler_future => error!("scheduler stopped unexpectedly"),
    );

    Err(Error::custom("stopping krill process"))
}

async fn single_http_listener(krill_server: Arc<KrillServer>, socket_addr: SocketAddr, config: Arc<Config>) {
    // See if we can bind to the configured address and port first.
    let incoming = match AddrIncoming::bind(&socket_addr) {
        Err(e) => {
            error!("Could not bind to address and port: {}, Error: {}", &socket_addr, e);
            return;
        }
        Ok(incoming) => incoming,
    };

    if config.https_mode().is_disable_https() {
        // Make a service function.
        let service = make_service_fn(|_| {
            let krill_server = krill_server.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: hyper::Request<hyper::Body>| {
                    let krill_server = krill_server.clone();
                    map_requests(req, krill_server)
                }))
            }
        });
        if let Err(e) = hyper::Server::builder(incoming).serve(service).await {
            error!("Fatal server error: {}", e)
        }
    } else {
        // Set up a TLS acceptor to use.
        let server_config_builder = tls::TlsConfigBuilder::new()
            .cert_path(tls_keys::cert_file_path(config.tls_keys_dir()))
            .key_path(tls_keys::key_file_path(config.tls_keys_dir()));

        let server_config = server_config_builder.build().unwrap();
        let acceptor = tls::TlsAcceptor::new(server_config, incoming);

        // Make a service function. We have to do this again because of hyper types..
        // It won't like a service made for a Server that is not of the type of the
        // TlsAcceptor we are about to set up.
        let service = make_service_fn(|_| {
            let krill_server = krill_server.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: hyper::Request<hyper::Body>| {
                    let krill_server = krill_server.clone();
                    map_requests(req, krill_server)
                }))
            }
        });

        if let Err(e) = hyper::Server::builder(acceptor).serve(service).await {
            error!("Fatal server error: {}", e)
        }
    }
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
                }

                if response.loggable() && log_enabled!(log::Level::Trace) {
                    trace!("{} {} {}", self.req_method, self.req_path, response.status());
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
        res = ta(req).await;
    }
    if let Err(req) = res {
        res = rrdp(req).await;
    }
    if let Err(req) = res {
        res = testbed(req).await;
    }
    if let Err(req) = res {
        res = statics(req).await;
    }

    if res.is_err() {
        // catch all to the UI
        res = Ok(HttpResponse::html(super::statics::INDEX));
    }

    // Not found responses are actually a special Ok result..
    let res = res.map_err(|_| Error::custom("should have received not found response"));

    // Augment the response with any updated auth details that were determined above.
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
    let location = format!("/ui/login?error={}", b64);
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
#[allow(clippy::format_push_string)]
pub async fn metrics(req: Request) -> RoutingResult {
    if req.is_get() && req.path().segment().starts_with("metrics") {
        let server = req.state();

        struct AllBgpStats {
            announcements_valid: HashMap<CaHandle, usize>,
            announcements_invalid_asn: HashMap<CaHandle, usize>,
            announcements_invalid_length: HashMap<CaHandle, usize>,
            announcements_not_found: HashMap<CaHandle, usize>,
            roas_too_permissive: HashMap<CaHandle, usize>,
            roas_redundant: HashMap<CaHandle, usize>,
            roas_stale: HashMap<CaHandle, usize>,
            roas_total: HashMap<CaHandle, usize>,
        }

        impl AllBgpStats {
            fn add_ca(&mut self, ca: &CaHandle, stats: &BgpStats) {
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
        res.push_str("# HELP krill_server_start unix timestamp in seconds of last krill server start\n");
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

        if let Ok(cas_stats) = server.cas_stats().await {
            let number_cas = cas_stats.len();

            res.push('\n');
            res.push_str("# HELP krill_cas number of cas in krill\n");
            res.push_str("# TYPE krill_cas gauge\n");
            res.push_str(&format!("krill_cas {}\n", number_cas));

            if !server.config.metrics.metrics_hide_ca_details {
                // Show per CA details

                let mut ca_status_map: HashMap<CaHandle, CaStatus> = HashMap::new();

                for ca in cas_stats.keys() {
                    if let Ok(ca_status) = server.ca_status(ca).await {
                        ca_status_map.insert(ca.clone(), ca_status);
                    }
                }

                {
                    // CA -> Parent metrics

                    // krill_ca_parent_success{{ca="ca", parent="parent"}} 1
                    // krill_ca_parent_last_success_time{{ca="ca", parent="parent"}} 1630921599 // timestamp

                    res.push('\n');
                    res.push_str(
                        "# HELP krill_ca_parent_success status of last CA to parent connection (0=issue, 1=success)\n",
                    );
                    res.push_str("# TYPE krill_ca_parent_success gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        if ca.as_str() != TA_NAME {
                            for (parent, status) in status.parents().iter() {
                                // skip the ones for which we have no status yet, i.e it was really only just added
                                // and no attempt to connect has yet been made.
                                if let Some(exchange) = status.last_exchange() {
                                    res.push_str(&format!(
                                        "krill_ca_parent_success{{ca=\"{}\", parent=\"{}\"}} {}\n",
                                        ca,
                                        parent,
                                        i32::from(exchange.was_success())
                                    ));
                                }
                            }
                        }
                    }

                    res.push('\n');
                    res.push_str(
                    "# HELP krill_ca_parent_last_success_time unix timestamp in seconds of last successful CA to parent connection\n",
                );
                    res.push_str("# TYPE krill_ca_parent_last_success_time gauge\n");

                    for (ca, status) in ca_status_map.iter() {
                        if ca.as_str() != TA_NAME {
                            for (parent, status) in status.parents().iter() {
                                // skip the ones for which we have no successful connection at all. Most likely
                                // they were just added (in which case it will come) - or were never successful
                                // in which case the metric above will say that the status is 0
                                if let Some(last_success) = status.last_success() {
                                    res.push_str(&format!(
                                        "krill_ca_parent_last_success_time{{ca=\"{}\", parent=\"{}\"}} {}\n",
                                        ca, parent, last_success
                                    ));
                                }
                            }
                        }
                    }
                }

                {
                    // CA -> Publication Server status

                    // krill_ca_repo_success{{ca="ca"}} 1
                    // krill_ca_repo_last_success_time{{ca="ca"}} 1630921599
                    // krill_ca_repo_next_before_time{{ca="ca"}} 1630921599

                    res.push('\n');
                    res.push_str("# HELP krill_ca_ps_success status of last CA to Publication Server connection (0=issue, 1=success)\n");
                    res.push_str("# TYPE krill_ca_ps_success gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.
                        if let Some(exchange) = status.repo().last_exchange() {
                            res.push_str(&format!(
                                "krill_ca_ps_success{{ca=\"{}\"}} {}\n",
                                ca,
                                i32::from(exchange.was_success())
                            ));
                        }
                    }

                    res.push('\n');
                    res.push_str("# HELP krill_ca_ps_last_success_time unix timestamp in seconds of last successful CA to Publication Server connection\n");
                    res.push_str("# TYPE krill_ca_ps_last_success_time gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.
                        if let Some(last_success) = status.repo().last_success() {
                            res.push_str(&format!(
                                "krill_ca_ps_last_success_time{{ca=\"{}\"}} {}\n",
                                ca, last_success
                            ));
                        }
                    }
                }

                // Do not show child metrics if none of the CAs has any children..
                // Many users do not delegate so, showing these metrics would just be confusing.
                let any_children = cas_stats.values().any(|ca| ca.child_count() > 0);

                if any_children && !server.config.metrics.metrics_hide_child_details {
                    // CA -> Children

                    // krill_cas_children{ca="parent"} 11 // nr of children
                    // krill_ca_child_success{ca="parent", child="child"} 1
                    // krill_ca_child_state{ca="parent", child="child"} 1
                    // krill_ca_child_last_connection{ca="parent", child="child"} 1630921599
                    // krill_ca_child_last_success{ca="parent", child="child"} 1630921599
                    // krill_ca_child_agent_total{ca="parent", ua="krill/0.9.2"} 11

                    res.push('\n');
                    res.push_str("# HELP krill_cas_children number of children for CA\n");
                    res.push_str("# TYPE krill_cas_children gauge\n");
                    for (ca, status) in cas_stats.iter() {
                        res.push_str(&format!(
                            "krill_cas_children{{ca=\"{}\"}} {}\n",
                            ca,
                            status.child_count()
                        ));
                    }

                    res.push('\n');
                    res.push_str(
                        "# HELP krill_ca_child_success status of last child to CA connection (0=issue, 1=success)\n",
                    );
                    res.push_str("# TYPE krill_ca_child_success gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.
                        for (child, status) in status.children().iter() {
                            if let Some(exchange) = status.last_exchange() {
                                res.push_str(&format!(
                                    "krill_ca_child_success{{ca=\"{}\", child=\"{}\"}} {}\n",
                                    ca,
                                    child,
                                    i32::from(exchange.was_success())
                                ));
                            }
                        }
                    }

                    res.push('\n');
                    res.push_str(
                        "# HELP krill_ca_child_state child state (see 'suspend_child_after_inactive_hours' config) (0=suspended, 1=active)\n",
                    );
                    res.push_str("# TYPE krill_ca_child_state gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        for (child, status) in status.children().iter() {
                            res.push_str(&format!(
                                "krill_ca_child_state{{ca=\"{}\", child=\"{}\"}} {}\n",
                                ca,
                                child,
                                i32::from(status.suspended().is_none())
                            ));
                        }
                    }

                    res.push('\n');
                    res.push_str("# HELP krill_ca_child_last_connection unix timestamp in seconds of last child to CA connection\n");
                    res.push_str("# TYPE krill_ca_child_last_connection gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.
                        for (child, status) in status.children().iter() {
                            if let Some(exchange) = status.last_exchange() {
                                let timestamp = exchange.timestamp();
                                res.push_str(&format!(
                                    "krill_ca_child_last_connection{{ca=\"{}\", child=\"{}\"}} {}\n",
                                    ca, child, timestamp
                                ));
                            }
                        }
                    }

                    res.push('\n');
                    res.push_str(
                    "# HELP krill_ca_child_last_success unix timestamp in seconds of last successful child to CA connection\n",
                );
                    res.push_str("# TYPE krill_ca_child_last_success gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.
                        for (child, status) in status.children().iter() {
                            if let Some(time) = status.last_success() {
                                res.push_str(&format!(
                                    "krill_ca_child_last_success{{ca=\"{}\", child=\"{}\"}} {}\n",
                                    ca, child, time
                                ));
                            }
                        }
                    }

                    res.push('\n');
                    res.push_str(
                    "# HELP krill_ca_child_agent_total total children per user agent based on their last connection\n",
                );
                    res.push_str("# TYPE krill_ca_child_agent_total gauge\n");
                    for (ca, status) in ca_status_map.iter() {
                        // skip the ones for which we have no status yet, i.e it was really only just added
                        // and no attempt to connect has yet been made.

                        let mut user_agent_totals: HashMap<String, usize> = HashMap::new();
                        for status in status.children().values() {
                            if let Some(exchange) = status.last_exchange() {
                                let agent = exchange.user_agent().cloned().unwrap_or_else(|| "<none>".to_string());
                                *user_agent_totals.entry(agent).or_insert(0) += 1;
                            }
                        }

                        for (ua, total) in user_agent_totals.iter() {
                            res.push_str(&format!(
                                "krill_ca_child_agent_total{{ca=\"{}\", user_agent=\"{}\"}} {}\n",
                                ca, ua, total
                            ));
                        }
                    }
                }

                if !server.config.metrics.metrics_hide_roa_details {
                    // BGP Announcement metrics

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

                    for (ca, ca_stats) in cas_stats.iter() {
                        all_bgp_stats.add_ca(ca, ca_stats.bgp_stats());
                    }

                    res.push('\n');
                    res.push_str("# HELP krill_cas_bgp_announcements_valid number of announcements seen for CA resources with RPKI state VALID\n");
                    res.push_str("# TYPE krill_cas_bgp_announcements_valid gauge\n");
                    for (ca, nr) in all_bgp_stats.announcements_valid.iter() {
                        res.push_str(&format!("krill_cas_bgp_announcements_valid{{ca=\"{}\"}} {}\n", ca, nr));
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
            }
        }

        if let Ok(stats) = server.repo_stats() {
            let publishers = stats.get_publishers();

            res.push('\n');
            res.push_str("# HELP krill_repo_publisher number of publishers in repository\n");
            res.push_str("# TYPE krill_repo_publisher gauge\n");
            res.push_str(&format!("krill_repo_publisher {}\n", publishers.len()));

            if let Some(last_update) = stats.last_update() {
                res.push('\n');
                res.push_str(
                    "# HELP krill_repo_rrdp_last_update unix timestamp in seconds of last update by any publisher\n",
                );
                res.push_str("# TYPE krill_repo_rrdp_last_update gauge\n");
                res.push_str(&format!("krill_repo_rrdp_last_update {}\n", last_update.timestamp()));
            }

            res.push('\n');
            res.push_str("# HELP krill_repo_rrdp_serial RRDP serial\n");
            res.push_str("# TYPE krill_repo_rrdp_serial counter\n");
            res.push_str(&format!("krill_repo_rrdp_serial {}\n", stats.serial()));

            if !server.config.metrics.metrics_hide_publisher_details {
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
                res.push_str("# HELP krill_repo_last_update unix timestamp in seconds of last update for publisher\n");
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
    match req.state().ta_cert_details().await {
        Ok(ta) => Ok(HttpResponse::text(format!("{}", ta.tal()).into_bytes())),
        Err(_) => render_unknown_resource(),
    }
}

pub async fn ta_cer(req: Request) -> RoutingResult {
    match req.state().trust_anchor_cert().await {
        Some(cert) => Ok(HttpResponse::cert(cert.to_bytes().to_vec())),
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
                        Some("ta") => aa!(req, Permission::CA_ADMIN, api_ta(req, &mut path).await),
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
        "/api/v1/bulk/cas/import" => api_cas_import(req).await,
        "/api/v1/bulk/cas/issues" => api_all_ca_issues(req).await,
        "/api/v1/bulk/cas/sync/parent" => api_refresh_all(req).await,
        "/api/v1/bulk/cas/sync/repo" => api_resync_all(req).await,
        "/api/v1/bulk/cas/publish" => api_republish_all(req, false).await,
        "/api/v1/bulk/cas/force_publish" => api_republish_all(req, true).await,
        "/api/v1/bulk/cas/suspend" => api_suspend_all(req).await,
        _ => render_unknown_method(),
    }
}

async fn api_cas(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.path_arg::<CaHandle>() {
        Some(ca) => aa!(req, Permission::CA_READ, Handle::from(&ca), {
            match path.next() {
                None => match *req.method() {
                    Method::GET => api_ca_info(req, ca).await,
                    Method::DELETE => api_ca_delete(req, ca).await,
                    _ => render_unknown_method(),
                },
                Some("aspas") => api_ca_aspas(req, path, ca).await,
                Some("bgpsec") => api_ca_bgpsec(req, path, ca).await,
                Some("children") => api_ca_children(req, path, ca).await,
                Some("history") => api_ca_history(req, path, ca).await,

                Some("id") => api_ca_id(req, path, ca).await,
                Some("issues") => api_ca_issues(req, ca).await,
                Some("keys") => api_ca_keys(req, path, ca).await,
                Some("parents") => api_ca_parents(req, path, ca).await,
                Some("repo") => api_ca_repo(req, path, ca).await,
                Some("routes") => api_ca_routes(req, path, ca).await,
                Some("stats") => api_ca_stats(req, path, ca).await,
                Some("sync") => api_ca_sync(req, path, ca).await,

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

async fn api_ca_keys(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::POST => match path.next() {
            Some("roll_init") => api_ca_kr_init(req, ca).await,
            Some("roll_activate") => api_ca_kr_activate(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_ca_parents(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
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

async fn api_ca_repo(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
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

async fn api_ca_routes(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
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

async fn api_ca_stats(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    match path.next() {
        Some("children") => match path.next() {
            Some("connections") => api_ca_stats_child_connections(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_ca_sync(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        if req.is_post() {
            match path.next() {
                Some("parents") => render_empty_res(req.state().cas_refresh_single(ca).await),
                Some("repo") => render_empty_res(req.state().cas_repo_sync_single(&ca)),
                _ => render_unknown_method(),
            }
        } else {
            render_unknown_method()
        }
    })
}

async fn api_publication_server(req: Request, path: &mut RequestPath) -> RoutingResult {
    match path.next() {
        Some("publishers") => api_publishers(req, path).await,
        Some("delete") => match *req.method() {
            Method::POST => {
                let state = req.state.clone();

                match req.json().await {
                    Ok(criteria) => render_empty_res(state.delete_matching_files(criteria)),
                    Err(e) => render_error(e),
                }
            }
            _ => render_unknown_method(),
        },
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
        Some("session_reset") => match *req.method() {
            Method::POST => render_empty_res(req.state().repository_session_reset()),
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
pub async fn api_remove_pbl(req: Request, publisher: PublisherHandle) -> RoutingResult {
    aa!(req, Permission::PUB_DELETE, {
        let actor = req.actor();
        render_empty_res(req.state().remove_publisher(publisher, &actor))
    })
}

/// Returns a json structure with publisher details
#[allow(clippy::redundant_clone)] // false positive
pub async fn api_show_pbl(req: Request, publisher: PublisherHandle) -> RoutingResult {
    aa!(
        req,
        Permission::PUB_READ,
        render_json_res(req.state().get_publisher(&publisher))
    )
}

//------------ repository_response ---------------------------------------------

#[allow(clippy::redundant_clone)] // false positive
pub async fn api_repository_response_xml(req: Request, publisher: PublisherHandle) -> RoutingResult {
    aa!(req, Permission::PUB_READ, {
        match repository_response(&req, &publisher).await {
            Ok(repository_response) => Ok(HttpResponse::xml(repository_response.to_xml_vec())),
            Err(e) => render_error(e),
        }
    })
}

#[allow(clippy::redundant_clone)] // false positive
pub async fn api_repository_response_json(req: Request, publisher: PublisherHandle) -> RoutingResult {
    aa!(req, Permission::PUB_READ, {
        match repository_response(&req, &publisher).await {
            Ok(res) => render_json(res),
            Err(e) => render_error(e),
        }
    })
}

async fn repository_response(
    req: &Request,
    publisher: &PublisherHandle,
) -> Result<idexchange::RepositoryResponse, Error> {
    req.state().repository_response(publisher)
}

pub async fn api_ca_add_child(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(child_req) => render_json_res(server.ca_add_child(&ca, child_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_child_update(req: Request, ca: CaHandle, child: ChildHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(child_req) => render_empty_res(server.ca_child_update(&ca, child, child_req, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

pub async fn api_ca_child_remove(req: Request, ca: CaHandle, child: ChildHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        render_empty_res(req.state().ca_child_remove(&ca, child, &actor).await)
    })
}

async fn api_ca_child_show(req: Request, ca: CaHandle, child: ChildHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().ca_child_show(&ca, &child).await)
    )
}

async fn api_ca_child_export(req: Request, ca: CaHandle, child: ChildHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().api_ca_child_export(&ca, &child).await)
    )
}

async fn api_ca_child_import(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::CA_ADMIN, Handle::from(&ca), {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(import_child) => render_empty_res(server.api_ca_child_import(&ca, import_child, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_stats_child_connections(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().ca_stats_child_connections(&ca).await)
    )
}

async fn api_ca_parent_res_json(req: Request, ca: CaHandle, child: ChildHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().ca_parent_response(&ca, child.clone()).await)
    )
}

pub async fn api_ca_parent_res_xml(req: Request, ca: CaHandle, child: ChildHandle) -> RoutingResult {
    aa!(req, Permission::CA_READ, Handle::from(&ca), {
        match req.state().ca_parent_response(&ca, child.clone()).await {
            Ok(res) => Ok(HttpResponse::xml(res.to_xml_vec())),
            Err(e) => render_error(e),
        }
    })
}

//------------ Admin: CertAuth -----------------------------------------------

async fn api_cas_import(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            let server = req.state().clone();
            match req.json().await {
                Ok(structure) => render_empty_res(server.cas_import(structure).await),
                Err(e) => render_error(e),
            }
        }),
        _ => render_unknown_method(),
    }
}

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
async fn api_ca_issues(req: Request, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            Handle::from(&ca),
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

async fn api_ca_id(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
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

async fn api_ca_info(req: Request, handle: CaHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&handle),
        render_json_res(req.state().ca_info(&handle).await)
    )
}

async fn api_ca_delete(req: Request, handle: CaHandle) -> RoutingResult {
    let actor = req.actor();
    aa!(
        req,
        Permission::CA_DELETE,
        Handle::from(&handle),
        render_json_res(req.state().ca_delete(&handle, &actor).await)
    )
}

async fn api_ca_my_parent_contact(req: Request, ca: CaHandle, parent: ParentHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().ca_my_parent_contact(&ca, &parent).await)
    )
}

async fn api_ca_my_parent_statuses(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().ca_status(&ca).await.map(|s| s.parents().clone()))
    )
}

async fn api_ca_aspas(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    match path.next() {
        None => match *req.method() {
            Method::GET => api_ca_aspas_definitions_show(req, ca).await,
            Method::POST => api_ca_aspas_definitions_update(req, ca).await,
            _ => render_unknown_method(),
        },
        // We may need other functions in future, such as 'analyze' or 'try'.
        // So keep the base namespace clean and use '/api/v1/aspas/as/<asn>/..'
        // for functions on specific ASPA definitions for the given (customer)
        // ASN.
        Some("as") => {
            // get as path parameter, or error
            // - get (specific definition)
            // - delete
            // - update? (definition includes the ASN so this can be in the base path)
            match path.path_arg() {
                Some(customer) => match *req.method() {
                    Method::POST => api_ca_aspas_update_aspa(req, ca, customer).await,
                    Method::DELETE => api_ca_aspas_delete(req, ca, customer).await,
                    _ => render_unknown_method(),
                },
                None => render_unknown_method(),
            }
        }
        _ => render_unknown_method(),
    }
}

async fn api_ca_bgpsec(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    // Handles /api/v1/cas/{ca}/bgpsec/:
    //    GET  /api/v1/cas/{ca}/bgpsec/ -> List BGPSec Definitions
    //    POST /api/v1/cas/{ca}/bgpsec/ -> Send BgpSecDefinitionUpdates
    match path.next() {
        None => match *req.method() {
            Method::GET => api_ca_bgpsec_definitions_show(req, ca).await,
            Method::POST => api_ca_bgpsec_definitions_update(req, ca).await,
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

async fn api_ca_bgpsec_definitions_show(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::BGPSEC_READ, Handle::from(&ca), {
        render_json_res(req.state().ca_bgpsec_definitions_show(ca).await)
    })
}

async fn api_ca_bgpsec_definitions_update(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::BGPSEC_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let server = req.state().clone();
        match req.json().await {
            Ok(updates) => render_empty_res(server.ca_bgpsec_definitions_update(ca, updates, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_children(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    match path.path_arg() {
        Some(child) => match path.next() {
            None => match *req.method() {
                Method::GET => api_ca_child_show(req, ca, child).await,
                Method::POST => api_ca_child_update(req, ca, child).await,
                Method::DELETE => api_ca_child_remove(req, ca, child).await,
                _ => render_unknown_method(),
            },
            Some("contact") | Some("parent_response.json") => api_ca_parent_res_json(req, ca, child).await,
            Some("parent_response.xml") => api_ca_parent_res_xml(req, ca, child).await,
            Some("export") => api_ca_child_export(req, ca, child).await,
            Some("import") => api_ca_child_import(req, ca).await,
            _ => render_unknown_method(),
        },
        None => match *req.method() {
            Method::POST => api_ca_add_child(req, ca).await,
            _ => render_unknown_method(),
        },
    }
}

async fn api_ca_history_commands(req: Request, path: &mut RequestPath, handle: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(req, Permission::CA_READ, Handle::from(&handle), {
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

async fn api_ca_history(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    match path.next() {
        Some("details") => api_ca_command_details(req, path, ca).await,
        Some("commands") => api_ca_history_commands(req, path, ca).await,
        _ => render_unknown_method(),
    }
}

#[allow(clippy::redundant_clone)] // false positive
async fn api_ca_command_details(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    // /api/v1/cas/{ca}/command/<command-key>
    match path.path_arg() {
        Some(key) => match *req.method() {
            Method::GET => aa!(req, Permission::CA_READ, Handle::from(&ca), {
                match req.state().ca_command_details(&ca, key) {
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

async fn api_ca_child_req_xml(req: Request, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            Handle::from(&ca),
            match ca_child_req(&req, &ca).await {
                Ok(child_request) => Ok(HttpResponse::xml(child_request.to_xml_vec())),
                Err(e) => render_error(e),
            }
        ),
        _ => render_unknown_method(),
    }
}

async fn api_ca_child_req_json(req: Request, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            Handle::from(&ca),
            match ca_child_req(&req, &ca).await {
                Ok(req) => render_json(req),
                Err(e) => render_error(e),
            }
        ),
        _ => render_unknown_method(),
    }
}

async fn ca_child_req(req: &Request, ca: &CaHandle) -> Result<idexchange::ChildRequest, Error> {
    req.state().ca_child_req(ca).await
}

async fn api_ca_publisher_req_json(req: Request, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            Handle::from(&ca),
            render_json_res(req.state().ca_publisher_req(&ca).await)
        ),
        _ => render_unknown_method(),
    }
}

async fn api_ca_publisher_req_xml(req: Request, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            Handle::from(&ca),
            match req.state().ca_publisher_req(&ca).await {
                Ok(publisher_request) => Ok(HttpResponse::xml(publisher_request.to_xml_vec())),
                Err(e) => render_error(e),
            }
        ),
        _ => render_unknown_method(),
    }
}

async fn api_ca_repo_details(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(
        req,
        Permission::CA_READ,
        Handle::from(&ca),
        render_json_res(req.state().ca_repo_details(&ca).await)
    )
}

async fn api_ca_repo_status(req: Request, ca: CaHandle) -> RoutingResult {
    match *req.method() {
        Method::GET => aa!(
            req,
            Permission::CA_READ,
            Handle::from(&ca),
            render_json_res(req.state().ca_status(&ca).await.map(|status| status.repo().clone()))
        ),
        _ => render_unknown_method(),
    }
}

fn extract_repository_contact(ca: &CaHandle, bytes: Bytes) -> Result<RepositoryContact, Error> {
    let string = String::from_utf8(bytes.to_vec()).map_err(Error::custom)?;

    // Get rid of whitespace first so we can check if it smells like XML.
    // We could change this to check for Content-Type headers instead.
    let string = string.trim();

    if string.starts_with('<') {
        if string.contains("<parent_response") {
            Err(Error::CaRepoResponseWrongXml(ca.clone()))
        } else {
            let response = idexchange::RepositoryResponse::parse(string.as_bytes())
                .map_err(|e| Error::CaRepoResponseInvalid(ca.clone(), e.to_string()))?;

            RepositoryContact::for_response(response)
                .map_err(|e| Error::CaRepoResponseInvalid(ca.clone(), e.to_string()))
        }
    } else {
        let api_contact: ApiRepositoryContact = serde_json::from_str(string).map_err(Error::JsonError)?;
        api_contact.try_into()
    }
}

async fn api_ca_repo_update(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let server = req.state().clone();

        match req
            .api_bytes()
            .await
            .map(|bytes| extract_repository_contact(&ca, bytes))
        {
            Ok(Ok(update)) => render_empty_res(server.ca_repo_update(ca, update, &actor).await),
            Ok(Err(e)) | Err(e) => render_error(e),
        }
    })
}

async fn api_ca_parent_add_or_update(
    req: Request,
    ca: CaHandle,
    parent_override: Option<ParentHandle>,
) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
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

fn extract_parent_ca_req(
    ca: &CaHandle,
    bytes: Bytes,
    parent_override: Option<ParentHandle>,
) -> Result<ParentCaReq, Error> {
    let string = String::from_utf8(bytes.to_vec()).map_err(Error::custom)?;

    // Get rid of whitespace first so we can check if it smells like XML.
    // We could change this to check for Content-Type headers instead.
    let string = string.trim();
    let req = if string.starts_with('<') {
        if string.starts_with("<repository") {
            return Err(Error::CaParentResponseWrongXml(ca.clone()));
        } else {
            let response = idexchange::ParentResponse::parse(string.as_bytes())
                .map_err(|e| Error::CaParentResponseInvalid(ca.clone(), e.to_string()))?;

            let parent_name = parent_override.unwrap_or_else(|| response.parent_handle().clone());

            ParentCaReq::new(parent_name, response)
        }
    } else {
        let req: ParentCaReq = serde_json::from_str(string).map_err(Error::JsonError)?;
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

async fn api_ca_remove_parent(req: Request, ca: CaHandle, parent: ParentHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        render_empty_res(req.state().ca_parent_remove(ca, parent, &actor).await)
    })
}

/// Force a key roll for a CA, i.e. use a max key age of 0 seconds.
async fn api_ca_kr_init(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        render_empty_res(req.state().ca_keyroll_init(ca, &actor).await)
    })
}

/// Force key activation for all new keys, i.e. use a staging period of 0 seconds.
async fn api_ca_kr_activate(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::CA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        render_empty_res(req.state().ca_keyroll_activate(ca, &actor).await)
    })
}

// -- ASPA functions

/// List the current ASPA definitions for a CA
async fn api_ca_aspas_definitions_show(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::ASPAS_READ, Handle::from(&ca), {
        let state = req.state().clone();
        render_json_res(state.ca_aspas_definitions_show(ca).await)
    })
}

/// Add a new ASPA definition for a CA based on the update in the POST
async fn api_ca_aspas_definitions_update(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::ASPAS_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Err(e) => render_error(e),
            Ok(updates) => render_empty_res(state.ca_aspas_definitions_update(ca, updates, &actor).await),
        }
    })
}

/// Update an existing ASPA definition for a CA based on the update in the POST
async fn api_ca_aspas_update_aspa(req: Request, ca: CaHandle, customer: Asn) -> RoutingResult {
    aa!(req, Permission::ASPAS_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Err(e) => render_error(e),
            Ok(update) => render_empty_res(state.ca_aspas_update_aspa(ca, customer, update, &actor).await),
        }
    })
}

/// Delete the ASPA definition for the given CA and customer ASN
async fn api_ca_aspas_delete(req: Request, ca: CaHandle, customer: Asn) -> RoutingResult {
    aa!(req, Permission::ASPAS_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();

        let updates = AspaDefinitionUpdates::new(vec![], vec![customer]);
        render_empty_res(state.ca_aspas_definitions_update(ca, updates, &actor).await)
    })
}

/// Update the route authorizations for this CA
async fn api_ca_routes_update(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::ROUTES_UPDATE, Handle::from(&ca), {
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
async fn api_ca_routes_try_update(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::ROUTES_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json::<RoaConfigurationUpdates>().await {
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
                            let updates = updates.into_explicit_max_length();
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
async fn api_ca_routes_show(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::ROUTES_READ, Handle::from(&ca), {
        match req.state().ca_routes_show(&ca).await {
            Ok(roas) => render_json(roas),
            Err(_) => render_unknown_resource(),
        }
    })
}

/// Show the state of ROAs vs BGP for this CA
async fn api_ca_routes_analysis(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
    aa!(req, Permission::ROUTES_ANALYSIS, Handle::from(&ca), {
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

async fn api_republish_all(req: Request, force: bool) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            render_empty_res(req.state().republish_all(force).await)
        }),
        _ => render_unknown_method(),
    }
}

async fn api_resync_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            let actor = req.actor();
            render_empty_res(req.state().cas_repo_sync_all(&actor))
        }),
        _ => render_unknown_method(),
    }
}

/// Refresh all CAs
async fn api_refresh_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            render_empty_res(req.state().cas_refresh_all().await)
        }),
        _ => render_unknown_method(),
    }
}

/// Schedule check suspend for all CAs
async fn api_suspend_all(req: Request) -> RoutingResult {
    match *req.method() {
        Method::POST => aa!(req, Permission::CA_ADMIN, {
            render_empty_res(req.state().cas_schedule_suspend_all())
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

        match File::open(&full_path) {
            Ok(mut file) if full_path.is_file() => {
                let mut buffer = Vec::new();
                match file.read_to_end(&mut buffer) {
                    Ok(_) => Ok(HttpResponse::xml_with_cache(buffer, cache_seconds)),
                    Err(_) => Ok(HttpResponse::not_found()),
                }
            }
            _ => Ok(HttpResponse::not_found()),
        }
    }
}

//------------ Support Resource Tagged Attestations (RTA) ----------------------

async fn api_ca_rta(req: Request, path: &mut RequestPath, ca: CaHandle) -> RoutingResult {
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

async fn api_ca_rta_list(req: Request, ca: CaHandle) -> RoutingResult {
    aa!(
        req,
        Permission::RTA_LIST,
        Handle::from(&ca),
        render_json_res(req.state().rta_list(ca).await)
    )
}

async fn api_ca_rta_show(req: Request, ca: CaHandle, name: RtaName) -> RoutingResult {
    aa!(
        req,
        Permission::RTA_READ,
        Handle::from(&ca),
        render_json_res(req.state().rta_show(ca, name).await)
    )
}

async fn api_ca_rta_sign(req: Request, ca: CaHandle, name: RtaName) -> RoutingResult {
    aa!(req, Permission::RTA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();
        match req.json().await {
            Err(e) => render_error(e),
            Ok(request) => render_empty_res(state.rta_sign(ca, name, request, &actor).await),
        }
    })
}

async fn api_ca_rta_multi_prep(req: Request, ca: CaHandle, name: RtaName) -> RoutingResult {
    aa!(req, Permission::RTA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();

        match req.json().await {
            Ok(resources) => render_json_res(state.rta_multi_prep(ca, name, resources, &actor).await),
            Err(e) => render_error(e),
        }
    })
}

async fn api_ca_rta_multi_sign(req: Request, ca: CaHandle, name: RtaName) -> RoutingResult {
    aa!(req, Permission::RTA_UPDATE, Handle::from(&ca), {
        let actor = req.actor();
        let state = req.state().clone();
        match req.json().await {
            Ok(rta) => render_empty_res(state.rta_multi_cosign(ca, name, rta, &actor).await),
            Err(_) => render_error(Error::custom("Cannot decode RTA for co-signing")),
        }
    })
}

//-------------------------------- API TA --------------------------------------------------
async fn api_ta(req: Request, path: &mut RequestPath) -> RoutingResult {
    //
    // krillta proxy --server .. --token ..
    //
    // Uses API krill API:
    //
    // /api/v1/ta/
    //
    //    - proxy and signer set up
    //    POST /proxy/init                     initialise proxy
    //    POST /proxy/id                       proxy id cert info
    //    GET  /proxy/repo/request.xml         get RFC8181 publisher request
    //    GET  /proxy/repo/request.json        get RFC8181 publisher request
    //    GET  /proxy/repo                     get repository contact
    //    POST /proxy/repo                     add pub server
    //    POST /proxy/signer/add               add initialised signer to proxy
    //    POST /proxy/signer/request           create sign request for signer (returns request)
    //    GET  /proxy/signer/request           show open sign request if any
    //    POST /proxy/signer/response          process sign response from signer
    //
    //    - children
    //    GET  /proxy/children/                 future: list children
    //    POST /proxy/children/                 add child
    //    GET  /proxy/children/{child}/parent_response.json    show parent response for child
    //    GET  /proxy/children/{child}/parent_response.xml    show parent response for child
    //    POST /proxy/children/{child}          future: update child
    //    DEL  /proxy/children/{child}          future: remove child
    //
    // krillta signer --dir
    //            init
    //            process
    //            history (future)
    //            response <nonce>

    match path.next() {
        Some("proxy") => match path.next() {
            Some("init") => render_empty_res(req.state().ta_proxy_init().await),
            Some("id") => render_json_res(req.state().ta_proxy_id().await),
            Some("repo") => match path.next() {
                Some("request.xml") => match req.state().ta_proxy_publisher_request().await {
                    Ok(req) => Ok(HttpResponse::xml(req.to_xml_vec())),
                    Err(e) => render_error(e),
                },
                Some("request.json") => render_json_res(req.state().ta_proxy_publisher_request().await),
                None => match *req.method() {
                    Method::POST => {
                        let ta_handle = ta::ta_handle();
                        let server = req.state().clone();
                        let actor = req.actor.clone();

                        match req
                            .api_bytes()
                            .await
                            .map(|bytes| extract_repository_contact(&ta_handle, bytes))
                        {
                            Ok(Ok(contact)) => {
                                render_empty_res(server.ta_proxy_repository_update(contact, &actor).await)
                            }
                            Ok(Err(e)) | Err(e) => render_error(e),
                        }
                    }
                    Method::GET => render_json_res(req.state().ta_proxy_repository_contact().await),
                    _ => render_unknown_method(),
                },

                _ => render_unknown_method(),
            },
            Some("signer") => match path.next() {
                Some("add") => {
                    let server = req.state().clone();
                    let actor = req.actor.clone();
                    match req.json().await {
                        Ok(ta_signer_info) => {
                            render_empty_res(server.ta_proxy_signer_add(ta_signer_info, &actor).await)
                        }
                        Err(e) => render_error(e),
                    }
                }
                Some("request") => match *req.method() {
                    Method::POST => render_json_res(req.state().ta_proxy_signer_make_request(&req.actor()).await),
                    Method::GET => render_json_res(req.state().ta_proxy_signer_get_request().await),
                    _ => render_unknown_method(),
                },
                Some("response") => match *req.method() {
                    Method::POST => {
                        let server = req.state().clone();
                        let actor = req.actor.clone();

                        match req.json().await {
                            Ok(response) => {
                                render_empty_res(server.ta_proxy_signer_process_response(response, &actor).await)
                            }
                            Err(e) => render_error(e),
                        }
                    }
                    _ => render_unknown_method(),
                },
                _ => render_unknown_method(),
            },
            Some("children") => match path.path_arg::<ChildHandle>() {
                Some(child) => match path.next() {
                    Some("parent_response.json") => {
                        render_json_res(req.state().ca_parent_response(&ta::ta_handle(), child).await)
                    }
                    Some("parent_response.xml") => {
                        match req.state().ca_parent_response(&ta::ta_handle(), child).await {
                            Ok(parent_response) => Ok(HttpResponse::xml(parent_response.to_xml_vec())),
                            Err(e) => render_error(e),
                        }
                    }
                    None => match *req.method() {
                        Method::POST => render_error(Error::custom("update TA child not yet supported")),
                        Method::DELETE => render_error(Error::custom("remove TA child not yet supported")),
                        _ => render_unknown_method(),
                    },
                    _ => render_unknown_method(),
                },
                None => match *req.method() {
                    Method::POST => {
                        let actor = req.actor();
                        let server = req.state().clone();
                        match req.json().await {
                            Ok(child_req) => render_json_res(server.ta_proxy_children_add(child_req, &actor).await),
                            Err(e) => render_error(e),
                        }
                    }
                    Method::GET => render_error(Error::custom("show TA child not yet supported")),
                    _ => render_unknown_method(),
                },
            },
            _ => render_unknown_method(),
        },
        _ => render_unknown_method(),
    }
}

//------------ Tests ---------------------------------------------------------
#[cfg(test)]
mod tests {
    // NOTE: This is extensively tested through the functional and e2e tests found under
    //       the $project/tests dir
    use crate::test;

    #[tokio::test]
    async fn start_krill_daemon() {
        let cleanup = test::start_krill_with_default_test_config(false, false, false, false).await;

        cleanup();
    }

    #[tokio::test]
    async fn start_krill_pubd_daemon() {
        let cleanup = test::start_krill_pubd(0).await;

        cleanup();
    }
}
