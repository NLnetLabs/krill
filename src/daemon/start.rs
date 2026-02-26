//! Starts and then runs the Krill daemon.
//!
//! Despite its name, this module contains the core game loop of Krill. It
//! provides both the socket listeners and connection handlers for the HTTP
//! server and sets everything up. All of this is provided via the
//! [`start_krill_daemon`] function.

use std::{env, process};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use clap::crate_version;
use log::{error, info, warn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use crate::commons::file;
use crate::commons::error::{Error, Error as KrillError};
use crate::commons::version::KrillVersion;
use crate::config::Config;
use crate::constants::{KRILL_ENV_UPGRADE_ONLY, KRILL_SERVER_APP};
use crate::server::properties::PropertiesManager;
use crate::server::manager::StartupManager;
use crate::upgrades::{
    finalise_data_migration, post_start_upgrade,
    prepare_upgrade_data_migrations, UpgradeError, UpgradeMode,
};
use super::http::{tls, tls_keys};
use super::http::server::HttpServer;


//------------ start_krill_daemon --------------------------------------------

/// Starts the Krill daemon and blocks until it exits.
///
/// The configuration of the Krill daemon and server is taken from `config`.
///
/// If `signal_running` is given, a `()` will be sent to it once the first
/// listener socket is ready to process requests.
///
/// If `signal_exit` is given, the daemon will exit when a `()` is sent to
/// the channel. Otherwise it waits for a SIGINT or SIGTERM or a fatal
/// error happening.
///
/// The function will return an error if something goes wrong during startup.
/// Once it blocks waiting for an exit, it will return `Ok(())` even if
/// something went wrong. In this case, an error message will be logged,
pub fn start_krill_daemon(
    config: Config,
    mut signal_running: Option<oneshot::Sender<()>>,
    signal_exit: Option<oneshot::Receiver<()>>,
) -> Result<(), Error> {
    info!("Starting {} v{}", KRILL_SERVER_APP, crate_version!());

    write_pid_file_or_die(&config);
    test_data_dirs_or_die(&config);

    // Set up the runtime properties manager, so that we can check
    // the version used for the current data in storage
    let properties_manager = PropertiesManager::create(
        &config.storage_uri,
        config.use_history_cache,
    )?;

    // Call upgrade, this will only do actual work if needed.
    let upgrade_report = prepare_upgrade_data_migrations(
        UpgradeMode::PrepareToFinalise, &config, &properties_manager
    ).map_err(|e| {
        match e {
            UpgradeError::CodeOlderThanData(_,_) => {
                Error::Custom(e.to_string())
            },
            _ => {
                Error::Custom(format!(
                    "Upgrade data migration failed with error: {e}\n\n\
                     NOTE: your data was not changed. Please downgrade \
                     your krill instance to your previous version."
                ))
            }
        }
    })?;

    if let Some(report) = &upgrade_report {
        finalise_data_migration(
            report.versions(), &config, &properties_manager
        ).map_err(|e| {
            Error::Custom(format!(
                "Finishing prepared migration failed unexpectedly. Please \
                 check your data {}. If you find folders named \
                 'arch-cas-{}' or 'arch-pubd-{}' there, then rename them \
                 to 'cas' and 'pubd' respectively and re-install krill \
                 version {}. Underlying error was: {}",
                config.storage_uri,
                report.versions().from(),
                report.versions().from(),
                report.versions().from(),
                e
            ))
        })?;
    }

    // Added in 0.15.0: Initialize the property manager if it isn’t yet.
    if !properties_manager.is_initialized() {
        properties_manager.init(KrillVersion::code_version())?;
    }

    // XXX TODO This may need some configuration.
    let tokio = tokio::runtime::Runtime::new().map_err(|err| {
        KrillError::custom(
            format!("Failed to create Tokio runtime: {err}")
        )
    })?;

    let mut krill = StartupManager::new(config, tokio.handle().clone())?;

    // Setup testbed if necessary.
    krill.prepare_testbed()?;

    // Call post-start upgrades to trigger any upgrade related runtime
    // actions, such as re-issuing ROAs because subject name strategy has
    // changed.
    if let Some(report) = upgrade_report {
        post_start_upgrade(report, &krill)?;
    }

    // If the operator wanted to do the upgrade only, now is a good time to
    // report success and stop
    if env::var(KRILL_ENV_UPGRADE_ONLY).is_ok() {
        println!("Krill upgrade successful");
        std::process::exit(0);
    }

    krill.run_scheduler()?;
    let (krill, pool) = krill.promote()?;

    // Create the HTTP server.
    let server = HttpServer::new(krill, &tokio.handle())?;

    // Create self-signed HTTPS cert if configured and not generated earlier.
    if server.config().https_mode().is_generate_https_cert() {
        tls_keys::create_key_cert_if_needed(server.config().tls_keys_dir())
            .map_err(|e| Error::HttpsSetup(format!("{e}")))?;
    }

    let (exit_tx, exit_rx) = watch::channel(false);
    let mut join = JoinSet::new();

    // Start a hyper server for the configured http sockets.
    for socket_addr in server.config().socket_addresses().into_iter() {
        join.spawn_on(
            single_http_listener(
                server.clone(),
                socket_addr,
                signal_running.take(),
                exit_rx.clone(),
            ),
            tokio.handle(),
        );
    }

    // Start a hyper server for the configured unix sockets.
    #[cfg(unix)]
    if server.config().unix_socket_enabled() {
        if let Some(path) = server.config().unix_socket() {
            join.spawn_on(
                single_unix_listener(
                    server.clone(),
                    path.clone(),
                    signal_running.take(),
                    exit_rx.clone(),
                ),
                tokio.handle(),
            );
        }
    }

    tokio.block_on(async {
        if let Some(exit) = signal_exit {
            let _ = exit.await;
        }
        else {
            exit_signalled().await;
        }
        let _ = exit_tx.send(true);
        let _ = join.join_all().await;
    });

    drop(server);
    pool.terminate();

    Ok(())
}


//------------ single_http_listener ------------------------------------------

/// Creates and listens on a TCP socket for the Krill API.
///
/// The socket will listening on the given `addr`. Unless TLS is disabled in
/// the config associated with `server`, then listener will start a TLS
/// handshake on connections.
///
/// Requests will be dispatched to `server`.
///
/// If `signal_running` is given, a signal is sent when the listener is ready
/// to receive connections.
///
/// The listener will shut down after `true` is sent to `signal_exit`. This
/// will also initate closing of all currently open connections. The function
/// will return when both the listener and all connections are closed or after
/// then seconds.
async fn single_http_listener(
    server: Arc<HttpServer>,
    addr: SocketAddr,
    signal_running: Option<oneshot::Sender<()>>,
    mut signal_exit: watch::Receiver<bool>,
) {
    let listener = TcpListener::bind(addr).await.unwrap();

    let tls = if server.config().https_mode().is_disable_https() {
        None
    } else {
        match tls::create_server_config(
            &tls_keys::key_file_path(server.config().tls_keys_dir()),
            &tls_keys::cert_file_path(server.config().tls_keys_dir()),
        ) {
            Ok(config) => Some(TlsAcceptor::from(Arc::new(config))),
            Err(err) => {
                error!("{err}");
                return;
            }
        }
    };

    let conn_builder = conn::auto::Builder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();

    let weak_server = Arc::downgrade(&server);
    drop(server);

    if let Some(tx) = signal_running {
        let _ = tx.send(());
    }

    loop {
        // Break here already if `signal_exit` is true.
        if *signal_exit.borrow_and_update() {
            drop(listener);
            break;
        }

        tokio::select! {
            conn = listener.accept() => {
                let (stream, _addr) = match conn {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!("TCP socket accept error: {}", e);
                        tokio::time::sleep(
                            Duration::from_millis(100)
                        ).await;
                        continue;
                    }
                };

                let stream = TokioIo::new(
                    tls::MaybeTlsTcpStream::new(
                        stream, tls.as_ref()
                    )
                );

                let server = weak_server.clone();
                let conn = conn_builder.serve_connection_with_upgrades(
                    stream,
                    hyper::service::service_fn(move |req| {
                        HttpServer::process_request(server.clone(), req)
                    })
                );
                let conn = graceful.watch(conn.into_owned());

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("TCP connection error: {}", err);
                    }
                });
            },

            res = signal_exit.changed() => {
                // Break if the channel is closed or the new value is `true`.
                if res.is_err() || *signal_exit.borrow() {
                    drop(listener);
                    break;
                }
            }
        }
    }

    tokio::select! {
        _ = graceful.shutdown() => { },
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            warn!(
                "Waited 10 seconds for TCP listener to shutdown, aborting..."
            );
        }
    }
}


//------------ single_unix_listener ------------------------------------------

/// Creates and listens on a Unix socket for the Krill API.
///
/// The socket will listening on the given `addr`. It will dispatch requests
/// to `server`.
///
/// If `signal_running` is given, a signal is sent when the listener is ready
/// to receive connections.
///
/// The listener will shut down after `true` is sent to `signal_exit`. This
/// will also initate closing of all currently open connections. The function
/// will return when both the listener and all connections are closed or after
/// then seconds.
#[cfg(unix)]
async fn single_unix_listener(
    server: Arc<HttpServer>,
    path: std::path::PathBuf,
    signal_running: Option<oneshot::Sender<()>>,
    mut signal_exit: watch::Receiver<bool>,
) {
    use nix::unistd::{Uid, User};
    use tokio::net::UnixListener;

    if path.exists() {
        if let Err(err) = std::fs::remove_file(&path) {
            error!("Failed to remove existing Unix socket file: {err}");
            return;
        };
    }

    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            error!(
                "Could not bind to Unix socket '{}': {}",
                &path.to_string_lossy(), err
            );
            return;
        }
    };

    let conn_builder = conn::auto::Builder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();

    let weak_server = Arc::downgrade(&server);
    drop(server);

    if let Some(tx) = signal_running {
        let _ = tx.send(());
    }

    loop {
        // Break here already if `signal_exit` is true.
        if *signal_exit.borrow_and_update() {
            drop(listener);
            break;
        }

        tokio::select! {
            conn = listener.accept() => {
                let (stream, _addr) = match conn {
                    Ok(stream) => stream,
                    Err(err) => {
                        warn!("Unix socket accept error: {}", err);
                        tokio::time::sleep(
                            Duration::from_millis(100)
                        ).await;
                        continue;
                    }
                };


                let uid = match stream.peer_cred() {
                    Ok(cred) => Uid::from_raw(cred.uid()),
                    Err(err) => {
                        warn!(
                            "Unix socket could not obtain peer credentials: \
                             {err}"
                        );
                        continue;
                    }
                };
                let user = match User::from_uid(uid) {
                    Ok(Some(user)) => user,
                    Ok(None) => {
                        error!(
                            "Unix socket could not obtain user details: \
                             unknown user ID."
                        );
                        continue;
                    }
                    Err(err) => {
                        error!(
                            "Unix socket could not obtain user details: {err}"
                        );
                        continue;
                    },
                };

                let server = weak_server.clone();
                let conn = conn_builder.serve_connection_with_upgrades(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |mut req| {
                        let extensions = req.extensions_mut();
                        extensions.insert(user.clone());
                        HttpServer::process_request(server.clone(), req)
                    })
                );
                let conn = graceful.watch(conn.into_owned());

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        warn!("Unix connection error: {}", err);
                    }
                });
            },

            res = signal_exit.changed() => {
                // Break if the channel is closed or the new value is `true`.
                if res.is_err() || *signal_exit.borrow() {
                    drop(listener);
                    break;
                }
            }
        }
    }

    tokio::select! {
        _ = graceful.shutdown() => { },
        _ = tokio::time::sleep(Duration::from_secs(10)) => {
            warn!(
                "Waited 10 seconds for TCP listener to shutdown, aborting..."
            );
        }
    }
}


//------------ exit_signalled ------------------------------------------------

/// Returns when an exit signal was received.
///
/// This non-Unix implementation returns when the equivalent of a Ctrl+C is
/// received.
#[cfg(not(unix))]
async fn exit_signalled() {
    tokio::signal::ctrl_c().await
}

/// Returns when an exit signal was received.
///
/// Returns when either a SIGINT or SIGTERM was received.
/// 
#[cfg(unix)]
async fn exit_signalled() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(sig) => sig,
        Err(err) => {
            error!("Failed to install SIGTERM handler: {err}.");
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(sig) => sig,
        Err(err) => {
            error!("Failed to install SIGINT handler: {err}.");
            return;
        }
    };

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM. Shutting down.");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT. Shutting down.");
        }
    }
}


//------------ Helper functions ----------------------------------------------

/// Writes the process ID to the configured PID file or dies trying.
fn write_pid_file_or_die(config: &Config) {
    if let Err(e) = file::save(
        process::id().to_string().as_bytes(), config.pid_file()
    ) {
        print_write_error_hint_and_die(format!(
            "Could not write PID file: {e}"
        ));
    }
}

/// Checks that all the configured test directories are present or dies.
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

/// Checks that the given directory can be written to.
///
/// Does so by writing to a file “test” and deleting it thereafter.
fn test_data_dir_or_die(config_item: &str, dir: &Path) {
    let test_file = dir.join("test");

    if let Err(e) = file::save(b"test", &test_file) {
        print_write_error_hint_and_die(format!(
            "Cannot write to dir '{}' for configuration setting '{}', \
             Error: {}",
            dir.to_string_lossy(),
            config_item,
            e
        ));
    }
    else if let Err(e) = file::delete_file(&test_file) {
        print_write_error_hint_and_die(format!(
            "Cannot delete test file '{}' in dir for configuration setting \
             '{}', Error: {}",
            test_file.to_string_lossy(),
            config_item,
            e
        ));
    }
}

/// Writes an error message and a hint how to proceeed.
//
// XXX Doesn’t actually die?
//
fn print_write_error_hint_and_die(error_msg: String) {
    eprintln!("{error_msg}");
    eprintln!();
    eprintln!("Hint: if you use systemd you may need to override the allowed");
    eprintln!("ReadWritePaths, the easiest way may be by doing ");
    eprintln!("'systemctl edit krill' and add a section like:");
    eprintln!();
    eprintln!("[Service]");
    eprintln!("ReadWritePaths=/local/path1 /local/path2 ...");
}

