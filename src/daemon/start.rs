use std::{env, process};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use log::error;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::select;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use crate::commons::file;
use crate::commons::error::Error;
use crate::commons::storage::StorageSystem;
use crate::commons::version::KrillVersion;
use crate::config::Config;
use crate::constants::KRILL_ENV_UPGRADE_ONLY;
use crate::server::properties::PropertiesManager;
use crate::server::manager::KrillManager;
use crate::upgrades::{
    finalise_data_migration, post_start_upgrade,
    prepare_upgrade_data_migrations, UpgradeError, UpgradeMode,
};
use super::http::{tls, tls_keys};
use super::http::server::HttpServer;


pub async fn start_krill_daemon(
    config: Arc<Config>,
    mut signal_running: Option<oneshot::Sender<()>>,
) -> Result<(), Error> {
    write_pid_file_or_die(&config);
    test_data_dirs_or_die(&config);

    let storage = StorageSystem::new(config.storage_uri.clone());

    // Set up the runtime properties manager, so that we can check
    // the version used for the current data in storage
    let properties_manager = PropertiesManager::create(
        &storage, config.use_history_cache,
    )?;

    // Call upgrade, this will only do actual work if needed.
    let upgrade_report = prepare_upgrade_data_migrations(
        UpgradeMode::PrepareToFinalise, &storage, &config, &properties_manager
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
            report.versions(), &storage, &properties_manager
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

    // Create the Krill manager, this will create the necessary data
    // sub-directories if needed
    let krill = Arc::new(KrillManager::build(storage, config.clone()).await?);

    // Call post-start upgrades to trigger any upgrade related runtime
    // actions, such as re-issuing ROAs because subject name strategy has
    // changed.
    if let Some(report) = upgrade_report {
        post_start_upgrade(report, &krill).await?;
    }

    // If the operator wanted to do the upgrade only, now is a good time to
    // report success and stop
    if env::var(KRILL_ENV_UPGRADE_ONLY).is_ok() {
        println!("Krill upgrade successful");
        std::process::exit(0);
    }

    // Build the scheduler which will be responsible for executing
    // planned/triggered tasks
    let scheduler_future = krill.run_scheduler();

    // Create the HTTP server.
    let server = HttpServer::new(krill.clone(), config.clone())?;

    // Create self-signed HTTPS cert if configured and not generated earlier.
    if config.https_mode().is_generate_https_cert() {
        tls_keys::create_key_cert_if_needed(config.tls_keys_dir())
            .map_err(|e| Error::HttpsSetup(format!("{e}")))?;
    }

    // Start a hyper server for the configured socket.
    let server_futures = futures_util::future::select_all(
        config.socket_addresses().into_iter().map(|socket_addr| {
            tokio::spawn(single_http_listener(
                server.clone(),
                socket_addr,
                config.clone(),
                signal_running.take(),
            ))
        }),
    );

    select!(
        _ = server_futures => error!("http server stopped unexpectedly"),
        _ = scheduler_future => error!("scheduler stopped unexpectedly"),
    );

    Err(Error::custom("stopping krill process"))
}

/// Runs an HTTP listener on a single socket.
async fn single_http_listener(
    server: Arc<HttpServer>,
    addr: SocketAddr,
    config: Arc<Config>,
    signal_running: Option<oneshot::Sender<()>>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!("Could not bind to {addr}: {err}");
            return;
        }
    };

    let tls = if config.https_mode().is_disable_https() {
        None
    } else {
        match tls::create_server_config(
            &tls_keys::key_file_path(config.tls_keys_dir()),
            &tls_keys::cert_file_path(config.tls_keys_dir()),
        ) {
            Ok(config) => Some(TlsAcceptor::from(Arc::new(config))),
            Err(err) => {
                error!("{err}");
                return;
            }
        }
    };

    if let Some(tx) = signal_running {
        let _ = tx.send(());
    }

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => {
                tls::MaybeTlsTcpStream::new(stream, tls.as_ref())
            }
            Err(err) => {
                error!("Fatal error in HTTP server {addr}: {err}");
                return;
            }
        };
        let server = server.clone();
        tokio::task::spawn(async move {
            let _ = hyper_util::server::conn::auto::Builder::new(
                TokioExecutor::new(),
            )
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |req| {
                    let server = server.clone();
                    async move { server.process_request(req).await }
                }),
            )
            .await;
        });
    }
}

fn write_pid_file_or_die(config: &Config) {
    if let Err(e) = file::save(
        process::id().to_string().as_bytes(), config.pid_file()
    ) {
        print_write_error_hint_and_die(format!(
            "Could not write PID file: {e}"
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

