//! Controlling Krill server instances.
#![allow(unused)]

use crate::utils::fmt::WriteOrPanic;

use std::fs::{self, File};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;

use indoc::writedoc;
use krill::cli::client::{KrillClient, ServerUri};
use nix::libc::FAN_RESPONSE_INFO_AUDIT_RULE;
use rpki::uri::{Https, Rsync};

//------------ KrillServer ---------------------------------------------------

/// A single Krill server instance.
pub struct KrillServer {
    /// Location of the Krill binary.
    krill_bin: PathBuf,

    /// The directory where the server keeps all its stuff.
    server_dir: PathBuf,

    /// The listen address for the server.
    listen: (IpAddr, u16),

    /// The listen address for the nginx proxy in front of Krill.
    ///
    /// When Krill advertizes itself to the outside world, for example in a
    /// TAL file, it needs to mention this address, not its own address.
    service_uri: String,

    /// Whether or not this Krill instance should act as a testbed.
    ///
    /// A testbed is a combined RPKI trust anchor and publication server.
    is_testbed: bool,

    /// The Krill process if it is running.
    process: Option<process::Child>,
}

impl KrillServer {
    /// Creates and configures a new Krill server.
    pub fn new(
        krill_bin: PathBuf,
        server_dir: PathBuf,
        listen: (IpAddr, u16),
        service_uri: String,
        is_testbed: bool,
    ) -> Self {
        let mut res = Self {
            krill_bin,
            server_dir,
            listen,
            service_uri,
            is_testbed,
            process: None,
        };
        fs::create_dir_all(&res.server_dir).unwrap();
        res.make_conf();
        res.start();
        res
    }
}

/// # Paths and URLs
impl KrillServer {
    /// Returns the path to the Krill config file.
    fn config_path(&self) -> PathBuf {
        self.server_dir.join("krill.conf")
    }

    // Returns the Krill TLS keys directory.
    fn tls_keys_dir(&self) -> PathBuf {
        self.server_dir.join("data/tls")
    }

    // Returns the Krill repo directory.
    fn repo_dir(&self) -> PathBuf {
        self.server_dir.join("data/repo")
    }

    // Returns the PID file path.
    fn pid_file(&self) -> PathBuf {
        self.server_dir.join("krill.pid")
    }

    // Returns the UNIX socket path.
    fn unix_socket(&self) -> PathBuf {
        self.server_dir.join("krill.sock")
    }

    /// Returns the base URL at which Krill can be contacted by clients.
    ///
    /// If Krill is fronted by a proxy like nginx this will point to the
    /// proxy rather than to Krill itself.
    pub fn service_uri(&self) -> &str {
        &self.service_uri
    }

    /// Returns the public URL at which the Trust Anchor Locator can be found.
    pub fn tal_url(&self) -> String {
        format!("{}ta/ta.tal", self.service_uri())
    }

    pub fn make_client(&self) -> KrillClient {
        KrillClient::new(
            ServerUri::try_from(format!(
                "unix://{}",
                self.unix_socket().display()
            ))
            .unwrap(),
            None,
        )
        .unwrap()
    }
}

/// # Setup
impl KrillServer {
    /// Creates the Krill config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        // Create string representations of configuration values.
        let service_uri = &self.service_uri;
        let storage_uri =
            format!("memory://{}", hex::encode(rand::random::<[u8; 8]>()));
        // tls_keys_dir, repo_dir and pid_file must be set because we are
        // using an in-memory storage URI. defaults/krill.conf notes that
        // repo_dir will no longer be required "when issues #1092 and #1093
        // are implemented".
        let tls_keys_dir = self.tls_keys_dir().display().to_string();
        let repo_dir = self.repo_dir().display().to_string();
        let pid_file = self.pid_file().display().to_string();
        let unix_socket = self.unix_socket().display().to_string();
        let addr = self.listen.0;
        let port = self.listen.1;

        let curr_user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap()
            .name;
        println!(
            "Authorizing current user '{curr_user}' to use the Krill UNIX socket API as admin"
        );

        // Write the Krill config file using the strings we just created.
        writedoc!(
            conf,
            r#"
                storage_uri = "{storage_uri}"
                tls_keys_dir = "{tls_keys_dir}"
                repo_dir = "{repo_dir}"
                pid_file = "{pid_file}"
                admin_token = "xxx"
                log_type = "stderr"
                log_level = "info"
                ip = "{addr}"
                port = {port}
                bgp_riswhois_enabled = false
                post_protocol_msg_timeout_seconds = 10
                unix_socket = "{unix_socket}"
                service_uri = "{service_uri}"

                [unix_users]
                {curr_user} = "admin"
            "#
        );

        if self.is_testbed {
            // A note about rsync: we have to configure Krill with an rsync
            // URI, but Krill itself is not capable of acting as an rsync
            // server. In the rsync URIs below no port number is specified,
            // thus multiple Krill instances created with is_testbed = true
            // would refer to the same rsync server. However at the time of
            // writing there is no rsync server in our test setup and RPs are
            // expected to use RRDP rather than rsync, i.e. these URIs have to
            // be specified but will not be used.
            let rsync_jail = format!("rsync://{}/repo/", self.listen.0);
            let rrdp_base_uri = format!("{}rrdp/", self.service_uri());
            let ta_aia = format!("rsync://{}/ta/ta.cer", self.listen.0);
            let ta_uri = format!("{}ta/ta.cer", self.service_uri());

            writedoc!(
                conf,
                r#"
                    [testbed]
                    rrdp_base_uri = "{rrdp_base_uri}"
                    rsync_jail = "{rsync_jail}"
                    ta_aia = "{ta_aia}"
                    ta_uri = "{ta_uri}"
                "#
            );
        }
    }

    /// Starts or restarts Krill.
    fn start(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.kill().unwrap();
        }
        self.process = Some(
            process::Command::new(&self.krill_bin)
                .args([
                    // Tell Krill where to find its config file.
                    "-c",
                    &self.config_path().display().to_string(),
                ])
                // Enable test mode to avoid error "Invalid CSR received: MUST use hostnames in URIs for certificate requests"
                .env("KRILL_TEST", "1")
                .spawn()
                .unwrap(),
        );
    }
}

impl Drop for KrillServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            if let Err(err) = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::SIGTERM,
            ) {
                eprintln!("Failed to kill Krill: {err}");
            }
            if let Err(err) = child.wait() {
                eprintln!("Failed to wait for Krill: {err}");
            }
        }
    }
}
