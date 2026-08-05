//! Controlling Krill server instances.
#![allow(unused)]

use crate::utils::fmt::WriteOrPanic;

use std::fs::{self, File};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;

use indoc::writedoc;
use nix::libc::FAN_RESPONSE_INFO_AUDIT_RULE;

//------------ KrillServer ---------------------------------------------------

/// A single Krill server instance.
pub struct KrillServer {
    /// Location of the Krill binary.
    krill: String,

    /// The directory where the server keeps all its stuff.
    server_dir: PathBuf,

    /// The listen address for the server.
    listen: (IpAddr, u16),

    /// The URI for the RRDP server.
    rrdp_uri: String,

    /// The URI for the rsync server.
    rsync_uri: String,

    /// The Krill process if it is running.
    process: Option<process::Child>,
}

impl KrillServer {
    /// Creates and configures a new Krill server.
    pub fn new(
        krill_bin: String,
        server_dir: PathBuf,
        listen: (IpAddr, u16),
        rrdp_uri: String,
        rsync_uri: String,
        enable_ta: bool,
    ) -> Self {
        let mut res = Self {
            krill: krill_bin,
            server_dir,
            listen,
            rrdp_uri,
            rsync_uri,
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
}

/// # Setup
impl KrillServer {
    /// Creates the Krill config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        // Create string representations of configuration values.
        let storage_uri =
            format!("memory://{}", hex::encode(rand::random::<[u8; 8]>()));
        // tls_keys_dir, repo_dir and pid_file must be set because we are
        // using an in-memory storage URI. defaults/krill.conf notes that
        // repo_dir will no longer be required "when issues #1092 and #1093
        // are implemented".
        let tls_keys_dir = self.tls_keys_dir().display().to_string();
        let repo_dir = self.repo_dir().display().to_string();
        let pid_file = self.pid_file().display().to_string();
        let addr = self.listen.0;
        let port = self.listen.1;
        let unix_socket = format!("{}/krill.sock", self.server_dir.display());

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
            "#
        );
    }

    /// Starts or restarts Krill.
    fn start(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.kill().unwrap();
        }
        self.process = Some(
            process::Command::new(&self.krill)
                .args([
                    // Tell Krill where to find its config file.
                    "-c",
                    &self.config_path().display().to_string(),
                ])
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
