//! Controlling Krill server instances.
#![allow(unused)]

use crate::utils::fmt::WriteOrPanic;

use std::fs::{self, File};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process;

use indoc::writedoc;

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

    /// Returns the storage_path for the server.
    pub fn storage_path(&self) -> PathBuf {
        self.server_dir.join("data")
    }
}

/// # Setup
impl KrillServer {
    /// Creates the Krill config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        // Create string representations of configuration values.
        let storage_uri = self.storage_path().display().to_string();
        let addr = self.listen.0;
        let port = self.listen.1;
        let unix_socket = format!("{}/krill.sock", self.server_dir.display());

        // Write the Krill config file using the strings we just created.
        writedoc!(
            conf,
            r#"
                storage_uri = "{storage_uri}"
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
