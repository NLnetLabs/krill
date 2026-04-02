//! Controlling Krill server instances.
#![allow(unused)]

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use crate::utils::fmt::WriteOrPanic;


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
        let res = Self {
            krill: krill_bin,
            server_dir, listen, rrdp_uri, rsync_uri
        };
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
    /// Creates the Nginx config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        writeln!(conf, "storage_uri = \"{}\"", self.storage_path.display());
    }
}

