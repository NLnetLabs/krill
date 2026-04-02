//! The test environment.
#![allow(unused)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use super::krill::KrillServer;
use super::nginx::NginxServer;
use super::routinator::Routinator;


//------------ Environment ---------------------------------------------------

/// The complete test environment.
pub struct Environment {
    /// The base directory.
    base_dir: PathBuf,

    /// The Krill servers.
    ///
    /// There may be more than one. Each has a name which will be used when
    /// setting up the paths for RRDP.
    krill: HashMap<String, KrillServer>,

    /// An Nginx server for serving RRDP.
    nginx: NginxServer,

    /// A Routinator installation for validating results.
    routinator: Routinator,
}

impl Environment {
    /// Creates a new environment.
    ///
    /// The environment will keep all its data under `base_dir`. It will
    /// contain both an Nginx and a Routinator setup ready to use. It will,
    /// however, not yet contain any Krill servers. You need to add those
    /// via the [`add_krill`][Self::add_krill] method.
    ///
    /// Note that Nginx will already be started, despite not actually having
    /// anything to serve. But this way you can already check that everything
    /// works.
    pub fn new(
        base_dir: PathBuf,
        nginx_bin: String,
        nginx_listen: (IpAddr, u16),
        routinator_bin: PathBuf,
    ) -> Self {
        let nginx = NginxServer::new(
            nginx_bin, base_dir.join("nginx"), nginx_listen,
        );
        let routinator = Routinator::new(
            routinator_bin, base_dir.join("routinator"), nginx.tls_cert_path()
        );
        Self {
            base_dir,
            krill: Default::default(),
            nginx,
            routinator
        }
    }

    /// Adds a Krill server.

    /// Returns a reference to the Nginx server.
    pub fn nginx(&self) -> &NginxServer {
        &self.nginx
    }
}

