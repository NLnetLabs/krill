//! The test environment.
use tokio::time::sleep;

use super::krill::KrillServer;
use super::nginx::NginxServer;
use super::routinator::Routinator;

use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::Duration;

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

    /// The path to the Krill binary for spawning Krill instances.
    krill_bin: PathBuf,

    /// The IP address and port range that spawned services should listen on.
    listen: (IpAddr, RangeInclusive<u16>),

    /// Assigned TCP ports.
    used_tcp_ports: BTreeSet<u16>,
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
        krill_bin: PathBuf,
        nginx_bin: PathBuf,
        routinator_bin: PathBuf,
        listen: (IpAddr, RangeInclusive<u16>),
    ) -> Self {
        let nginx =
            NginxServer::new(nginx_bin, base_dir.join("nginx"), listen.0);

        let routinator = Routinator::new(
            routinator_bin,
            base_dir.join("routinator"),
            nginx.tls_cert_path(),
        );

        Self {
            base_dir,
            krill: Default::default(),
            nginx,
            routinator,
            krill_bin,
            listen,
            used_tcp_ports: Default::default(),
        }
    }

    /// Adds a Krill server.
    pub async fn add_krill<T: Display>(&mut self, name: T) {
        let name = format!("{name}");
        let listen_addr = self.listen.0;
        let public_port =
            self.acquire_port(format!("nginx public port for {name}"));
        let private_port =
            self.acquire_port(format!("Krilll private port for {name}"));
        let krill = KrillServer::new(
            self.krill_bin.clone(),
            self.base_dir.join(name.clone()),
            (listen_addr, private_port),
            format!("https://{listen_addr}:{public_port}/"),
            true,
        );
        let krillc = krill.make_client();

        self.krill.insert(name.clone(), krill);
        self.nginx.add_backend(
            format!(
                "{}/data/repo/",
                self.base_dir.join(name.clone()).display()
            ),
            public_port,
            format!("https://{listen_addr}:{private_port}/"),
        );
        self.nginx.reconfigure();

        while !krillc.health().await.is_ok() {
            println!(
                "Waiting for Krill instance '{name}' to finish starting up..."
            );
            sleep(Duration::from_millis(100)).await;
        }
        println!("Krill instance '{name}' is ready");
    }

    /// Returns a reference to the specified Krill server.
    pub fn krill(&self, name: &str) -> &KrillServer {
        self.krill.get(name).unwrap()
    }

    /// Returns a reference to the specified Krill server.
    pub fn krill_mut(&mut self, name: &str) -> &mut KrillServer {
        self.krill.get_mut(name).unwrap()
    }

    /// Returns a reference to the Nginx server.
    pub fn nginx(&self) -> &NginxServer {
        &self.nginx
    }

    /// Returns a reference to the Nginx server.
    pub fn nginx_mut(&mut self) -> &mut NginxServer {
        &mut self.nginx
    }

    /// Returns a reference to the Routinator controller.
    pub fn routinator(&self) -> &Routinator {
        &self.routinator
    }

    fn acquire_port<T: Display>(&mut self, service_description: T) -> u16 {
        let port = match self.used_tcp_ports.first().map(|p| *p) {
            None => *self.listen.1.start(),
            Some(mut last_used_port) => {
                let mut port_iter = self.used_tcp_ports.iter();
                let mut port_to_use = None;
                while let Some(used_port) = port_iter.next().map(|p| *p) {
                    if used_port > (last_used_port + 1) {
                        // Gap in used range, use the port in the gap.
                        port_to_use = Some(last_used_port + 1);
                        break;
                    } else {
                        last_used_port = used_port;
                    }
                }
                port_to_use.unwrap_or_else(|| last_used_port + 1)
            }
        };
        println!("Using TCP port {port} as {service_description}");
        self.used_tcp_ports.insert(port);
        port
    }
}
