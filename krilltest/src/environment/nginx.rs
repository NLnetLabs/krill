//! Controlling an Nginx server. 

use std::{fs, process};
use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use crate::utils::fmt::WriteOrPanic;


//------------ NginxServer ---------------------------------------------------

/// An Nginx server instance to serve files.
pub struct NginxServer {
    /// Location of the nginx binary.
    nginx: String,

    /// The directory where the server keeps all its stuff.
    server_dir: PathBuf,

    /// The listen address for the server.
    listen: (IpAddr, u16),

    /// A map between path prefixes and directories.
    routes: Vec<(String, PathBuf)>,

    /// The Nginx process if it is running.
    process: Option<process::Child>,
}

impl NginxServer {
    /// Creates a new Nginx server and starts it.
    pub fn new(
        nginx_bin: String,
        server_dir: PathBuf,
        listen: (IpAddr, u16),
    ) -> Self {
        let mut res = Self {
            nginx: nginx_bin,
            server_dir,
            listen,
            routes: Default::default(),
            process: None,
        };

        fs::create_dir_all(res.tls_path()).unwrap();
        res.make_tls();

        fs::create_dir_all(res.root_path()).unwrap();
        fs::write(
            res.root_path().join("test.txt"),
            "test"
        ).unwrap();

        res.make_conf();
        res.start();
        
        res
    }
}

impl Drop for NginxServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            if let Err(err) = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::SIGTERM
            ) {
                eprintln!("Failed to kill nginx: {err}");
            }
            if let Err(err) = child.wait() {
                eprintln!("Failed to wait for nginx: {err}");
            }
        }
    }
}


/// # Paths to things
impl NginxServer {
    /// Returns the directory for the TLS configuration.
    fn tls_path(&self) -> PathBuf {
        self.server_dir.join("tls")
    }

    /// Returns the path to the TLS certificate.
    pub fn tls_cert_path(&self) -> PathBuf {
        self.tls_path().join("cert.pem")
    }

    /// Returns the path to the TLS certificate.
    fn tls_key_path(&self) -> PathBuf {
        self.tls_path().join("privkey.pem")
    }

    /// Returns the path to the Nginx config file.
    fn config_path(&self) -> PathBuf {
        self.server_dir.join("nginx.conf")
    }

    /// Returns the server root path.
    fn root_path(&self) -> PathBuf {
        self.server_dir.join("http")
    }

    /// Returns the base URL of the server.
    pub fn url(&self) -> String {
        match self.listen.0 {
            IpAddr::V4(addr) => {
                format!("https://{}:{}/", addr, self.listen.1)
            }
            IpAddr::V6(addr) => {
                format!("https://[{}]:{}/", addr, self.listen.1)
            }
        }
    }

    /// Returns the URL of the test file.
    pub fn test_url(&self) -> String {
        format!("{}test.txt", self.url())
    }
}

/// # Setup
impl NginxServer {
    /// Create the TLS key and certificate.
    fn make_tls(&self) {
        let tls = rcgen::generate_simple_self_signed(
            vec![self.listen.0.to_string()]
        ).unwrap();

        fs::write(
            self.tls_cert_path(),
            &tls.cert.pem(),
        ).unwrap();
        fs::write(
            self.tls_key_path(),
            tls.signing_key.serialize_pem()
        ).unwrap();
    }

    /// Creates the Nginx config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        writeln!(conf, "daemon off;");
        writeln!(conf, "events {{ }}");
        writeln!(conf,
            "pid {}/nginx.pid;", self.server_dir.display()
        );
        writeln!(conf, "http {{");
        writeln!(conf, "  access_log /dev/stdout;");

        writeln!(conf, "  server {{");
        match self.listen.0 {
            IpAddr::V4(addr) => {
                writeln!(conf,
                    "    listen {}:{} ssl default_server;",
                    addr, self.listen.1
                );
            }
            IpAddr::V6(addr) => {
                writeln!(conf,
                    "    listen [{}]:{} ssl default_server;",
                    addr, self.listen.1
                );
            }
        }
        writeln!(conf, "    root {};", self.root_path().display());
        writeln!(conf, "    server_name _;");
        writeln!(conf,
            "    ssl_certificate {};", self.tls_cert_path().display()
        );
        writeln!(conf,
            "    ssl_certificate_key {};", self.tls_key_path().display()
        );

        for (location, alias) in &self.routes {
            writeln!(conf, "    location {location} {{");
            writeln!(conf, "      alias {};", alias.display());
            writeln!(conf, "    }}");
        }

        writeln!(conf, "  }}");
        writeln!(conf, "}}");
    }

    /// Starts or restarts nginx.
    fn start(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.kill().unwrap();
        }
        self.process = Some(
            process::Command::new(
                &self.nginx
            ).args(
                ["-c", &self.config_path().display().to_string()]
            ).spawn().unwrap()
        );
    }
}

