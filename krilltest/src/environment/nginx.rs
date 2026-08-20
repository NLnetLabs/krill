//! Controlling an Nginx server.
use crate::utils::fmt::WriteOrPanic;

use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use std::{fs, process};

use indoc::writedoc;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

//------------ NginxServer ---------------------------------------------------

/// An Nginx server instance to serve files.
pub struct NginxServer {
    /// Location of the nginx binary.
    nginx_bin: PathBuf,

    /// The directory where the server keeps all its stuff.
    server_dir: PathBuf,

    /// The listen address for the server.
    listen: IpAddr,

    /// The Nginx process if it is running.
    process: Option<process::Child>,

    /// Downstreams to proxy to.
    ///
    /// Maps root data dir and front end port numbers to backend URLs.
    backends: HashMap<(PathBuf, u16), String>,
}

impl NginxServer {
    /// Creates a new Nginx server and starts it.
    pub fn new(
        nginx_bin: PathBuf,
        server_dir: PathBuf,
        listen: IpAddr,
    ) -> Self {
        let res = Self {
            nginx_bin,
            server_dir,
            listen,
            process: None,
            backends: HashMap::new(),
        };

        fs::create_dir_all(res.tls_path()).unwrap();
        res.make_tls();
        res
    }

    pub fn reconfigure(&mut self) {
        self.make_conf();

        if let Some(process) = &self.process {
            eprintln!("Reconfiguring nginx");
            signal::kill(Pid::from_raw(process.id() as i32), Signal::SIGHUP)
                .unwrap();
        } else {
            eprintln!("Starting nginx");
            self.start()
        }
    }

    pub fn add_backend(
        &mut self,
        root_path: PathBuf,
        front_end_port: u16,
        backend_url: String,
    ) {
        self.backends
            .insert((root_path, front_end_port), backend_url);
        self.reconfigure();
    }

    /// Panics if the backend is not known.
    pub fn remove_backend(
        &mut self,
        root_path: PathBuf,
        front_end_port: u16,
    ) {
        self.backends.remove(&(root_path, front_end_port)).unwrap();
        self.reconfigure();
    }
}

impl Drop for NginxServer {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            if let Err(err) = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::SIGTERM,
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

    /// Returns the path to the NGINX temporary directory.
    fn tmp_path(&self) -> PathBuf {
        self.server_dir.join("tmp")
    }
}

/// # Setup
impl NginxServer {
    /// Create the TLS key and certificate.
    fn make_tls(&self) {
        let tls =
            rcgen::generate_simple_self_signed(vec![self.listen.to_string()])
                .unwrap();

        fs::write(self.tls_cert_path(), &tls.cert.pem()).unwrap();
        fs::write(self.tls_key_path(), tls.signing_key.serialize_pem())
            .unwrap();
    }

    /// Creates the Nginx config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        // Create string representations of configuration values.
        let ssl_certificate = self.tls_cert_path().display().to_string();
        let ssl_certificate_key = self.tls_key_path().display().to_string();
        let tmp = self.tmp_path().display().to_string();

        let mut server_blocks = String::new();
        for ((root, front_end_port), backend_url) in &self.backends {
            let root = root.display().to_string();
            let listen = match self.listen {
                IpAddr::V4(addr) => format!("{addr}:{front_end_port}"),
                IpAddr::V6(addr) => format!("{addr}:{front_end_port}"),
            };
            server_blocks.push_str(&format!(r#"
                    server {{
                        listen {listen} ssl default_server;
                        root {root};
                        server_name _;
                        access_log /dev/stdout;
                        ssl_certificate {ssl_certificate};
                        ssl_certificate_key {ssl_certificate_key};
                        client_body_temp_path {tmp};

                        # From Krill docs:
                        client_max_body_size 128m;

                        location / {{
                            proxy_pass {backend_url};
                            proxy_set_header Host $host;
                            proxy_set_header X-Real-IP $remote_addr;
                            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                            proxy_set_header X-Forwarded-Proto $scheme;
                            proxy_ssl_verify off;
                        }}
                    }}
                "#));
        }

        // Write the NGINX config file using the strings we just created.
        writedoc!(
            conf,
            r#"
                events {{}}
                daemon off;
                pid {tmp}/pid;
                # error_log set here occurs too late to prevent a warning
                # during nginx startup about not being able to write to
                # /var/log/nginx/error.log, to solve that we pass -e when
                # launching nginx. We do however need to specify error_log
                # here if we want to control the level at which nginx logs.
                # error_log /dev/stdout debug;
                http {{
                    proxy_temp_path {tmp};
                    fastcgi_temp_path {tmp};
                    uwsgi_temp_path {tmp};
                    scgi_temp_path {tmp};
                    {server_blocks}
                }}
            "#
        );
    }

    /// Starts or restarts nginx.
    fn start(&mut self) {
        self.process = Some(
            process::Command::new(&self.nginx_bin)
                .args([
                    // Tell nginx where to find its config file.
                    "-c",
                    &self.config_path().display().to_string(),
                    // Pass -e to suppress a warning about not being able to
                    // write to /var/log/.
                    "-e",
                    "/dev/stdout",
                ])
                .spawn()
                .unwrap(),
        );
    }
}
