//! Controlling an Nginx server.
use crate::utils::fmt::WriteOrPanic;

use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use std::{fs, process};

use indoc::writedoc;

//------------ NginxServer ---------------------------------------------------

/// An Nginx server instance to serve files.
pub struct NginxServer {
    /// Location of the nginx binary.
    nginx: String,

    /// The directory where the server keeps all its stuff.
    server_dir: PathBuf,

    /// The listen address for the server.
    listen: (IpAddr, u16),

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
            process: None,
        };

        fs::create_dir_all(res.tls_path()).unwrap();
        res.make_tls();
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

    /// Returns the path to the NGINX temporary directory.
    fn tmp_path(&self) -> PathBuf {
        self.server_dir.join("tmp")
    }

    /// Returns the server root path.
    fn root_path(&self) -> PathBuf {
        // TODO: Don't hard-code the location of a specific Krill instance
        // RRDP data directory here, as we may want to serve data published by
        // multiple Krill instances.
        self.server_dir.join("../krill/data/repo/")
    }

    /// Returns the base URL of the server.
    pub fn base_url(&self) -> String {
        match self.listen.0 {
            IpAddr::V4(addr) => {
                format!("https://{}:{}/", addr, self.listen.1)
            }
            IpAddr::V6(addr) => {
                format!("https://[{}]:{}/", addr, self.listen.1)
            }
        }
    }
}

/// # Setup
impl NginxServer {
    /// Create the TLS key and certificate.
    fn make_tls(&self) {
        let tls = rcgen::generate_simple_self_signed(vec![
            self.listen.0.to_string(),
        ])
        .unwrap();

        fs::write(self.tls_cert_path(), &tls.cert.pem()).unwrap();
        fs::write(self.tls_key_path(), tls.signing_key.serialize_pem())
            .unwrap();
    }

    /// Creates the Nginx config.
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        // Create string representations of configuration values.
        let listen = match self.listen {
            (IpAddr::V4(addr), port) => format!("{addr}:{port}"),
            (IpAddr::V6(addr), port) => format!("{addr}:{port}"),
        };
        let root = self.root_path().display().to_string();
        let ssl_certificate = self.tls_cert_path().display().to_string();
        let ssl_certificate_key = self.tls_key_path().display().to_string();
        let tmp = self.tmp_path().display().to_string();

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

                        # TODO: Make the location blocks below dynamically
                        # generated rather than hard-coded, so that we can
                        # support multiple Krill instances behind the nginx.

                        # Proxy RFC 8181 publication server requests to Krill.
                        location /rfc8181 {{
                            proxy_pass https://127.0.0.1:3001/rfc8181;
                            proxy_set_header Host $host;
                            proxy_set_header X-Real-IP $remote_addr;
                            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                            proxy_set_header X-Forwarded-Proto $scheme;

                            # krill does not use a valid certificate/tls is handled by nginx
                            proxy_ssl_verify off;
                        }}

                        # Proxy Krill API requests to Krill.
                        location /api {{
                            proxy_pass https://127.0.0.1:3001/api;
                            proxy_set_header Host $host;
                            proxy_set_header X-Real-IP $remote_addr;
                            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                            proxy_set_header X-Forwarded-Proto $scheme;

                            # allow IPv4 and IPv6 documentation ranges
                            # allow 192.0.2.0/24;
                            # allow 2001:0db8::/32;
                            # deny  all;

                            # krill does not use a valid certificate/tls is handled by nginx
                            proxy_ssl_verify off;
                        }}

                        # Serve RRDP files generated by Krill
                        # This is handled by the 'root' directive above.

                        location /ta {{
                            proxy_pass https://127.0.0.1:3001/ta;
                            proxy_set_header Host $host;
                            proxy_set_header X-Real-IP $remote_addr;
                            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                            proxy_set_header X-Forwarded-Proto $scheme;

                            # krill does not use a valid certificate/tls is handled by nginx
                            proxy_ssl_verify off;
                         }}
                    }}
                }}
            "#
        );
    }

    /// Starts or restarts nginx.
    fn start(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.kill().unwrap();
        }
        self.process = Some(
            process::Command::new(&self.nginx)
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

