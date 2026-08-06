//! End-to-end tests for Krill.
//!
//! This binary drives complext scenarios to test Krill. In general, these
//! scenarios involve setting up one or more Krill instances, issue commands
//! to them, and then verifying the results by checking the data set output
//! by a Routinator validation run.
use krilltest::environment::Environment;

use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use clap::crate_version;
use tempfile::TempDir;

//------------ main ----------------------------------------------------------

fn main() {
    let args = Args::parse();
    let (base_path, _tempdir) = match args.working_dir {
        Some(working_dir) => (working_dir, None),
        None => {
            let tempdir = TempDir::new().unwrap();
            (tempdir.path().to_path_buf(), Some(tempdir))
        }
    };

    let mut environment = Environment::new(
        base_path,
        args.nginx,
        (args.listen_addr, args.rrdp_port),
        args.routinator,
    );

    // Add a Krill test bed to the test environment and get the location of
    // Trust Anchor Locator so that we can install it for Routinator to use.
    let tal_url = {
        // TODO: Allocate a port that isn't already in use, don't just do +1.
        let some_free_port1 = args.rrdp_port + 1;
        let krill_listen = (args.listen_addr, some_free_port1);
        let krill = environment.add_krill("first", args.krill, krill_listen);
        krill.tal_url()
    };

    // Load the TLS certificate that can be used to verify that a TLS
    // connection to Krill can be trusted. The alternative would be to use the
    // reqwest `danger_accept_invalid_certs(true)` functionality but this is
    // more correct, but also more verbose.
    let tls_cert = load_tls_cert(&environment.nginx().tls_cert_path());

    // Fetch the Krill TAL and install it in the Routinator extra tals
    // directory.
    let tal_bytes = fetch_url(tal_url, tls_cert, 5);

    // Configure Routinator to use the Krill TAL.
    environment.routinator().install_tal("Krill", &tal_bytes);

    // Do a Routinator validation run and fetch the available VRPs.
    std::io::stdout()
        .write_all(&environment.routinator().vrps())
        .unwrap();

    // TODO: Actually add ROAs to Krill and verify that the fetched VRPs are
    // correct.
}

fn load_tls_cert(tls_cert_path: &Path) -> reqwest::Certificate {
    let mut f = std::fs::File::open(tls_cert_path).unwrap();
    let mut tls_ca_cert_pem_bytes = vec![];
    f.read_to_end(&mut tls_ca_cert_pem_bytes).unwrap();
    drop(f);
    let tls_ca_cert =
        reqwest::Certificate::from_pem(&tls_ca_cert_pem_bytes).unwrap();
    tls_ca_cert
}

fn fetch_url(
    url: String,
    tls_cert: reqwest::Certificate,
    max_tries: u8,
) -> bytes::Bytes {
    let trusting_client = reqwest::blocking::Client::builder()
        .tls_certs_only([tls_cert])
        .build()
        .unwrap();
    let mut tries_left = max_tries;
    while tries_left > 0 {
        match trusting_client.get(&url).send() {
            Ok(bytes) => {
                return bytes.bytes().unwrap();
            }
            Err(err) => {
                eprintln!(
                    "{url} not yet available, will retry in 1 second: {err}"
                );
                sleep(Duration::from_secs(1));
            }
        }
        tries_left -= 1;
    }
    unreachable!();
}

//------------ Args ----------------------------------------------------------

#[derive(clap::Parser)]
#[command(
    version = crate_version!(), name = "krilltest",
    about, long_about = None,
)]
struct Args {
    /// The path of the krill binary.
    #[arg(long, default_value = "target/release/krill")]
    krill: String,

    /// The path of the routinator binary.
    #[arg(long, default_value = "routinator")]
    routinator: PathBuf,

    /// The path of the nginx binary.
    #[arg(long, default_value = "/usr/sbin/nginx")]
    nginx: String,

    /// The working directory for all test data.
    ///
    /// A temporary directory in '/tmp' is used if not given.
    #[arg(long)]
    working_dir: Option<PathBuf>,

    /// The IP address all the servers should listen on.
    #[arg(long, default_value = "127.0.0.1")]
    listen_addr: IpAddr,

    /// The port the RRDP server should listen on.
    #[arg(long, default_value = "3000")]
    rrdp_port: u16,
}
