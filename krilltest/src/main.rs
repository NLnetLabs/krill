//! End-to-end tests for Krill.
//!
//! This binary drives complext scenarios to test Krill. In general, these
//! scenarios involve setting up one or more Krill instances, issue commands
//! to them, and then verifying the results by checking the data set output
//! by a Routinator validation run.

use std::net::IpAddr;
use std::path::PathBuf;
use clap::Parser;
use clap::crate_version;
use tempfile::TempDir;
use krilltest::environment::Environment;


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

    let _environment = Environment::new(
        base_path,
        args.nginx, (args.listen_addr, args.rrdp_port),
        args.routinator
    );

    eprintln!("Hit enter to quit.");

    let mut buffer = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer).unwrap();
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
    krill: PathBuf,

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

