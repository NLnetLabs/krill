//! Controlling a Routinator.
#![allow(unused)]

use crate::utils::fmt::WriteOrPanic;

use std::fs::File;
use std::net::IpAddr;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::{fs, process};

use indoc::writedoc;

//------------ Routinator ----------------------------------------------------

/// A Routinator installation for validating data.
pub struct Routinator {
    /// Location of the routinator binary.
    routinator: PathBuf,

    /// The directory where Routinator will keep its stuff.
    base_dir: PathBuf,

    /// The path to the TLS certificate used by the RRDP server.
    rrdp_tls_cert_path: PathBuf,
}

impl Routinator {
    /// Creates a new Routinator installation.
    ///
    /// Creates all the necessary paths but doesn’t run anything just yet.
    pub fn new(
        routinator_bin: PathBuf,
        base_dir: PathBuf,
        rrdp_tls_cert_path: PathBuf,
    ) -> Self {
        let mut res = Self {
            routinator: routinator_bin,
            base_dir,
            rrdp_tls_cert_path,
        };
        fs::create_dir(&res.base_dir).unwrap();
        fs::create_dir(&res.extra_tals_dir()).unwrap();
        res.make_conf();
        res
    }
}

/// # Paths and URLs
impl Routinator {
    /// Returns the path to the Routinator config file.
    fn config_path(&self) -> PathBuf {
        self.base_dir.join("routinator.conf")
    }

    /// Returns the Routinator repository directory
    fn repo_dir(&self) -> PathBuf {
        self.base_dir.join("rpki-cache")
    }

    fn extra_tals_dir(&self) -> PathBuf {
        self.base_dir.join("extra-tals")
    }
}

/// # Setup
impl Routinator {
    fn make_conf(&self) {
        let mut conf = File::create(self.config_path()).unwrap();

        // Create string representations of configuration values.
        let repository_dir = self.repo_dir().display().to_string();
        let rrdp_root_cert_path =
            self.rrdp_tls_cert_path.display().to_string();
        let extra_tals_dir = self.extra_tals_dir().display().to_string();

        // Write the Routinator config file using the strings we just created.
        writedoc!(
            conf,
            r#"
                repository-dir = "{repository_dir}"
                log = "stderr"
                log-level = "trace"
                rrdp-root-certs = ["{rrdp_root_cert_path}"]
                allow-dubious-hosts = true
                #disable-rsync = true
                no-rir-tals = true
                extra-tals-dir = "{extra_tals_dir}"
                strict = true
                log-repository-issues = true
            "#
        );
    }

    /// Store the given TAL bytes as a file in the correct location so that
    /// Routinator will use it.
    pub fn install_tal(&self, name: &str, bytes: &[u8]) {
        let mut f = File::create_new(
            self.extra_tals_dir().join(name).with_added_extension("tal"),
        )
        .unwrap();
        std::io::Write::write_all(&mut f, bytes).unwrap();
    }

    /// Update the local repository, validate the ROAs and return the VRPs.
    ///
    /// TODO: Deserialize the JSON into Rust data types.
    pub fn vrps(&self) -> Vec<u8> {
        let output = process::Command::new(&self.routinator)
            .args([
                // Tell Routinator where to find its config file.
                "-c",
                &self.config_path().display().to_string(),
                // Do a one time validation run.
                "vrps",
                // Output in JSON format.
                "--format",
                "json",
                // Output to standard output.
                "--output",
                "-",
                "--complete",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
            .wait_with_output()
            .unwrap();
        output.stdout
    }
}
