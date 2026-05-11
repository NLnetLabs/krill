//! Controlling a Routinator.
#![allow(unused)]

use std::fs;
use std::path::PathBuf;


//------------ Routinator ----------------------------------------------------

/// A Routinator installation for validating data.
pub struct Routinator {
    /// Location of the routinator binary.
    routinator: PathBuf,

    /// The directory where Routinator will keep its stuff.
    base_dir: PathBuf,

    /// Path to the TLS certificate used by Nginx server.
    tls_cert_path: PathBuf,
}

impl Routinator {
    /// Creates a new Routinator installation.
    ///
    /// Creates all the necessary paths but doesn’t run anything just yet.
    pub fn new(
        routinator_bin: PathBuf,
        base_dir: PathBuf,
        tls_cert_path: PathBuf,
    ) -> Self {
        let res = Self {
            routinator: routinator_bin,
            base_dir,
            tls_cert_path,
        };
        fs::create_dir(&res.base_dir).unwrap();
        res
    }
}


