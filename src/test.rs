//! Helper functions for testing Krill.
#![cfg(test)]

use std::{
    path::PathBuf,
    str::FromStr,
};

use bytes::Bytes;
use rpki::{
    uri,
};
use url::Url;

use crate::{
    commons::{
        api::{
            ConfiguredRoa, RoaConfiguration, RoaPayload,
        },
        bgp::{Announcement},
    },
};

use rpki::ca::idcert::IdCert;


/// This method returns an in-memory Key-Value store and then runs the test
/// provided in the closure using it
pub fn test_in_memory<F>(op: F)
where
    F: FnOnce(&Url),
{
    let storage_uri = mem_storage();

    op(&storage_uri);
}

/// This method sets up a test directory with a random name (a number)
/// under 'work', relative to where cargo is running. It then runs the
/// test provided in the closure, and finally it cleans up the test
/// directory.
///
/// Note that if your test fails the directory is not cleaned up.
pub fn test_under_tmp<F>(op: F)
where
    F: FnOnce(PathBuf),
{
    let dir = tempfile::tempdir().unwrap();
    op(dir.path().into());
}

fn random_hex_string() -> String {
    let mut bytes = [0; 8];
    openssl::rand::rand_bytes(&mut bytes).unwrap();
    hex::encode(bytes)
}

pub fn mem_storage() -> Url {
    let mut bytes = [0; 8];
    openssl::rand::rand_bytes(&mut bytes).unwrap();

    Url::parse(&format!("memory://{}", random_hex_string())).unwrap()
}

pub fn rsync(s: &str) -> uri::Rsync {
    uri::Rsync::from_str(s).unwrap()
}

pub fn https(s: &str) -> uri::Https {
    uri::Https::from_str(s).unwrap()
}

// Support testing announcements and ROAs etc

pub fn announcement(s: &str) -> Announcement {
    let def = roa_payload(s);
    Announcement::from(def)
}

pub fn configured_roa(s: &str) -> ConfiguredRoa {
    ConfiguredRoa::new(roa_configuration(s), vec![])
}

pub fn roa_configuration(s: &str) -> RoaConfiguration {
    RoaConfiguration::from_str(s).unwrap()
}

pub fn roa_payload(s: &str) -> RoaPayload {
    RoaPayload::from_str(s).unwrap()
}


#[cfg(test)]
pub fn test_id_certificate() -> IdCert {
    let data = include_bytes!("../test-resources/oob/id_publisher_ta.cer");
    IdCert::decode(Bytes::from_static(data)).unwrap()
}


