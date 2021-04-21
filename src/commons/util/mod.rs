//! General utility modules for use all over the code base
use bytes::Bytes;
use rpki::crypto::DigestAlgorithm;
use rpki::uri::{Https, Rsync};
use std::net::IpAddr;
use std::str::FromStr;

pub mod ext_serde;
pub mod file;
pub mod httpclient;
pub mod softsigner;
pub mod xml;

pub fn sha256(object: &[u8]) -> Bytes {
    let digest = DigestAlgorithm::default().digest(object);
    Bytes::copy_from_slice(digest.as_ref())
}

// TODO: check that an IP address is_global() when that stabilizes: https://github.com/rust-lang/rust/issues/27709
/// Assumes that non-ip hostnames are global (they may of course resolve to something that isn't but hey we tried to help)
fn seems_global_uri(auth: &str) -> bool {
    if auth.to_lowercase() == "localhost" || auth.starts_with('[') || IpAddr::from_str(auth).is_ok() {
        false
    } else if let Some(i) = auth.rfind(':') {
        let auth = &auth[0..i];
        IpAddr::from_str(auth).is_err()
    } else {
        // appears to be a non-ip hostname, assume it's global
        true
    }
}

pub trait AllowedUri {
    fn authority(&self) -> &str;

    fn seems_global_uri(&self) -> bool {
        seems_global_uri(self.authority())
    }
}

impl AllowedUri for Rsync {
    fn authority(&self) -> &str {
        self.authority()
    }
}

impl AllowedUri for Https {
    fn authority(&self) -> &str {
        self.authority()
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use crate::commons::util::seems_global_uri;

    #[test]
    fn check_uri_seems_global() {
        // Does not seem global
        assert!(!seems_global_uri("localhost"));
        assert!(!seems_global_uri("0.0.0.0"));
        assert!(!seems_global_uri("127.0.0.1"));
        assert!(!seems_global_uri("127.0.0.1:873"));
        assert!(!seems_global_uri("1.2.3.4"));
        assert!(!seems_global_uri("::"));
        assert!(!seems_global_uri("::1"));
        assert!(!seems_global_uri("[::1]:873"));
        assert!(!seems_global_uri("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));

        // Looks ok
        assert!(seems_global_uri("localghost"));
        assert!(seems_global_uri("rpki.bla"));
    }
}
