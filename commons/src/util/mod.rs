//! General utility modules for use all over the code base
use bytes::Bytes;
use rpki::crypto::DigestAlgorithm;

pub mod ext_serde;
pub mod file;
pub mod httpclient;
pub mod softsigner;
pub mod test;
pub mod xml;

pub fn sha256(object: &[u8]) -> Bytes {
    Bytes::from(DigestAlgorithm::default().digest(object).as_ref())
}
