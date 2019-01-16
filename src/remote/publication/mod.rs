pub mod pubmsg;
pub mod query;
pub mod reply;

use bytes::Bytes;
use rpki::crypto::digest::DigestAlgorithm;

pub fn hash(object: &Bytes) -> Bytes {
    Bytes::from(DigestAlgorithm.digest(object.as_ref()).as_ref())
}
