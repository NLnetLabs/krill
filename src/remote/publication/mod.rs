use bytes::Bytes;
use rpki::signing::digest;

pub mod pubmsg;
pub mod query;
pub mod reply;

pub fn hash(object: &Bytes) -> Bytes {
    Bytes::from(digest::digest(
        &digest::SHA256,
        object.as_ref()
    ).as_ref())
}
