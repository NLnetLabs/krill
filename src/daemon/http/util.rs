//! Utils for the HTTP service.
//!
//! This is a temporary place to park some things until we find a better home
//! for them.

#[cfg(feature = "multi-user")]
pub fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

