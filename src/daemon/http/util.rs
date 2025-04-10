//! Utils for the HTTP service.
//!
//! This is a temporary place to park some things until we find a better home
//! for them.

#[cfg(feature = "multi-user")]
pub fn url_encode<S: AsRef<str>>(
    s: S
) -> Result<String, crate::commons::error::Error> {
    urlparse::quote(s, b"").map_err(|err| {
        crate::commons::error::Error::custom(err.to_string())
    })
}

