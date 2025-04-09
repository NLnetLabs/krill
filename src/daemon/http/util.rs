//! Utils for the HTTP service.
//!
//! This is a temporary place to park some things until we find a better home
//! for them.

use crate::commons::error::Error;


#[cfg(feature = "multi-user")]
pub fn url_encode<S: AsRef<str>>(s: S) -> Result<String, Error> {
    urlparse::quote(s, b"").map_err(|err| Error::custom(err.to_string()))
}

