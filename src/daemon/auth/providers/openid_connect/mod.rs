//! An authentication provider using OpenID Connect.

pub use self::config::ConfigAuthOpenIDConnect;
pub use self::provider::AuthProvider;

#[macro_use]
mod util;

mod claims;
mod config;
mod httpclient;
mod provider;

