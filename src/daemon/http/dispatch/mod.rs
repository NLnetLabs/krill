//! Dispatching of HTTP requests.

pub use self::error::DispatchError;
pub use self::root::dispatch_request;

/// The authentication callback path used by the OpenID provider.
///
/// This must not start with a slash.
///
/// It must also resolve to be dispatched to `self::auth::callback`.
pub const AUTH_CALLBACK_ENDPOINT: &str = "auth/callback";

mod api;
mod auth;
mod cas;
mod bulk;
mod error;
mod metrics;
mod pubd;
mod root;
mod stats;
mod ta;
mod testbed;

