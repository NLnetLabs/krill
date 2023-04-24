pub mod authorizer;
pub mod providers;

pub mod common;

#[cfg(feature = "multi-user")]
pub mod policy;
#[cfg(not(feature = "multi-user"))]
pub mod policy {
    use std::sync::Arc;

    use crate::{commons::KrillResult, daemon::config::Config};

    #[derive(Clone)]
    pub struct AuthPolicy {}
    impl AuthPolicy {
        pub fn new(_: Arc<Config>) -> KrillResult<Self> {
            Ok(AuthPolicy {})
        }
    }
}

pub use authorizer::{Auth, AuthProvider, Authorizer, Handle, LoggedInUser};
