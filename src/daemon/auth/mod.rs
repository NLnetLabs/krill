pub mod authorizer;
pub mod providers;

#[cfg(feature = "multi-user")]
pub mod common;

#[cfg(feature = "multi-user")]
pub mod policy;
#[cfg(not(feature = "multi-user"))]
pub mod policy {
    use std::sync::Arc;

    use crate::{daemon::config::Config, commons::KrillResult};

    #[derive(Clone)]
    pub struct AuthPolicy {}
    impl AuthPolicy {
        pub fn new(_: Arc<Config>) -> KrillResult<Self> {
            Ok(AuthPolicy {})
        }
    }
}

pub use authorizer::{Auth, Authorizer, AuthProvider, LoggedInUser};