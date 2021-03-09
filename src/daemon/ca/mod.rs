//! Certificate Authority related code.
//!
use crate::commons::api::Handle;
use crate::commons::error::Error;

mod certauth;
pub use self::certauth::CertAuth;
pub use self::certauth::Rfc8183Id;

mod child;
pub use self::child::*;

mod rc;
pub use self::rc::ResourceClass;

mod keys;
pub use self::keys::*;

mod publishing;
pub use self::publishing::*;

mod routes;
pub use self::routes::*;

mod commands;
pub use self::commands::*;

mod events;
pub use self::events::*;

mod manager;
pub use self::manager::CaManager;

mod rta;
pub use self::rta::*;

mod status;
pub use self::status::*;

pub const TA_NAME: &str = "ta"; // reserved for TA
pub const TESTBED_CA_NAME: &str = "testbed"; // reserved for testbed mode

pub fn ta_handle() -> Handle {
    use std::str::FromStr;
    Handle::from_str(TA_NAME).unwrap()
}

pub fn testbed_ca_handle() -> Handle {
    use std::str::FromStr;
    Handle::from_str(TESTBED_CA_NAME).unwrap()
}
