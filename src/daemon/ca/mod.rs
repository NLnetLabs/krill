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

mod server;
pub use self::server::CaServer;

mod signing;
pub use self::signing::*;

pub const TA_NAME: &str = "ta"; // reserved for TA

pub fn ta_handle() -> Handle {
    unsafe { Handle::from_str_unsafe(TA_NAME) }
}
