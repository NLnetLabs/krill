//! Certificate Authority related code.
//!
use krill_commons::api::Handle;

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
pub use self::commands::Cmd;
pub use self::commands::CmdDet;

mod events;
pub use self::events::Evt;
pub use self::events::EvtDet;
pub use self::events::Ini;
pub use self::events::IniDet;

mod server;
pub use self::server::CaServer;

mod signing;
pub use self::signing::SignSupport;
pub use self::signing::Signer;

mod error;
pub use self::error::Error;
pub use self::error::ServerError;

pub type Result<T> = std::result::Result<T, Error>;
pub type ServerResult<R, S> = std::result::Result<R, ServerError<S>>;
pub type ParentHandle = Handle;
pub type ChildHandle = Handle;

pub const TA_NAME: &str = "ta"; // reserved for TA

pub fn ta_handle() -> Handle {
    Handle::from(TA_NAME)
}
