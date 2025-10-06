//! Common types used by the various Krill components.
pub mod actor;
pub mod cmslogger;
pub mod crypto;
pub mod error;
pub mod eventsourcing;
pub mod ext_serde;
pub mod file;
pub mod httpclient;
pub mod queue;
pub mod storage;
pub mod test;
pub mod util;
pub mod version;

//------------ Response Aliases ----------------------------------------------

pub use self::error::Error;

pub type KrillEmptyResult = std::result::Result<(), Error>;
pub type KrillResult<T> = std::result::Result<T, Error>;
