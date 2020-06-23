//! Common types used by the various Krill components.
pub mod api;
pub mod bgp;
pub mod error;
pub mod eventsourcing;
pub mod remote;
pub mod util;

//------------ Response Aliases ----------------------------------------------

pub type KrillEmptyResult = std::result::Result<(), self::error::Error>;
pub type KrillResult<T> = std::result::Result<T, self::error::Error>;
