//! The _Krill_ library crate.

// XXX Temporary allow for `commons::error::Error` until we refactor that.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod cli;
pub mod commons;
pub mod config;
pub mod constants;
pub mod daemon;
pub mod server;
pub mod tasigner;
pub mod upgrades;
