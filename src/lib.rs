#![allow(
    clippy::result_large_err,
    clippy::large_enum_variant
)]
//! The _Krill_ library crate.

pub mod api;
pub mod cli;
pub mod commons;
pub mod config;
pub mod constants;
pub mod daemon;
pub mod server;
pub mod tasigner;
pub mod upgrades;
