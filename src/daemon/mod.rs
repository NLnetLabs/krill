//! The Krill daemon.
//!
//! This module contains the code actually driving the daemon including
//! processing HTTP requests for the API.
//!
//! Everything related to processing HTTP requests can be found in the
//! [`http`] module. The [`start`] module contains the actual socket
//! listeners and connection handlers as well as the start-up code for
//! the daemon.
//!
//! # _Refactoring to be done_
//!
//! * Turn the current [`HttpServer`][http::server::HttpServer] into the
//!   `KrillDaemon` and attach all the things currently done in [`start`]
//!   to it.
//! * Then move everything from [`http`] up here.
//! * Limit what needs to be `pub`. Ideally, only the new `KrillDaemon`
//!   needs to be, but there are a few things that are referred to in the
//!   config. Consider moving those to the [`config`][crate::config] module
//!   and refer to them from here instead.
//! * Improve the error flow within the daemon to allow fatal errors to make
//!   Krill exit.

pub mod http;
pub mod start;

