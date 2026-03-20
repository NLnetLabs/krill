//! The Krill server.
//!
//! This module contains all the components that implement the Krill server
//! itself, its business logic, if you will. The server is controlled via
//! the [`daemon`][super::daemon] which primarily provides the HTTP server.
//!
//! Nearly everything in the Krill server is sync, with the notable exception
//! of the HTTP client user to talk to remote parents and publication servers.
//! However, the server can be run in parallel in multiple threads. The
//! translation between the async HTTP server code and the sync Krill server
//! happens in [`daemon`][super::daemon] as well.
//!
//! Primarily, interaction with the server should happen through the types
//! in the [`manager`] module only.
//!
//! The additional modules contain the individual components of the server.
//! The main components are:
//!
//! * [`ca`]: the RPKI certification authority which collects the
//!   configuration for each CA and translates it into objects.
//! * [`pubd`]: the publication server which manages the data that is
//!   published by a Krill instance.
//! * [`taproxy`]: the server-side of managing a trust anchor which interacts
//!   with the [`tasigner`][crate::tasigner].
//!
//! In addition, there are a number of helper components:
//!
//! * [`bgp`]: the BGP analyser which uses RISwhois data to check ROA
//!   configurations and suggests changes.
//! * [`mq`] and [`scheduler`]: a task queue which is used to schedule and
//!   then execute follow-up or recurring tasks.
//! * [`properties`]: a place to store and update certain properties of a
//!   Krill instance.
//!
//! All of this is tied together through the [`runtime`] module which makes
//! all components available to all other components, avoiding complicated
//! side-ways relationships.

pub mod bgp;
pub mod ca;
pub mod manager;
pub mod mq;
pub mod properties;
pub mod pubd;
pub mod runtime;
pub mod scheduler;
pub mod taproxy;

