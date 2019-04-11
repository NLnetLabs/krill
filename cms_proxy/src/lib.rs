//! This module provides support for proxying RFC compliant clients, using XML in
//! CMS to the krill native HTTPS JSON API.

extern crate base64;
#[macro_use] extern crate bcder;
extern crate bytes;
extern crate chrono;
#[macro_use] extern crate derive_more;
extern crate fern;
extern crate hex;
extern crate krill_commons;
#[macro_use] extern crate log;
extern crate openssl;
extern crate rpki;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate xml as xmlrs;

// Support parsing json sent to the actix server
extern crate actix;
extern crate actix_web;
extern crate futures;

// XXX Temporarily
extern crate ring;
extern crate untrusted;

pub mod api;
pub mod builder;
pub mod clients;
pub mod fromreq;
pub mod id;
pub mod proxy;
pub mod responder;
pub mod rfc8181;
pub mod rfc8183;
pub mod sigmsg;