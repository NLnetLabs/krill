pub const KRILL_VERSION: &str = "0.2.1";
pub const KRILL_SERVER_APP: &str = "NLnet Labs RRDP Server";
pub const KRILL_CLIENT_APP: &str = "Krill Client";

extern crate clap;
#[macro_use]
extern crate derive_more;
extern crate rpki;
#[macro_use]
extern crate serde;
extern crate base64;
#[macro_use]
extern crate bcder;
extern crate bytes;
extern crate chrono;
extern crate futures;
extern crate hex;
#[macro_use]
extern crate log;
extern crate actix_identity;
extern crate actix_service;
extern crate actix_session;
extern crate actix_web;
extern crate clokwerk;
extern crate openssl;
extern crate rand;
extern crate reqwest;
extern crate serde_json;
extern crate syslog;
extern crate tokio;
extern crate toml;
extern crate uuid;
extern crate xml as xmlrs;

pub mod cli;
pub mod commons;
pub mod daemon;
pub mod pubd;
