//! Command line client to the publication server.
//!
//! Can be used for testing the publication server, but may also be useful
//! for setups where a CA simply writes its current state to some disk, so
//! that this CLI may be triggered to synchronise this state to a publication
//! server.

extern crate rpubd;

use rpubd::pubc::config::{ Config, RunMode };
use rpubd::pubc::client::PubClient;

fn main() {

    let config = match Config::create() {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    };

    let mut client = match PubClient::new(config.state_dir()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    };

    let result = match config.mode() {
        RunMode::Init => client.init(config.name().clone()),
        _ => {
            unimplemented!()
        }
    };
    match result {
        Ok(()) => {}//,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}