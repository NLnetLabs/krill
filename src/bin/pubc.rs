//! Command line client to the publication server.
//!
//! Can be used for testing the publication server, but may also be useful
//! for setups where a CA simply writes its current state to some disk, so
//! that this CLI may be triggered to synchronise this state to a publication
//! server.

extern crate rpubd;

#[macro_use] extern crate lazy_static;

use rpubd::pubc::config::Config;

lazy_static! {
    static ref CONFIG: Config = {
        match Config::create() {
            Ok(c)  => c,
            Err(e) => {
                eprintln!("{}", e);
                ::std::process::exit(1);
            }
        }
    };
}

fn main() {
    println!("Data dir: {}", CONFIG.data_dir());
}