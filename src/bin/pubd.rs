extern crate actix;
extern crate rpubd;

#[macro_use] extern crate lazy_static;
extern crate core;

use rpubd::pubd::config::Config;
use rpubd::pubd::http::PubServerApp;

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
    PubServerApp::run(&CONFIG)
}
