extern crate rpubd;

use rpubd::pubd::config::Config;
use rpubd::pubd::http::PubServerApp;

fn main() {
    match Config::create() {
        Ok(config) => PubServerApp::run(&config),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
