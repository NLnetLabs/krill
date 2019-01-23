extern crate krill;

use krill::krilld::config::Config;
use krill::krilld::http::server::PubServerApp;

fn main() {
    match Config::create() {
        Ok(config) => PubServerApp::run(&config),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
