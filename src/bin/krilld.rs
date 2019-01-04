extern crate krill;

use krill::daemon::config::Config;
use krill::daemon::http::server::PubServerApp;

fn main() {
    match Config::create() {
        Ok(config) => PubServerApp::run(&config),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
