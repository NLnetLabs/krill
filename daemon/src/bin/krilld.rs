extern crate krill_daemon;

use krill_daemon::config::Config;
use krill_daemon::http::server::PubServerApp;

fn main() {
    match Config::create() {
        Ok(config) => PubServerApp::run(&config),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
