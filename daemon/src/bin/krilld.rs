extern crate krill_daemon;

use krill_daemon::config::Config;
use krill_daemon::http::server;

fn main() {
    match Config::create() {
        Ok(config) => server::start(&config).unwrap(),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
