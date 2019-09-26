extern crate krill;

use krill::daemon::config::Config;
use krill::daemon::http::server;

fn main() {
    match Config::create() {
        Ok(config) => server::start(&config).unwrap(),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
