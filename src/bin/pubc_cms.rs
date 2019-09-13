//! Command line client for the publication server. Uses the api.
extern crate krill;

use krill::pubc::cmsclient;
use krill::pubc::cmsclient::PubClient;

fn main() {
    let options = match cmsclient::Options::create() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    };

    let format = options.format().clone();

    match PubClient::execute(options) {
        Ok(res) => res.report(&format),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
