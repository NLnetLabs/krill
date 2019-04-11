//! Command line client for the publication server. Uses the api.
extern crate krill_pubc;

use krill_pubc::cmsclient;
use krill_pubc::cmsclient::PubClient;

fn main() {

    let options = match cmsclient::Options::create() {
        Ok(o)  => o,
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