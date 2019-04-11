//! Command line client for the publication server. Uses the api.
extern crate krill_pubc;

use krill_pubc::apiclient;

fn main() {

    let options = match apiclient::Options::create() {
        Ok(o)  => o,
        Err(e) => {
            eprintln!("Error parsing options: {}", e);
            ::std::process::exit(1);
        }
    };

    let format = options.format().clone();

    match apiclient::execute(options) {
        Ok(res) => res.report(&format),
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }

}