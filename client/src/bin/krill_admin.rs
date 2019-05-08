extern crate krill_client;

use krill_client::KrillClient;
use krill_client::options::Options;
use krill_client::report::ReportFormat;

fn main() {
    match Options::from_args() {
        Ok(options) => {
            let format = options.format().clone();
            match KrillClient::report(options) {
                Ok(()) => {} //,
                Err(e) => {
                    if format != ReportFormat::None {
                        eprintln!("{}", e);
                    }
                    ::std::process::exit(1);
                }
            }
        },
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}