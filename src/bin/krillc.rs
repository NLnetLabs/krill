extern crate krill;

use krill::client::data::ReportFormat;
use krill::client::krillc::KrillClient;
use krill::client::options::Options;

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