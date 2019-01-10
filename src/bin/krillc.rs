extern crate krill;

use krill::client::krillc::{KrillClient, Options, Error};
use krill::client::data::ReportFormat;

fn error(error: Error) {
    eprintln!("{}", error);
    ::std::process::exit(1);
}

fn main() {
    match Options::from_args() {
        Ok(options) => {
            let format = options.format().clone();
            match KrillClient::report(options) {
                Ok(()) => {} //,
                Err(e) => {
                    if format != ReportFormat::None {
                        error(e)
                    }
                }
            }
        },
        Err(e) => {
            error(e)
        }
    }
}