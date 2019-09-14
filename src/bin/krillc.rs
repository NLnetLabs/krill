extern crate krill;

use krill::cli::options::Options;
use krill::cli::report::ReportFormat;
use krill::cli::KrillClient;

fn main() {
    match Options::from_args() {
        Ok(options) => {
            let format = options.format();
            match KrillClient::report(options) {
                Ok(()) => {} //,
                Err(e) => {
                    if format != ReportFormat::None {
                        eprintln!("{}", e);
                    }
                    ::std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
