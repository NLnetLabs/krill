extern crate krill;

use krill::cli::options::Options;
use krill::cli::report::ReportFormat;
use krill::cli::{Error, KrillClient};
use krill::commons::util::httpclient;

fn main() {
    match Options::from_args() {
        Ok(options) => {
            let format = options.format();
            match KrillClient::report(options) {
                Ok(()) => {} //,
                Err(e) => {
                    if format != ReportFormat::None {
                        match &e {
                            Error::HttpClientError(httpclient::Error::ErrorWithJson(
                                _code,
                                res,
                            )) => {
                                if format == ReportFormat::Json {
                                    eprintln!("{}", e);
                                } else {
                                    eprintln!("Error {}: {}", res.code(), res.msg());
                                }
                            }
                            _ => {
                                eprintln!("{}", e);
                            }
                        }
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
