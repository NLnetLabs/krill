#![recursion_limit = "155"]

extern crate krill;

use krill::cli::options::KrillPubcOptions;
use krill::cli::report::ReportFormat;
use krill::cli::{Error, KrillPubdClient};
use krill::commons::util::httpclient;

#[tokio::main]
async fn main() {
    match KrillPubcOptions::from_args() {
        Ok(options) => {
            let format = options.format;
            match KrillPubdClient::report(options).await {
                Ok(()) => {} //,
                Err(e) => {
                    if format != ReportFormat::None {
                        match &e {
                            Error::HttpClientError(httpclient::Error::ErrorWithJson(_code, res)) => {
                                if format == ReportFormat::Json {
                                    eprintln!("{}", e);
                                } else if let Some(delta_error) = res.delta_error() {
                                    eprintln!("Delta rejected:\n\n{}", delta_error);
                                } else {
                                    eprintln!("Error: {}", res.msg());
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
