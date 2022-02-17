extern crate krill;

use krill::{
    cli::{
        options::Options,
        report::ReportFormat,
        {Error, KrillClient},
    },
    commons::util::httpclient,
};

#[tokio::main]
async fn main() {
    match Options::from_args() {
        Ok(options) => {
            let format = options.format();
            match KrillClient::report(options).await {
                Ok(()) => {} //,
                Err(e) => {
                    if format != ReportFormat::None {
                        match &e {
                            Error::HttpClientError(httpclient::Error::ErrorResponseWithJson(_uri, _code, res)) => {
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
