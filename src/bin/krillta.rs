extern crate krill;

use krill::cli::ta_client::*;

#[tokio::main]
async fn main() {
    match TrustAnchorClientCommand::from_args() {
        Ok(command) => {
            let fmt = command.report_format();
            match TrustAnchorClient::process(command).await {
                Ok(response) => match response.report(fmt) {
                    Ok(Some(msg)) => println!("{}", msg),
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("{}", e);
                        ::std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("{}", e);
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
