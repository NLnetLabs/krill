//! The Krill command line client.

use std::{env, process};
use krill::cli::client::KrillClient;
use krill::cli::options::Options;
use krill::cli::report::Report;
use krill::constants;


//------------ main ----------------------------------------------------------

#[tokio::main]
async fn main() {
    let options = Options::from_args();
    let client = KrillClient::new(
        options.general.server, options.general.token
    );

    let client = match client {
        Ok(client) => client,
        Err(err) => {
            let status = Report::from_err(err).report(options.general.format);
            process::exit(status);
        }
    };

    if options.general.api {
        // Safety: There shouldn’t be anything else going on at this point.
        //         XXX That said, we need to replace this mechanism.
        unsafe { env::set_var(constants::KRILL_CLI_API_ENV, "1"); }
    }
    let report = options.command.run(&client).await;
    let status = report.report(options.general.format);
    process::exit(status);
}

