use std::{env, process};
use krill::cli::client::KrillClient;
use krill::cli::options::Options;
use krill::constants;


fn main() {
    let options = Options::from_args();
    let client = KrillClient::new(
        options.general.server, options.general.token
    );
    if options.general.api {
        env::set_var(constants::KRILL_CLI_API_ENV, "1")
    }
    let report = options.command.run(&client);
    let status = report.report(options.general.format);
    process::exit(status);
}
