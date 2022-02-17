extern crate krill;

use std::sync::Arc;

use clap::{App, Arg};
use log::error;

use krill::{
    constants::{KRILL_DEFAULT_CONFIG_FILE, KRILL_SERVER_APP, KRILL_VERSION},
    daemon::{config::Config, http::server},
};

#[tokio::main]
async fn main() {
    let matches = App::new(KRILL_SERVER_APP)
        .version(KRILL_VERSION)
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help(&format!(
                    "Override the path to the config file (default: '{}')",
                    KRILL_DEFAULT_CONFIG_FILE
                ))
                .required(false),
        )
        .get_matches();

    let config_file = matches.value_of("config").unwrap_or(KRILL_DEFAULT_CONFIG_FILE);

    match Config::create(config_file, false) {
        Ok(config) => {
            if let Err(e) = server::start_krill_daemon(Arc::new(config)).await {
                error!("Krill failed to start: {}", e);
                ::std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Could not parse config: {}", e);
            ::std::process::exit(1);
        }
    }
}
