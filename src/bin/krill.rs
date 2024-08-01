extern crate krill;

use std::path::PathBuf;
use std::sync::Arc;
use clap::Parser;
use log::error;
use krill::constants::{
    KRILL_DEFAULT_CONFIG_FILE, KRILL_SERVER_APP, KRILL_VERSION
};
use krill::daemon::{config::Config, http::server};


//------------ Args ----------------------------------------------------------

#[derive(clap::Parser)]
#[command(
    version = KRILL_VERSION, name = KRILL_SERVER_APP,
    about, long_about = None,
)]
struct Args {
    /// Override the path to the config file
    #[arg(short, long, default_value = KRILL_DEFAULT_CONFIG_FILE)]
    config: PathBuf,
}


//------------ main ----------------------------------------------------------

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match Config::create(&args.config, false) {
        Ok(config) => {
            if let Err(e) = server::start_krill_daemon(
                Arc::new(config), None
            ).await {
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
