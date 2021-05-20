extern crate krill;

use std::sync::Arc;

use krill::daemon::http::server;

#[tokio::main]
async fn main() {
    match server::parse_config() {
        Ok(config) => {
            if let Err(e) = server::start_krill_daemon(Arc::new(config)).await {
                eprintln!("Krill failed to start: {}", e);
                ::std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Could not parse config: {}", e);
            ::std::process::exit(1);
        }
    }
}
