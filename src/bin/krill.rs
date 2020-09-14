#![type_length_limit = "5000000"]

extern crate krill;

use krill::daemon::http::server;

#[tokio::main]
async fn main() {
    if let Err(e) = server::start().await {
        eprintln!("Krill failed to start: {}", e);
        ::std::process::exit(1);
    }
}
