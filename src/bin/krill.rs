extern crate krill;

use krill::daemon::config::Config;
use krill::daemon::http::server;

#[tokio::main]
async fn main() {
    match Config::create() {
        Ok(config) => {
            if let Err(e) = server::start(config).await {
                eprintln!("Krill failed to start: {}", e);
                ::std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            ::std::process::exit(1);
        }
    }
}
