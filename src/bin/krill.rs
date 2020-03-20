extern crate krill;

use std::process;

use krill::commons::util::file;
use krill::daemon::config::Config;
use krill::daemon::http::server;

#[tokio::main]
async fn main() {
    match Config::create() {
        Ok(config) => {
            let pid_file = config.pid_file();
            if let Err(e) = file::save(process::id().to_string().as_bytes(), &pid_file) {
                eprintln!("Could not write PID file: {}", e);
                ::std::process::exit(1);
            }

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
