// Added so that the call chain from http/auth.rs through to Authorizer doesn't
// exceed the recursion limit within future macro expansion. Possibly related to
// this:
//   "Note that select! relies on proc-macro-hack, and may require to set the
//    compiler's recursion limit very high, e.g. #![recursion_limit="1024"]."
// From: https://docs.rs/futures/0.3.6/futures/macro.select.html
#![recursion_limit = "155"]

extern crate krill;

use std::env;
use std::sync::Arc;

use krill::constants::KRILL_ENV_TESTBED_ENABLED;
use krill::daemon::http::server;
use krill::daemon::krillserver::KrillMode;

#[tokio::main]
async fn main() {
    match server::parse_config() {
        Ok(config) => {
            let mode = if env::var(KRILL_ENV_TESTBED_ENABLED).is_ok() {
                KrillMode::Testbed
            } else {
                KrillMode::Ca
            };

            if let Err(e) = server::start_krill_daemon(Arc::new(config), mode).await {
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
