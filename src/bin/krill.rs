// Added so that the call chain from http/auth.rs through to Authorizer doesn't
// exceed the recursion limit within future macro expansion. Possibly related to
// this:
//   "Note that select! relies on proc-macro-hack, and may require to set the
//    compiler's recursion limit very high, e.g. #![recursion_limit="1024"]."
// From: https://docs.rs/futures/0.3.6/futures/macro.select.html
#![recursion_limit = "155"]

#![type_length_limit = "5000000"]

extern crate krill;

use krill::daemon::http::server;

#[tokio::main]
async fn main() {
    if let Err(e) = server::start(None).await {
        eprintln!("Krill failed to start: {}", e);
        ::std::process::exit(1);
    }
}
