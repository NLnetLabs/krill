//! The Krill trust anchor manager.

use std::process;
use krill::cli::ta::options::Command;


//------------ main ----------------------------------------------------------

#[tokio::main]
async fn main() {
    let status = match Command::from_args() {
        Command::Proxy(proxy) => {
            let format = proxy.general.format;
            proxy.run().await.report(format)
        }
        Command::Signer(signer) => {
            let format = signer.format;
            signer.run().report(format)
        }
    };
    process::exit(status);
}
