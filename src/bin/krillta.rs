use std::process;
use krill::cli::ta::options::Command;

fn main() {
    let status = match Command::from_args() {
        Command::Proxy(proxy) => {
            let format = proxy.general.format;
            proxy.run().report(format)
        }
        Command::Signer(signer) => {
            let format = signer.format;
            signer.run().report(format)
        }
    };
    process::exit(status);
}
