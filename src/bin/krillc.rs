extern crate krill;

use krill::client::krillc::{KrillClient, Options, Error};

fn error(error: Error) {
    eprintln!("{}", error);
    ::std::process::exit(1);
}

fn main() {
    match Options::from_args() {
        Ok(options) => {
            match KrillClient::report(options) {
                Ok(()) => {} //,
                Err(e) => error(e)
            }
        },
        Err(e) => {
            error(e)
        }
    }
}