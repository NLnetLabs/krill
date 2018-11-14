extern crate rpubd;

#[macro_use] extern crate lazy_static;

use rpubd::pubd::config::Config;
use rpubd::pubd::server;

lazy_static! {
    static ref CONFIG: Config = {
        match Config::create() {
            Ok(c)  => c,
            Err(e) => {
                eprintln!("{}", e);
                ::std::process::exit(1);
            }
        }
    };
}

fn main() {
    server::serve(&CONFIG);
}
