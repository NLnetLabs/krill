extern crate rpubd;
extern crate tokio;

#[macro_use] extern crate lazy_static;

use rpubd::pubd::config::Config;
use rpubd::pubd::daemon;

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

    use tokio::runtime::Runtime;
    use tokio::prelude::*;

    // Note, using a runtime and spawn here, with another spawn
    // inside server::serve, in order to allow testing the server
    // in integration tests, and shutting it down. A 'run' in
    // server::serve would be simpler, but would not allow for easy
    // shutdown of thr server in a test.
    let mut rt = Runtime::new().unwrap();

    rt.spawn(
        future::lazy(|| {
            daemon::serve(&CONFIG);
            Ok(())
        })
    );

    loop {
        // wait forever
    }
}
