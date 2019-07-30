extern crate ignore;

use ignore::Walk;
use std::process::Command;

//#[allow(dead_code)]
fn main() {
    for result in Walk::new("./ui/src") {
        if let Ok(entry) = result {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
    Command::new("./build-dist.sh").status().unwrap();
}
