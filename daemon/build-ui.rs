extern crate ignore;

use std::process::Command;
use ignore::Walk;

//#[allow(dead_code)]
fn main() {
    for result in Walk::new("./ui/src") {
        if let Ok(entry) = result {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
    Command::new("./build-dist.sh").status().unwrap();
}