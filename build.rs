use std::process::Command;

#[allow(dead_code)]
fn main() {
    Command::new("./build-dist.sh").status().unwrap();
}