use std::process::Command;

#[allow(dead_code)]
fn main() {
    println!("cargo:rerun-if-changed=ui/dev");
    Command::new("./build-dist.sh").status().unwrap();
}