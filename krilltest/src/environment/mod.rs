//! All the parts of the test environment.
pub use self::core::Environment;
pub use self::nginx::NginxServer;

pub mod core;
pub mod krill;
pub mod nginx;
pub mod routinator;

use std::io::{BufRead, BufReader};
use std::process;

fn prefix_process_output<T: ToString>(name: T, process: &mut process::Child) {
    let pid = process.id();
    let stdout = process.stdout.take().unwrap();
    let stderr = process.stderr.take().unwrap();

    let out_name = name.to_string();
    std::thread::spawn(move || {
        let mut iter = BufReader::new(stdout).lines().into_iter();
        while let Some(Ok(line)) = iter.next() {
            println!("[{pid}] {out_name}: {line}");
        }
    });

    let err_name = name.to_string();
    std::thread::spawn(move || {
        let mut iter = BufReader::new(stderr).lines().into_iter();
        while let Some(Ok(line)) = iter.next() {
            println!("[{pid}] {err_name}: {line}");
        }
    });
}
