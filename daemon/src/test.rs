//! Support for tests in other modules using a running krill server

use std::{thread, time};
use std::path::PathBuf;

use krill_commons::util::test;
use krill_client::KrillClient;
use krill_client::Error;
use krill_client::options::{Command, Options};
use krill_client::report::{ApiResponse, ReportFormat};

use crate::config::Config;
use crate::http::server;

pub fn test_with_krill_server<F>(op: F) where F: FnOnce(PathBuf) -> () {
    test::test_under_tmp(|dir| {
        // Set up a test PubServer Config
        let server_conf = {
            // Use a data dir for the storage
            let data_dir = test::sub_dir(&dir);
            Config::test(&data_dir)
        };

        // Start the server
        thread::spawn(move || { server::start(&server_conf).unwrap() });

        let mut tries = 0;
        loop {
            thread::sleep(time::Duration::from_millis(100));
            if let Ok(_res) = health_check() {
                break
            }

            tries += 1;
            if tries > 20 {
                panic!("Server is not coming up")
            }
        }


        op(dir)
    })
}

pub fn wait_seconds(s: u64) {
    thread::sleep(time::Duration::from_secs(s));
}

fn health_check() -> Result<ApiResponse, Error> {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Default,
        Command::Health
    );

    KrillClient::process(krillc_opts)
}


pub fn krill_admin(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Json,
        command
    );
    match KrillClient::process(krillc_opts) {
        Ok(res) => res, // ok
        Err(e) => {
            panic!("{}", e)
        }
    }
}