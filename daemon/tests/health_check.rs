extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::{thread, time};
use actix::System;
use krill_client::KrillClient;
use krill_client::options::{
    Command,
    Options
};
use krill_client::report::{
    ApiResponse,
    ReportFormat
};
use krill_commons::util::test;
use krill_daemon::config::Config;
use krill_daemon::http::server::PubServerApp;

/// Tests that the server can be started and a health check can be done
/// through the CLI
#[test]
#[ignore]
fn health_check() {
    test::test_with_tmp_dir(|d| {
        // Set up a test PubServer Config with a client in it.
        let server_conf = {
            // Use a data dir for the storage
            let data_dir = test::create_sub_dir(&d);
            Config::test(&data_dir)
        };

        // Start the server
        thread::spawn(||{
            System::run(move || {
                PubServerApp::start(&server_conf);
            })
        });

        // XXX TODO: Find a better way to know the server is ready!
        thread::sleep(time::Duration::from_millis(500));

        let krillc_opts = Options::new(
            test::https_uri("https://localhost:3000/"),
            "secret",
            ReportFormat::Default,
            Command::Health
        );

        let res = KrillClient::process(krillc_opts);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res, ApiResponse::Health)
    });
}

