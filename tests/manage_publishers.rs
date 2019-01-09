extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate krill;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::{thread, time};
use actix::System;
use krill::daemon::config::Config;
use krill::daemon::http::server::PubServerApp;
use krill::client::data::{
    ApiResponse,
    ReportFormat
};
use krill::client::krillc::{
    Command,
    KrillClient,
    Options,
    PublishersCommand};
use krill::client::pubc::PubClient;
use krill::util::test;

/// Tests that we can list publishers through the API
#[test]
fn manage_publishers() {
    test::test_with_tmp_dir(|d| {
        // Set up a test PubServer Config with a client in it.
        let server_conf = {
            // Use a data dir for the storage
            let data_dir = test::create_sub_dir(&d);
            let xml_dir = test::create_sub_dir(&d);
            Config::test(&data_dir, &xml_dir)
        };

        // Start the server
        thread::spawn(||{
            System::run(move || {
                PubServerApp::start(&server_conf);
            })
        });

        // XXX TODO: Find a better way to know the server is ready!
        thread::sleep(time::Duration::from_millis(500));

        // Set up a client
        let client_dir = test::create_sub_dir(&d);
        let mut client = PubClient::new(&client_dir).unwrap();
        client.init("alice").unwrap();
        let pr = client.publisher_request().unwrap();
        test::save_pr(&d, "alice.xml", &pr);

        let mut alice_path = d.clone();
        alice_path.push("alice.xml");

        let krillc_opts = Options::new(
            test::http_uri("http://localhost:3000/"),
            "secret",
            ReportFormat::Default,
            Command::Publishers(PublishersCommand::Add(alice_path))
        );
        let _res = KrillClient::process(krillc_opts);

        let krillc_opts = Options::new(
            test::http_uri("http://localhost:3000/"),
            "secret",
            ReportFormat::Default,
            Command::Publishers(PublishersCommand::List)
        );

        let res = KrillClient::process(krillc_opts);
        assert!(res.is_ok());
        let api_response = res.unwrap();

        match api_response {
            ApiResponse::PublisherList(list) => {
                assert!(
                    list.publishers()
                        .into_iter()
                        .find(|p| p.id().as_str() == "alice")
                        .is_some()
                );
            }
            _ => assert!(false) // Fail!
        }
    });
}

