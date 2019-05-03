extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate krill_commons;
extern crate krill_client;
extern crate krill_daemon;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::{thread, time};
use actix::System;
use krill_client::options::{AddPublisher, Command, Options, PublishersCommand};
use krill_client::KrillClient;
use krill_client::report::ApiResponse;
use krill_client::report::ReportFormat;
use krill_commons::util::test;
use krill_daemon::config::Config;
use krill_daemon::http::server::PubServerApp;

fn execute_krillc_command(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::https_uri("https://localhost:3000/"),
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

fn add_publisher(handle: &str, base_uri: &str, token: &str) {
    let command = Command::Publishers(PublishersCommand::Add(
        AddPublisher {
            handle: handle.to_string(),
            base_uri: test::rsync_uri(base_uri),
            token: token.to_string()
        }
    ));
    execute_krillc_command(command);
}

fn deactivate_publisher(handle: &str) {
    let command = Command::Publishers(
        PublishersCommand::Deactivate(handle.to_string())
    );

    execute_krillc_command(command);
}

fn list_publishers() -> ApiResponse {
    let command = Command::Publishers(
        PublishersCommand::List
    );

    execute_krillc_command(command)
}

fn details_publisher(handle: &str) -> ApiResponse {
    let command = Command::Publishers(
        PublishersCommand::Details(handle.to_string())
    );

    execute_krillc_command(command)
}

#[test]
#[ignore]
fn admin_publishers() {
    test::test_with_tmp_dir(|d| {

        let handle = "alice";
        let token = "secret";
        let base_rsync_uri_alice = "rsync://localhost/repo/alice/";

        // Set up a test PubServer Config
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
        thread::sleep(time::Duration::from_millis(30000));

        // Add client "alice"
        add_publisher(handle, base_rsync_uri_alice, token);

        // Find "alice" in list
        let res = list_publishers();
        match res {
            ApiResponse::PublisherList(list) => {
                // there should be one and it should be alice
                assert_eq!(1, list.publishers().len());
                let alice = &list.publishers().get(0).unwrap();
                assert_eq!("alice", alice.id());
            },
            _ => panic!("Expected publisher list")
        }

        // Find details for alice
        let details_res = details_publisher("alice");
        match details_res {
            ApiResponse::PublisherDetails(details) => {
                assert_eq!("alice", details.handle());
                assert_eq!(false, details.deactivated());
            },
            _ => panic!("Expected details")
        }

        // Remove alice
        deactivate_publisher(handle);

        // Expect that alice still exists, but is now deactivated.
        let details_res = details_publisher("alice");
        match details_res {
            ApiResponse::PublisherDetails(details) => {
                assert_eq!("alice", details.handle());
                assert_eq!(true, details.deactivated());
            },
            _ => panic!("Expected details")
        }

    });
}

