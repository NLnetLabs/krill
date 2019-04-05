extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate krill;
extern crate krill_commons;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::{thread, time};
use actix::System;
use krill::krillc::options::{AddPublisher, Command, Options, PublishersCommand, Rfc8181Command, AddRfc8181Client};
use krill::krillc::KrillClient;
use krill::krilld::config::Config;
use krill::krilld::http::server::PubServerApp;
use krill::krillc::report::ApiResponse;
use krill::krillc::report::ReportFormat;
use krill_commons::util::test;
use krill::pubc::cmsclient::PubClient;

fn execute_krillc_command(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::http_uri("http://localhost:3000/"),
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

fn list_rfc8181_clients() -> ApiResponse {
    let command = Command::Rfc8181(Rfc8181Command::List);
    execute_krillc_command(command)
}

#[test]
fn admin_publishers() {
    test::test_with_tmp_dir(|d| {

        let handle = "alice";
        let token = "secret";
        let base_rsync_uri_alice = "rsync://127.0.0.1/repo/alice/";

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
        thread::sleep(time::Duration::from_millis(500));

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

        // List RFC8181 clients
        let rfc8181_clients_res = list_rfc8181_clients();
        match rfc8181_clients_res {
            ApiResponse::Rfc8181ClientList(list) => {
                assert_eq!(0, list.len())
            },
            _ => panic!("Expected a response (with empty list)")
        }

        // Add an RFC8181 client
        let client_dir = test::create_sub_dir(&d);
        let mut client = PubClient::build(&client_dir).unwrap();
        client.init("alice").unwrap();
        let pr = client.publisher_request().unwrap();
        let mut pr_path = d.clone();
        pr_path.push("alice.xml");
        pr.save(&pr_path).unwrap();

        let command = Command::Rfc8181(
            Rfc8181Command::Add(
                AddRfc8181Client { token: "alice".to_string(), xml: pr_path }
            )
        );
        match execute_krillc_command(command) {
            ApiResponse::Empty => {},
            _ => panic!("Expect ok")
        }

        // Now see that it's been added.
        let rfc8181_clients_res = list_rfc8181_clients();
        match rfc8181_clients_res {
            ApiResponse::Rfc8181ClientList(list) => {
                assert_eq!(1, list.len())
            },
            _ => panic!("Expected a response (with 1 entry in the list)")
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

