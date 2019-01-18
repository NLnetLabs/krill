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
use krill::client::krillc;
use krill::client::krillc::KrillClient;
use krill::client::options::{
    Command,
    Options,
    PublishersCommand
};
use krill::client::pubc::PubClient;
use krill::util::test;
use krill::remote::rfc8183::RepositoryResponse;
use reqwest::StatusCode;

/// Tests that we can list publishers through the API
#[test]
fn manage_publishers() {
    test::test_with_tmp_dir(|d| {

        let token = "secret";

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

        // Set up a client "alice"
        {
            let client_dir = test::create_sub_dir(&d);
            let mut client = PubClient::new(&client_dir).unwrap();
            client.init("alice").unwrap();
            let pr = client.publisher_request().unwrap();
            test::save_pr(&d, "alice.xml", &pr);

        }

        // Add client "alice"
        {
            let mut alice_path = d.clone();
            alice_path.push("alice.xml");
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Add(
                    alice_path,
                    None
                ))
            );
            let res = KrillClient::process(krillc_opts);
            assert!(res.is_ok())
        }

        // Find "alice" in the list
        {
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
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
        }

        // Find details for "alice"
        {
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Details("alice".to_string()))
            );

            let res = KrillClient::process(krillc_opts).unwrap();

            match res {
                ApiResponse::PublisherDetails(details) => {
                    assert_eq!(
                        details.publisher_handle(),
                        "alice"
                    );
                }
                _ => assert!(false) // Fail!
            }
        }

        // Get repository response for "alice"
        {
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(
                    PublishersCommand::RepositoryResponseXml(
                        "alice".to_string(),
                        None
                    )
                )
            );

            let res = KrillClient::process(krillc_opts).unwrap();

            match res {
                ApiResponse::GenericBody(xml) => {
                    // Assert that the response is a valid response.xml
                    let xml = RepositoryResponse::decode(xml.as_bytes()).unwrap();
                    assert_eq!(xml.publisher_handle(), "alice")
                }
                _ => assert!(false) // Fail!
            }
        }

        // Remove "alice"
        {
            let mut alice_path = d.clone();
            alice_path.push("alice.xml");
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Remove("alice".to_string()))
            );
            let res = KrillClient::process(krillc_opts);
            assert!(res.is_ok());

            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Details("alice".to_string()))
            );

            let res = KrillClient::process(krillc_opts);

            match res {
                Err(krillc::Error::BadStatus(code)) => {
                    assert_eq!(code, StatusCode::NOT_FOUND);
                },
                _ => assert!(false) // should have failed!
            }

            assert!(res.is_err());
        }

        // Add a publisher using a non-default name, i.e. not the one the
        // client included in the publisher request --> Add alice as "bob"
        {
            let mut alice_path = d.clone();
            alice_path.push("alice.xml");
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Add(
                    alice_path,
                    Some("bob".to_string())
                ))
            );
            let res = KrillClient::process(krillc_opts);
            assert!(res.is_ok());

            // Find details for bob
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                token,
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Details("bob".to_string()))
            );

            let res = KrillClient::process(krillc_opts).unwrap();

            match res {
                ApiResponse::PublisherDetails(details) => {
                    assert_eq!(
                        details.publisher_handle(),
                        "bob"
                    );
                }
                _ => assert!(false) // Fail!
            }
        }

    });
}

