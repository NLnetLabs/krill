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
use krill::krillc::data::ReportFormat;
use krill::krillc::options::{
    AddPublisher,
    Command,
    Options,
    PublishersCommand
};
use krill::krillc::KrillClient;
use krill::krilld::config::Config;
use krill::krilld::http::server::PubServerApp;
use krill::util::test;
use krill::pubc::apiclient;
use krill::pubc::apiclient::ApiResponse;
use krill::util::file::CurrentFile;
use krill::util::file;
use std::collections::HashSet;
use krill::util::httpclient;

#[test]
fn client_publish_at_server() {
    test::test_with_tmp_dir(|d| {


        let server_uri = "http://localhost:3000/";
        let handle = "alice";
        let token = "secret";
        let base_rsync_uri = "rsync://127.0.0.1/repo/alice/";

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
        {
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                "secret",
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Add(
                    AddPublisher {
                        handle: handle.to_string(),
                        base_uri: test::rsync_uri(base_rsync_uri),
                        token: token.to_string()
                    }
                ))
            );
            let res = KrillClient::process(krillc_opts);
            assert!(res.is_ok())
        }

        // Calls to api should require the correct token
        {
            let res = apiclient::execute(apiclient::Options::list(
                server_uri,
                handle,
                "wrong token"
            ).unwrap());

            match res {
                Err(apiclient::Error::HttpClientError
                    (httpclient::Error::Forbidden)) => {},
                _ => panic!("Expected forbidden")
            }
        }

        // List files at server, expect no files
        {
            let list = apiclient::execute(apiclient::Options::list(
                server_uri,
                handle,
                token
            ).unwrap()).unwrap();

            match list {
                ApiResponse::List(list) => {
                    assert_eq!(0, list.elements().len());
                },
                _ => panic!("Expected list")
            }
        }

        // Create files on disk to sync
        let sync_dir = test::create_sub_dir(&d);
        let file_a = CurrentFile::new(
            test::rsync_uri("rsync://127.0.0.1/repo/alice/a.txt"),
            test::as_bytes("a")
        );
        let file_b = CurrentFile::new(
            test::rsync_uri("rsync://127.0.0.1/repo/alice/b.txt"),
            test::as_bytes("b")
        );
        let file_c = CurrentFile::new(
            test::rsync_uri("rsync://127.0.0.1/repo/alice/c.txt"),
            test::as_bytes("c")
        );

        file::save_in_dir(file_a.content(), &sync_dir, "a.txt").unwrap();
        file::save_in_dir(file_b.content(), &sync_dir, "b.txt").unwrap();
        file::save_in_dir(file_c.content(), &sync_dir, "c.txt").unwrap();

        // Sync files
        {
            let api_res = apiclient::execute(apiclient::Options::sync(
                server_uri,
                handle,
                token,
                &sync_dir.to_string_lossy(),
                base_rsync_uri
            ).unwrap()).unwrap();

            assert_eq!(ApiResponse::Success, api_res);
        }

        // We should now see these files when we list
        {
            let list = apiclient::execute(apiclient::Options::list(
                server_uri,
                handle,
                token
            ).unwrap()).unwrap();

            match list {
                ApiResponse::List(list) => {
                    assert_eq!(3, list.elements().len());

                    let returned_set: HashSet<_>  = list.elements().into_iter().collect();

                    let list_el_a = file_a.into_list_element();
                    let list_el_b = file_b.into_list_element();
                    let list_el_c = file_c.into_list_element();

                    let expected_elements = vec![
                        &list_el_a,
                        &list_el_b,
                        &list_el_c
                    ];
                    let expected_set: HashSet<_> = expected_elements.into_iter().collect();
                    assert_eq!(expected_set, returned_set);
                },
                _ => panic!("Expected list")
            }
        }

        // Now we should be able to delete it all again
        file::delete_in_dir(&sync_dir, "a.txt").unwrap();
        file::delete_in_dir(&sync_dir, "b.txt").unwrap();
        file::delete_in_dir(&sync_dir, "c.txt").unwrap();

        // Sync files
        {
            let api_res = apiclient::execute(apiclient::Options::sync(
                server_uri,
                handle,
                token,
                &sync_dir.to_string_lossy(),
                base_rsync_uri
            ).unwrap()).unwrap();

            assert_eq!(ApiResponse::Success, api_res);
        }

        // List files at server, expect no files
        {
            let list = apiclient::execute(apiclient::Options::list(
                server_uri,
                handle,
                token
            ).unwrap()).unwrap();

            match list {
                ApiResponse::List(list) => {
                    assert_eq!(0, list.elements().len());
                },
                _ => panic!("Expected list")
            }
        }


    });
}

