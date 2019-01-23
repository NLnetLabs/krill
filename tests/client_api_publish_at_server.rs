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
use krill::pubc::apiclient::PubClientOptions;
use krill::pubc::apiclient::ApiResponse;

#[test]
fn client_publish_at_server() {
    test::test_with_tmp_dir(|d| {


        let server_uri = "http://localhost:3000/";
        let handle = "alice";
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

        // Add client "alice"
        {
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                "secret",
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Add(
                    AddPublisher {
                        handle: handle.to_string(),
                        base_uri: test::rsync_uri("rsync://127.0.0.1/repo/alice/"),
                        token: token.to_string()
                    }
                ))
            );
            let res = KrillClient::process(krillc_opts);
            assert!(res.is_ok())
        }

        // List files at server
        let list = apiclient::execute(PubClientOptions::list(
            server_uri,
            handle,
            token
        ).unwrap()).unwrap();

        match list {
            ApiResponse::List(list) => {
                assert_eq!(0, list.files().len());
            },
            _ => panic!("Expected list")
        }

//        // now let's sync something real
//        let sync_dir = test::create_sub_dir(&d);
//        let file_a = CurrentFile::new(
//            test::rsync_uri("rsync://127.0.0.1/repo/alice/a.txt"),
//            test::as_bytes("a")
//        );
//        let file_b = CurrentFile::new(
//            test::rsync_uri("rsync://127.0.0.1/repo/alice/b.txt"),
//            test::as_bytes("b")
//        );
//        let file_c = CurrentFile::new(
//            test::rsync_uri("rsync://127.0.0.1/repo/alice/c.txt"),
//            test::as_bytes("c")
//        );
//
//        file::save_in_dir(file_a.content(), &sync_dir, "a.txt").unwrap();
//        file::save_in_dir(file_b.content(), &sync_dir, "b.txt").unwrap();
//        file::save_in_dir(file_c.content(), &sync_dir, "c.txt").unwrap();
//
//        client.sync_dir(&sync_dir).unwrap();
//
//        // We should now see these files when we list
//        let list_reply = client.get_server_list().unwrap();
//        let returned_elements = list_reply.elements().clone();
//        let returned_set = returned_elements.into_iter()
//            .collect::<HashSet<_>>();
//
//        let expected_elements = vec![
//            file_a.to_rfc8181_list_element(),
//            file_b.to_rfc8181_list_element(),
//            file_c.to_rfc8181_list_element()
//        ];
//        let expected_set: HashSet<_> = expected_elements.into_iter()
//            .collect();
//        assert_eq!(expected_set, returned_set);
//
//        // Now we should be able to delete it all again
//        file::delete_in_dir(&sync_dir, "a.txt").unwrap();
//        file::delete_in_dir(&sync_dir, "b.txt").unwrap();
//        file::delete_in_dir(&sync_dir, "c.txt").unwrap();
//        client.sync_dir(&sync_dir).unwrap();
//
//        // And they should be gone when we list
//        let list_reply = client.get_server_list().unwrap();
//        assert_eq!(0, list_reply.elements().len());


    });
}

