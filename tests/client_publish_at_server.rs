extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate krill;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::collections::HashSet;
use std::{thread, time};
use actix::System;
use krill::client::pubc::PubClient;
use krill::client::data::ReportFormat;
use krill::client::options::Command;
use krill::client::options::Options;
use krill::client::options::PublishersCommand;
use krill::client::krillc::KrillClient;
use krill::daemon::config::Config;
use krill::daemon::http::server::PubServerApp;
use krill::util::file::{self, CurrentFile};
use krill::util::test;
use krill::remote::rfc8183::RepositoryResponse;

#[test]
fn client_publish_at_server() {
    test::test_with_tmp_dir(|d| {

        // Set up a client
        let client_dir = test::create_sub_dir(&d);
        let mut client = PubClient::new(&client_dir).unwrap();
        client.init("alice").unwrap();
        let pr = client.publisher_request().unwrap();
        test::save_pr(&d, "alice.xml", &pr);

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
            let mut alice_path = d.clone();
            alice_path.push("alice.xml");
            let krillc_opts = Options::new(
                test::http_uri("http://localhost:3000/"),
                "secret",
                ReportFormat::Default,
                Command::Publishers(PublishersCommand::Add(
                    alice_path,
                    None
                ))
            );
            let res = KrillClient::process(krillc_opts);
            assert!(res.is_ok())
        }

        // Should get repository response for alice
        let mut res = reqwest::Client::new()
            .get("http://localhost:3000/api/v1/publishers/alice/response.xml")
            .header("Authorization", "Bearer secret")
            .send()
            .unwrap();

        let repo_res = RepositoryResponse::decode(
            res.text().unwrap().as_bytes()
        ).unwrap();

        repo_res.validate().unwrap();
        client.process_repo_response(repo_res).unwrap();

        // List files at server
        let list = client.get_server_list().unwrap();
        assert_eq!(0, list.elements().len());

        // now let's sync something real
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

        client.sync_dir(&sync_dir).unwrap();

        // We should now see these files when we list
        let list_reply = client.get_server_list().unwrap();
        let returned_elements = list_reply.elements().clone();
        let returned_set = returned_elements.into_iter()
            .collect::<HashSet<_>>();

        let expected_elements = vec![
            file_a.to_list_element(),
            file_b.to_list_element(),
            file_c.to_list_element()
        ];
        let expected_set: HashSet<_> = expected_elements.into_iter()
            .collect();
        assert_eq!(expected_set, returned_set);

        // Now we should be able to delete it all again
        file::delete_in_dir(&sync_dir, "a.txt").unwrap();
        file::delete_in_dir(&sync_dir, "b.txt").unwrap();
        file::delete_in_dir(&sync_dir, "c.txt").unwrap();
        client.sync_dir(&sync_dir).unwrap();

        // And they should be gone when we list
        let list_reply = client.get_server_list().unwrap();
        assert_eq!(0, list_reply.elements().len());


    });
}

