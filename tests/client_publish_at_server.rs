extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate krill;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str;
use std::{thread, time};
use actix::System;
use bytes::Bytes;
use krill::daemon::config::Config;
use krill::daemon::http::server::PubServerApp;
use krill::remote::oob::{PublisherRequest, RepositoryResponse};
use krill::file;
use krill::file::CurrentFile;
use krill::client::pubc::PubClient;
use krill::test;

fn save_pr(base_dir: &PathBuf, file_name: &str, pr: &PublisherRequest) {
    let mut full_name = base_dir.clone();
    full_name.push(PathBuf::from
        (file_name));
    let mut f = File::create(full_name).unwrap();
    let xml = pr.encode_vec();
    f.write(xml.as_ref()).unwrap();
}

fn bytes(s: &str) -> Bytes {
    Bytes::from(s)
}

#[test]
fn client_publish_at_server() {
    test::test_with_tmp_dir(|d| {

        // Set up a client
        let client_dir = test::create_sub_dir(&d);
        let mut client = PubClient::new(&client_dir).unwrap();
        client.init("alice").unwrap();
        let pr = client.publisher_request().unwrap();

        // Set up a test PubServer Config with a client in it.
        let server_conf = {
            // Use a data dir for the storage
            let data_dir = test::create_sub_dir(&d);
            let xml_dir = test::create_sub_dir(&d);
            // Add the client's PublisherRequest to the server dir.
            save_pr(&xml_dir, "alice.xml", &pr);
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
            bytes("a")
        );
        let file_b = CurrentFile::new(
            test::rsync_uri("rsync://127.0.0.1/repo/alice/b.txt"),
            bytes("b")
        );
        let file_c = CurrentFile::new(
            test::rsync_uri("rsync://127.0.0.1/repo/alice/c.txt"),
            bytes("c")
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

