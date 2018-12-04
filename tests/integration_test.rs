extern crate actix;
extern crate futures;
extern crate reqwest;
extern crate rpki;
extern crate rpubd;
extern crate serde_json;
extern crate tokio;
extern crate bytes;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str;
use std::{thread, time};
use actix::System;
use rpki::oob::exchange::PublisherRequest;
use rpki::oob::exchange::RepositoryResponse;
use rpubd::test;
use rpubd::pubc::client::PubClient;
use rpubd::pubd::config::Config;
use rpubd::provisioning::publisher::Publisher;
use rpubd::pubd::http::PubServerApp;

fn save_pr(base_dir: &PathBuf, file_name: &str, pr: &PublisherRequest) {
    let mut full_name = base_dir.clone();
    full_name.push(PathBuf::from
        (file_name));
    let mut f = File::create(full_name).unwrap();
    let xml = pr.encode_vec();
    f.write(xml.as_ref()).unwrap();
}

#[test]
fn client_publish_at_server() {
    test::test_with_tmp_dir(|d| {

        // Set up a client
        let client_dir = test::create_sub_dir(&d);
        let mut client = PubClient::new(&client_dir).unwrap();
        client.init("alice".to_string()).unwrap();
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

        // Should see one configured publisher
        let mut res = reqwest::get("http://localhost:3000/publishers").unwrap();
        let pl: Vec<Publisher> = serde_json::from_str(&res.text().unwrap()).unwrap();
        assert_eq!(1, pl.len());

        // Should get repository response for alice
        let mut res = reqwest::get("http://localhost:3000/publishers/alice").unwrap();
        let repo_res = RepositoryResponse::decode(
            res.text().unwrap().as_bytes()
        ).unwrap();
        client.process_repo_response(repo_res).unwrap();

        // List files at server
        let list = client.get_server_list().unwrap();
        assert_eq!(0, list.elements().len());
    });
}

