extern crate rpubd;
extern crate rpki;
extern crate hyper;

use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use rpki::oob::exchange::PublisherRequest;
use rpubd::test;
use rpubd::server;
use std::time::Duration;
use hyper::server::conn::Serve;

fn save_pr(base_dir: &str, file_name: &str, pr: &PublisherRequest) {
    let full_name = PathBuf::from(format!("{}/{}", base_dir, file_name));
    let mut f = File::create(full_name).unwrap();
    let xml = pr.encode_vec();
    f.write(xml.as_ref()).unwrap();
}

#[test]
fn testing() {
    test::test_with_tmp_dir(|d| {

        // Use a data dir for the storage
        let data_dir = test::create_sub_dir(&d);

        // Start with an xml dir with two PRs for alice and bob
        let xml_dir = test::create_sub_dir(&d);
        let pr_alice = test::new_publisher_request("alice");
        let pr_bob   = test::new_publisher_request("bob");
        save_pr(&xml_dir, "alice.xml", &pr_alice);
        save_pr(&xml_dir, "bob.xml", &pr_bob);

        let addr = SocketAddr::from_str("127.0.0.1:3000").unwrap();

        unimplemented!()


    });
}

