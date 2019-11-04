extern crate krill;
extern crate rpki;

use std::path::PathBuf;
use std::str::FromStr;

use rpki::crypto::{PublicKeyFormat, Signer};
use rpki::uri;

use krill::cli::options::{Command, PublishersCommand};
use krill::cli::report::ApiResponse;
use krill::commons::api::rrdp::CurrentObjects;
use krill::commons::api::{Handle, PublisherHandle};
use krill::commons::remote::builder::IdCertBuilder;
use krill::commons::util::softsigner::OpenSslSigner;
use krill::daemon::test::{
    krill_admin, krill_pubd_admin, start_krill_pubd_server, test_with_krill_server,
};
use krill::pubd::Publisher;

fn publisher(work_dir: &PathBuf, base_uri: &str) -> Publisher {
    let mut signer = OpenSslSigner::build(work_dir).unwrap();

    let key = signer.create_key(PublicKeyFormat::default()).unwrap();
    let id_cert = IdCertBuilder::new_ta_id_cert(&key, &signer).unwrap();

    let base_uri = uri::Rsync::from_str(base_uri).unwrap();

    Publisher::new(id_cert, base_uri, CurrentObjects::default())
}

fn add_publisher(publisher_handle: &PublisherHandle, publisher: &Publisher) {
    let command = Command::Publishers(PublishersCommand::AddPublisher(
        publisher_handle.clone(),
        publisher.id_cert().clone(),
    ));
    krill_pubd_admin(command);
}

fn remove_publisher(publisher: &PublisherHandle) {
    let command = Command::Publishers(PublishersCommand::RemovePublisher(publisher.clone()));
    krill_pubd_admin(command);
}

fn list_publishers() -> ApiResponse {
    let command = Command::Publishers(PublishersCommand::PublisherList);
    krill_pubd_admin(command)
}

fn details_publisher(publisher: &PublisherHandle) -> ApiResponse {
    let command = Command::Publishers(PublishersCommand::ShowPublisher(publisher.clone()));
    krill_pubd_admin(command)
}

/// This tests that you can run krill with an embedded TA and CA, and
/// have the CA publish at another krill instance which is is set up
/// as a publication server only (i.e. it just has no TA and CAs).
#[test]
fn remote_publication() {
    test_with_krill_server(|d| {
        start_krill_pubd_server();

        let alice_handle = Handle::from_str_unsafe("alice");
        let alice = publisher(&d, "rsync://localhost/repo/0/alice/");

        // Add client "alice"
        add_publisher(&alice_handle, &alice);

        // Find "alice" in list
        let res = list_publishers();
        match res {
            ApiResponse::PublisherList(list) => assert!(list
                .publishers()
                .iter()
                .find(|p| { p.id() == "alice" })
                .is_some()),
            _ => panic!("Expected publisher list"),
        }

        // Find details for alice
        let details_res = details_publisher(&alice_handle);
        match details_res {
            ApiResponse::PublisherDetails(details) => {
                assert_eq!(&alice_handle, details.handle());
            }
            _ => panic!("Expected details"),
        }

        // Remove alice
        remove_publisher(&alice_handle);

        // Expect that alice has been removed
        let res = list_publishers();
        match res {
            ApiResponse::PublisherList(list) => assert!(list
                .publishers()
                .iter()
                .find(|p| { p.id() == "alice" })
                .is_none()),
            _ => panic!("Expected publisher list"),
        }
    });
}
