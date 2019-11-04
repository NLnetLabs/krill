extern crate krill;
extern crate pretty;
extern crate rpki;

use std::path::PathBuf;
use std::str::FromStr;

use rpki::crypto::{PublicKeyFormat, Signer};
use rpki::uri;

use krill::cli::options::{CaCommand, Command, PublishersCommand};
use krill::cli::report::ApiResponse;
use krill::commons::api::rrdp::CurrentObjects;
use krill::commons::api::{CaRepoDetails, Handle, ParentCaReq, PublisherHandle, ResourceSet};
use krill::commons::remote::builder::IdCertBuilder;
use krill::commons::util::softsigner::OpenSslSigner;
use krill::daemon::ca::ta_handle;
use krill::daemon::test::{
    add_child_to_ta_embedded, add_parent_to_ca, init_child, krill_admin, krill_pubd_admin,
    start_krill_pubd_server, test_with_krill_server, wait_for_current_resources,
};
use krill::pubd::Publisher;
use pretty::Doc::Append;

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

fn repo_details(ca: &Handle) -> CaRepoDetails {
    let command = Command::CertAuth(CaCommand::RepoDetails(ca.clone()));
    match krill_admin(command) {
        ApiResponse::RepoDetails(details) => details,
        _ => panic!("Expected repo details"),
    }
}

/// This tests that you can run krill with an embedded TA and CA, and
/// have the CA publish at another krill instance which is is set up
/// as a publication server only (i.e. it just has no TA and CAs).
#[test]
fn remote_publication() {
    test_with_krill_server(|d| {
        start_krill_pubd_server();

        let ta_handle = ta_handle();

        let child = Handle::from_str_unsafe("child");

        // Set up child as a child of the TA
        {
            init_child(&child);
            let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

            let parent = {
                let parent_contact = add_child_to_ta_embedded(&child, child_resources.clone());
                ParentCaReq::new(ta_handle.clone(), parent_contact)
            };

            add_parent_to_ca(&child, parent);
            wait_for_current_resources(&child, &child_resources);
        }

        // Child should now publish using the embedded repo
        let child_repo_details = repo_details(&child);
        assert!(child_repo_details.contact().is_embedded());
        let list = child_repo_details.state().as_list();
        assert_eq!(2, list.elements().len());

        //        let alice = publisher(&d, "rsync://localhost/repo/0/child/");
        //
        //        // Add client "alice"
        //        add_publisher(&alice_handle, &alice);
        //
        //        // Find "alice" in list
        //        let res = list_publishers();
        //        match res {
        //            ApiResponse::PublisherList(list) => assert!(list
        //                .publishers()
        //                .iter()
        //                .find(|p| { p.id() == "alice" })
        //                .is_some()),
        //            _ => panic!("Expected publisher list"),
        //        }
        //
        //        // Find details for alice
        //        let details_res = details_publisher(&alice_handle);
        //        match details_res {
        //            ApiResponse::PublisherDetails(details) => {
        //                assert_eq!(&alice_handle, details.handle());
        //            }
        //            _ => panic!("Expected details"),
        //        }
        //
        //        // Remove alice
        //        remove_publisher(&alice_handle);
        //
        //        // Expect that alice has been removed
        //        let res = list_publishers();
        //        match res {
        //            ApiResponse::PublisherList(list) => assert!(list
        //                .publishers()
        //                .iter()
        //                .find(|p| { p.id() == "alice" })
        //                .is_none()),
        //            _ => panic!("Expected publisher list"),
        //        }
    });
}
