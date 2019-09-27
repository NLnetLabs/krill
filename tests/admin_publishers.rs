extern crate krill;

use krill::cli::options::{AddPublisher, Command, PublishersCommand};
use krill::cli::report::ApiResponse;
use krill::commons::api::{Handle, Token};
use krill::commons::util::test;
use krill::daemon::test::{krill_admin, test_with_krill_server};

fn add_publisher(handle: &Handle, base_uri: &str, token: &str) {
    let command = Command::Publishers(PublishersCommand::Add(AddPublisher {
        handle: handle.clone(),
        base_uri: test::rsync(base_uri),
        token: Token::from(token),
    }));
    krill_admin(command);
}

fn deactivate_publisher(handle: &Handle) {
    let command = Command::Publishers(PublishersCommand::Deactivate(handle.clone()));

    krill_admin(command);
}

fn list_publishers() -> ApiResponse {
    let command = Command::Publishers(PublishersCommand::List);

    krill_admin(command)
}

fn details_publisher(handle: &Handle) -> ApiResponse {
    let command = Command::Publishers(PublishersCommand::Details(handle.clone()));

    krill_admin(command)
}

#[test]
fn admin_publishers() {
    test_with_krill_server(|_d| {
        let handle = Handle::from_str_unsafe("alice");
        let token = "secret";
        let base_rsync_uri_alice = "rsync://localhost/repo/alice/";

        // Add client "alice"
        add_publisher(&handle, base_rsync_uri_alice, token);

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
        let details_res = details_publisher(&handle);
        match details_res {
            ApiResponse::PublisherDetails(details) => {
                assert_eq!("alice", details.handle());
                assert_eq!(false, details.deactivated());
            }
            _ => panic!("Expected details"),
        }

        // Remove alice
        deactivate_publisher(&handle);

        // Expect that alice still exists, but is now deactivated.
        let details_res = details_publisher(&handle);
        match details_res {
            ApiResponse::PublisherDetails(details) => {
                assert_eq!("alice", details.handle());
                assert_eq!(true, details.deactivated());
            }
            _ => panic!("Expected details"),
        }
    });
}
