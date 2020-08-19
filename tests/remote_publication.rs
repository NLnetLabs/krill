extern crate krill;
extern crate pretty;
extern crate rpki;

use std::fs;
use std::str::FromStr;
use std::time::Duration;

use tokio::time::delay_for;

use krill::cli::options::{CaCommand, Command, PublishersCommand};
use krill::cli::report::ApiResponse;
use krill::commons::api::{
    Handle, ParentCaReq, PublisherDetails, PublisherHandle, RepoStatus, RepositoryUpdate, ResourceSet, RoaDefinition,
    RoaDefinitionUpdates,
};
use krill::commons::remote::rfc8183;
use krill::daemon::ca::ta_handle;
use krill::test::{
    add_child_to_ta_rfc6492, add_parent_to_ca, ca_gets_resources, ca_route_authorizations_update, child_request,
    init_child, krill_admin, start_krill,
};

async fn repository_response(publisher: &PublisherHandle) -> rfc8183::RepositoryResponse {
    let command = Command::Publishers(PublishersCommand::RepositoryResponse(publisher.clone()));
    match krill_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

async fn add_publisher(req: rfc8183::PublisherRequest) {
    let command = Command::Publishers(PublishersCommand::AddPublisher(req));
    krill_admin(command).await;
}

async fn details_publisher(publisher: &PublisherHandle) -> PublisherDetails {
    let command = Command::Publishers(PublishersCommand::ShowPublisher(publisher.clone()));
    match krill_admin(command).await {
        ApiResponse::PublisherDetails(details) => details,
        _ => panic!("Expected publisher details"),
    }
}

async fn repo_status(ca: &Handle) -> RepoStatus {
    let command = Command::CertAuth(CaCommand::RepoStatus(ca.clone()));
    match krill_admin(command).await {
        ApiResponse::RepoStatus(state) => state,
        _ => panic!("Expected repo state"),
    }
}

async fn repo_update(ca: &Handle, update: RepositoryUpdate) {
    let command = Command::CertAuth(CaCommand::RepoUpdate(ca.clone(), update));
    krill_admin(command).await;
}

async fn publisher_request(ca: &Handle) -> rfc8183::PublisherRequest {
    let command = Command::CertAuth(CaCommand::RepoPublisherRequest(ca.clone()));
    match krill_admin(command).await {
        ApiResponse::Rfc8183PublisherRequest(req) => req,
        _ => panic!("Expected publisher request"),
    }
}

async fn repo_ready(ca: &Handle) -> bool {
    for _ in 0..300 {
        // let repo_state = repo_state(ca).await;
        // if repo_state.as_list().elements().len() == number {
        let repo_state = repo_status(ca).await;
        if let Some(exchange) = repo_state.last_exchange() {
            if exchange.was_success() {
                return true;
            }
        }
        delay_for(Duration::from_millis(100)).await
    }
    false
}

async fn will_publish(ca: &Handle, number: usize) -> bool {
    for _ in 0..300 {
        // let repo_state = repo_state(ca).await;
        // if repo_state.as_list().elements().len() == number {
        let repo_state = repo_status(ca).await;
        if repo_state.published().len() == number {
            return true;
        }
        delay_for(Duration::from_millis(100)).await
    }
    false
}

/// This tests that you can run krill with an embedded TA and CA, and
/// have the CA publish at another krill instance which is is set up
/// as a publication server only (i.e. it just has no TA and CAs).
#[tokio::test]
async fn remote_publication() {
    let dir = start_krill().await;
    let ta_handle = ta_handle();

    let child = Handle::from_str("child").unwrap();
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

    // Set up child as a child of the TA
    init_child(&child).await;

    // Let child use the remote protocol
    let publisher_request = publisher_request(&child).await;
    add_publisher(publisher_request).await;

    // Get a Repository Response for the child CA
    let response = repository_response(&child).await;

    // Update the repo for the child
    let update = RepositoryUpdate::Rfc8181(response);
    repo_update(&child, update).await;
    assert!(repo_ready(&child).await);

    let parent = {
        let req = child_request(&child).await;
        let contact = add_child_to_ta_rfc6492(&child, req, child_resources.clone()).await;
        ParentCaReq::new(ta_handle, contact)
    };
    add_parent_to_ca(&child, parent).await;
    assert!(ca_gets_resources(&child, &child_resources).await);

    // Add some roas to have more to migrate when moving publication servers
    let route_1 = RoaDefinition::from_str("10.0.0.0/24 => 64496").unwrap();
    let route_2 = RoaDefinition::from_str("10.0.2.0/23 => 64496").unwrap();
    let mut updates = RoaDefinitionUpdates::empty();
    updates.add(route_1);
    updates.add(route_2);
    ca_route_authorizations_update(&child, updates).await;

    // Child should now publish
    assert!(will_publish(&child, 4).await);

    let details = details_publisher(&child).await;
    assert_eq!(4, details.current_files().len());

    let _ = fs::remove_dir_all(&dir);
}
