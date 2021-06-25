//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;
use std::time::Duration;

use tokio::time::sleep;

use rpki::uri::Rsync;

use krill::commons::api::{
    Handle, ObjectName, ParentCaReq, ParentHandle, PublisherHandle, ResourceClassKeysInfo, ResourceClassName,
    ResourceSet, RoaDefinitionUpdates,
};
use krill::commons::remote::rfc8183;
use krill::daemon::ca::ta_handle;
use krill::test::*;
use krill::{
    cli::options::{CaCommand, Command, PubServerCommand},
    commons::api::RepositoryContact,
};
use krill::{cli::report::ApiResponse, commons::api::RoaDefinition};

fn handle_for(s: &str) -> Handle {
    Handle::from_str(s).unwrap()
}

fn resources(v4: &str) -> ResourceSet {
    ResourceSet::from_strs("", v4, "").unwrap()
}

async fn repo_update(ca: &Handle, contact: RepositoryContact) {
    let command = Command::CertAuth(CaCommand::RepoUpdate(ca.clone(), contact));
    krill_admin(command).await;
}

async fn embedded_repository_response(publisher: &PublisherHandle) -> rfc8183::RepositoryResponse {
    let command = PubServerCommand::RepositoryResponse(publisher.clone());
    match krill_embedded_pubd_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

async fn dedicated_repository_response(publisher: &PublisherHandle) -> rfc8183::RepositoryResponse {
    let command = PubServerCommand::RepositoryResponse(publisher.clone());
    match krill_dedicated_pubd_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

async fn embedded_repo_add_publisher(req: rfc8183::PublisherRequest) {
    let command = PubServerCommand::AddPublisher(req);
    krill_embedded_pubd_admin(command).await;
}

async fn dedicated_repo_add_publisher(req: rfc8183::PublisherRequest) {
    let command = PubServerCommand::AddPublisher(req);
    krill_dedicated_pubd_admin(command).await;
}

async fn set_up_ca_with_repo(ca: &Handle) {
    init_ca(ca).await;

    // Add the CA as a publisher
    let publisher_request = publisher_request(ca).await;
    embedded_repo_add_publisher(publisher_request).await;

    // Get a Repository Response for the CA
    let response = embedded_repository_response(ca).await;

    // Update the repo for the child
    let contact = RepositoryContact::new(response);
    repo_update(ca, contact).await;
}

async fn expected_mft_and_crl(ca: &Handle, rcn: &ResourceClassName) -> Vec<String> {
    let rc_key = ca_key_for_rcn(ca, rcn).await;
    let mft_file = rc_key.incoming_cert().mft_name().to_string();
    let crl_file = rc_key.incoming_cert().crl_name().to_string();
    vec![mft_file, crl_file]
}

async fn expected_new_key_mft_and_crl(ca: &Handle, rcn: &ResourceClassName) -> Vec<String> {
    let rc_key = ca_new_key_for_rcn(ca, rcn).await;
    let mft_file = rc_key.incoming_cert().mft_name().to_string();
    let crl_file = rc_key.incoming_cert().crl_name().to_string();
    vec![mft_file, crl_file]
}

async fn expected_issued_cer(ca: &Handle, rcn: &ResourceClassName) -> String {
    let rc_key = ca_key_for_rcn(ca, rcn).await;
    ObjectName::from(rc_key.incoming_cert().cert()).to_string()
}

async fn will_publish_embedded(test_msg: &str, publisher: &PublisherHandle, files: &[String]) -> bool {
    will_publish(test_msg, publisher, files, PubServer::Embedded).await
}

async fn will_publish_dedicated(test_msg: &str, publisher: &PublisherHandle, files: &[String]) -> bool {
    will_publish(test_msg, publisher, files, PubServer::Dedicated).await
}

enum PubServer {
    Embedded,
    Dedicated,
}

async fn will_publish(test_msg: &str, publisher: &PublisherHandle, files: &[String], server: PubServer) -> bool {
    let objects: Vec<_> = files.iter().map(|s| s.as_str()).collect();
    for _ in 0..6000 {
        let details = {
            match &server {
                PubServer::Dedicated => dedicated_repo_publisher_details(publisher).await,
                PubServer::Embedded => publisher_details(publisher).await,
            }
        };

        let current_files = details.current_files();

        if current_files.len() == objects.len() {
            let current_files: Vec<&Rsync> = current_files.iter().map(|p| p.uri()).collect();
            let mut all_matched = true;
            for o in &objects {
                if current_files.iter().find(|uri| uri.ends_with(o)).is_none() {
                    all_matched = false;
                }
            }
            if all_matched {
                return true;
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    let details = publisher_details(publisher).await;

    eprintln!(
        "Did not find match for test: {}, for publisher: {}",
        test_msg, publisher
    );
    eprintln!("Found:");
    for file in details.current_files() {
        eprintln!("  {}", file.uri());
    }
    eprintln!("Expected:");
    for file in objects {
        eprintln!("  {}", file);
    }

    false
}

async fn set_up_ca_under_parent_with_resources(ca: &Handle, parent: &ParentHandle, resources: &ResourceSet) {
    let child_request = request(ca).await;
    let parent = {
        let contact = add_child_rfc6492(parent, ca, child_request, resources.clone()).await;
        ParentCaReq::new(parent.clone(), contact)
    };
    add_parent_to_ca(ca, parent).await;
    assert!(ca_contains_resources(ca, resources).await);
}

async fn ca_roll_activate(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollActivate(handle.clone()))).await;
}

async fn state_becomes_new_key(handle: &Handle) -> bool {
    for _ in 0..30_u8 {
        let ca = ca_details(handle).await;

        // wait for ALL RCs to become state new key
        let rc_map = ca.resource_classes();

        let expected = rc_map.len();
        let mut found = 0;

        for rc in rc_map.values() {
            if let ResourceClassKeysInfo::RollNew(_) = rc.keys() {
                found += 1;
            }
        }

        if found == expected {
            return true;
        }

        sleep(Duration::from_secs(1)).await
    }
    false
}

async fn state_becomes_active(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;

        // wait for ALL RCs to become state active key
        let rc_map = ca.resource_classes();

        let expected = rc_map.len();
        let mut found = 0;

        for rc in rc_map.values() {
            if let ResourceClassKeysInfo::Active(_) = rc.keys() {
                found += 1;
            }
        }

        if found == expected {
            return true;
        }

        sleep(Duration::from_millis(100)).await
    }
    false
}

#[tokio::test]
#[ignore = "See issue 481"]
async fn migrate_repository() {
    init_logging();

    info("##################################################################");
    info("#                                                                #");
    info("#                --= Test Migrating a Repository  =--            #");
    info("#                                                                #");
    info("##################################################################");

    info("##################################################################");
    info("#                                                                #");
    info("#                      Start Krill                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    let krill_dir = start_krill_with_default_test_config(true).await;

    info("##################################################################");
    info("#                                                                #");
    info("#               Start Secondary Publication Server               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    let pubd_dir = start_krill_pubd().await;

    let ta = ta_handle();
    let testbed = handle_for("testbed");

    let ca1 = handle_for("CA1");
    let ca1_res = resources("10.0.0.0/16");
    let ca1_route_definition = RoaDefinition::from_str("10.0.0.0/16-16 => 65000").unwrap();

    let rcn_0 = ResourceClassName::from(0);

    info("##################################################################");
    info("#                                                                #");
    info("# Wait for the *testbed* CA to get its certificate, this means   #");
    info("# that all CAs which are set up as part of krill_start under the #");
    info("# testbed config have been set up.                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    assert!(ca_contains_resources(&testbed, &ResourceSet::all_resources()).await);

    // Verify that the TA published expected objects
    {
        let mut expected_files = expected_mft_and_crl(&ta, &rcn_0).await;
        expected_files.push(expected_issued_cer(&testbed, &rcn_0).await);
        assert!(
            will_publish_embedded(
                "TA should have manifest, crl and cert for testbed",
                &ta,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Set up CA1 under testbed                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca1).await;
        set_up_ca_under_parent_with_resources(&ca1, &testbed, &ca1_res).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Create a ROA for CA1                      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(ca1_route_definition);
        ca_route_authorizations_update(&ca1, updates).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#    Verify that the testbed published the expected objects      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&testbed, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca1, &rcn_0).await);
        assert!(
            will_publish_embedded(
                "testbed CA should have mft, crl and certs for CA1 and CA2",
                &testbed,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#       Expect that CA1 publishes in the embedded repo           #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(ObjectName::from(&ca1_route_definition).to_string());

        assert!(will_publish_embedded("CA1 should publish the certificate for CA3", &ca1, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Migrate a Repository for CA1 (using a keyroll)                 #");
        info("#                                                                #");
        info("# CA1 currently uses the embedded publication server. In order   #");
        info("# to migrate it, we will need to do the following:               #");
        info("#                                                                #");
        info("# - get the RFC 8183 publisher request from CA1                  #");
        info("# - add CA1 as a publisher under the dedicated (separate) pubd,  #");
        info("# - get the response                                             #");
        info("# - update the repo config for CA1 using the 8183 response       #");
        info("#    -- this should initiate a key roll                          #");
        info("#    -- the new key publishes in the new repo                    #");
        info("# - complete the key roll                                        #");
        info("#    -- the old key should be cleaned up,                        #");
        info("#    -- nothing published for CA1 in the embedded repo           #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        // Add CA1 to dedicated repo
        let publisher_request = publisher_request(&ca1).await;
        dedicated_repo_add_publisher(publisher_request).await;
        let response = dedicated_repository_response(&ca1).await;

        // Wait a tiny bit.. when we add a new repo we check that it's available or
        // it will be rejected.
        sleep(Duration::from_secs(1)).await;

        // Update CA1 to use dedicated repo
        let contact = RepositoryContact::new(response);
        repo_update(&ca1, contact).await;

        // This should result in a key roll and content published in both repos
        assert!(state_becomes_new_key(&ca1).await);

        // Expect that CA1 still publishes two current keys in the embedded repo
        {
            let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
            expected_files.push(ObjectName::from(&ca1_route_definition).to_string());

            assert!(
                will_publish_embedded(
                    "CA1 should publish the MFT and CRL for both current keys in the embedded repo",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }

        // Expect that CA1 publishes two new keys in the dedicated repo
        {
            let expected_files = expected_new_key_mft_and_crl(&ca1, &rcn_0).await;
            assert!(
                will_publish_dedicated(
                    "CA1 should publish the MFT and CRL for both new keys in the dedicated repo",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }

        // Complete the keyroll, this should remove the content in the embedded repo
        ca_roll_activate(&ca1).await;
        assert!(state_becomes_active(&ca1).await);

        // Expect that CA1 publishes two current keys in the dedicated repo
        {
            let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
            expected_files.push(ObjectName::from(&ca1_route_definition).to_string());

            assert!(
                will_publish_dedicated(
                    "CA1 should publish the MFT and CRL for both current keys in the dedicated repo",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }

        // Expect that CA1 publishes nothing in the embedded repo
        {
            assert!(
                will_publish_embedded("CA1 should no longer publish anything in the embedded repo", &ca1, &[]).await
            );
        }
    }

    let _ = fs::remove_dir_all(krill_dir);
    let _ = fs::remove_dir_all(pubd_dir);
}
