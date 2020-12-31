//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;
use std::time::Duration;

use tokio::time::delay_for;

use bytes::Bytes;

use rpki::uri::Rsync;

use krill::cli::options::{BulkCaCommand, CaCommand, Command, PublishersCommand};
use krill::cli::report::ApiResponse;
use krill::commons::api::{
    Handle, ObjectName, ParentCaReq, ParentHandle, PublisherHandle, RepoStatus, RepositoryUpdate,
    ResourceClassKeysInfo, ResourceClassName, ResourceSet, RoaDefinition, RoaDefinitionUpdates, RtaList,
};
use krill::commons::remote::rfc8183;
use krill::daemon::ca::ta_handle;
use krill::test::*;

fn handle_for(s: &str) -> Handle {
    Handle::from_str(s).unwrap()
}

fn resources(v4: &str) -> ResourceSet {
    ResourceSet::from_strs("", v4, "").unwrap()
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

async fn repository_response(publisher: &PublisherHandle) -> rfc8183::RepositoryResponse {
    let command = PublishersCommand::RepositoryResponse(publisher.clone());
    match krill_pubd_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

async fn add_publisher(req: rfc8183::PublisherRequest) {
    let command = PublishersCommand::AddPublisher(req);
    krill_pubd_admin(command).await;
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

async fn set_up_ca_with_repo(ca: &Handle) {
    init_ca(ca).await;

    // Add the CA as a publisher
    let publisher_request = publisher_request(ca).await;
    add_publisher(publisher_request).await;

    // Get a Repository Response for the CA
    let response = repository_response(ca).await;

    // Update the repo for the child
    let update = RepositoryUpdate::Rfc8181(response);
    repo_update(ca, update).await;
    assert!(repo_ready(ca).await);
}

async fn expected_mft_and_crl(ca: &Handle, rcn: &ResourceClassName) -> Vec<String> {
    let rc_key = ca_key_for_rcn(ca, rcn).await;
    let mft_file = rc_key.incoming_cert().mft_name().to_string();
    let crl_file = rc_key.incoming_cert().crl_name().to_string();
    vec![mft_file, crl_file]
}

async fn expected_issued_cer(ca: &Handle, rcn: &ResourceClassName) -> String {
    let rc_key = ca_key_for_rcn(ca, rcn).await;
    ObjectName::from(rc_key.incoming_cert().cert()).to_string()
}

async fn will_publish(publisher: &PublisherHandle, files: &[String]) -> bool {
    let objects: Vec<_> = files.iter().map(|s| s.as_str()).collect();
    for _ in 0..300 {
        let details = publisher_details(publisher).await;

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

        delay_for(Duration::from_millis(100)).await
    }

    let details = publisher_details(publisher).await;

    eprintln!("Did not find match for: {}", publisher);
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
    let child_request = child_request(ca).await;
    let parent = {
        let contact = add_child_rfc6492(parent, ca, child_request, resources.clone()).await;
        ParentCaReq::new(parent.clone(), contact)
    };
    add_parent_to_ca(ca, parent).await;
    assert!(ca_contains_resources(ca, resources).await);
}

async fn ca_roll_init(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollInit(handle.clone()))).await;
}

async fn ca_roll_activate(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollActivate(handle.clone()))).await;
}

async fn state_becomes_new_key(handle: &Handle) -> bool {
    for _ in 0..30_u8 {
        let ca = ca_details(handle).await;
        if let Some(rc) = ca.resource_classes().get(&ResourceClassName::default()) {
            if let ResourceClassKeysInfo::RollNew(_) = rc.keys() {
                return true;
            }
        }
        delay_for(Duration::from_secs(1)).await
    }
    false
}

async fn state_becomes_active(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;
        if let Some(rc) = ca.resource_classes().get(&ResourceClassName::default()) {
            if let ResourceClassKeysInfo::Active(_) = rc.keys() {
                return true;
            }
        }
        delay_for(Duration::from_millis(100)).await
    }
    false
}

async fn refresh_all() {
    krill_admin(Command::Bulk(BulkCaCommand::Refresh)).await;
}

#[tokio::test]
async fn functional() {
    // We will use a fairly complicated CA structure so that we can
    // also test corner cases where a CA has multiple children (here: TA),
    // or multiple parents (here CA3), or a single parent with multiple
    // resource classes (here CA4):
    //
    //                     TA
    //                    /
    //                 testbed
    //                 /    \
    //               CA1    CA2
    //                 \   /
    //                  CA3 (two resource classes)
    //                  | |
    //                  CA4 (two resource classes)
    //

    // We will verify that:
    //  * CAs can be set up as parent child using RFC6492
    //  * CAs can publish using RFC8181
    //  * CAs can create ROAs
    //  * CA resources can change:
    //     - ROAs are cleaned up/created accordingly
    //  * CAs can perform key rolls:
    //     - Content (ROAs) should be unaffected
    //
    //  * RTAs can be created and co-signed under multiple CAs

    let d = start_krill(None).await;

    let ta = ta_handle();
    let testbed = handle_for("testbed");

    let ca1 = handle_for("CA1");
    let ca1_res = resources("10.0.0.0/16");
    let ca1_res_reduced = resources("10.0.0.0/24");

    let ca2 = handle_for("CA2");
    let ca2_res = resources("10.1.0.0/16");

    let ca3 = handle_for("CA3");
    let ca3_res_under_ca_1 = resources("10.0.0.0/16");
    let ca3_res_under_ca_2 = resources("10.1.0.0/24");
    let ca3_res_combined = resources("10.0.0.0/16, 10.1.0.0/24");
    let ca3_res_reduced = resources("10.0.0.0/24,10.1.0.0/24");

    let ca4 = handle_for("CA4");
    let ca4_res_under_ca_3 = resources("10.0.0.0-10.1.0.255");
    let ca4_res_reduced = resources("10.0.0.0/24,10.1.0.0/24");

    let rcn_0 = ResourceClassName::from(0);
    let rcn_1 = ResourceClassName::from(1);

    // Wait for the "testbed" CA to get its certificate, this means that all CAs
    // which are set up as part of krill_start under testbed config have been
    // set up.
    assert!(ca_contains_resources(&testbed, &ResourceSet::all_resources()).await);

    // Verify that the TA published expected objects
    {
        let mut expected_files = expected_mft_and_crl(&ta, &rcn_0).await;
        expected_files.push(expected_issued_cer(&testbed, &rcn_0).await);
        assert!(will_publish(&ta, &expected_files).await);
    }

    // Set up CA1 under testbed
    {
        set_up_ca_with_repo(&ca1).await;
        set_up_ca_under_parent_with_resources(&ca1, &testbed, &ca1_res).await;
    }

    // Set up CA2 under testbed
    {
        set_up_ca_with_repo(&ca2).await;
        set_up_ca_under_parent_with_resources(&ca2, &testbed, &ca2_res).await;
    }

    // Verify that the testbed published the expected objects
    {
        let mut expected_files = expected_mft_and_crl(&testbed, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca1, &rcn_0).await);
        expected_files.push(expected_issued_cer(&ca2, &rcn_0).await);
        assert!(will_publish(&testbed, &expected_files).await);
    }

    // Set up CA3 under CA1 first
    {
        set_up_ca_with_repo(&ca3).await;
        set_up_ca_under_parent_with_resources(&ca3, &ca1, &ca3_res_under_ca_1).await;
    }

    // Expect that CA1 publishes the certificate for CA3
    {
        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca3, &rcn_0).await);
        assert!(will_publish(&ca1, &expected_files).await);
    }

    // Set up CA3 under CA2 second (will get another resource class)
    {
        set_up_ca_under_parent_with_resources(&ca3, &ca2, &ca3_res_under_ca_2).await;
    }

    // Expect that CA2 publishes the certificate for CA3
    {
        let mut expected_files = expected_mft_and_crl(&ca2, &rcn_0).await;
        // CA3 will have the certificate from CA2 under its resource class '1' rather than '0'
        expected_files.push(expected_issued_cer(&ca3, &rcn_1).await);
        assert!(will_publish(&ca2, &expected_files).await);
    }

    // Set up CA4 under CA3 with resources from both parent classes
    {
        set_up_ca_with_repo(&ca4).await;
        set_up_ca_under_parent_with_resources(&ca4, &ca3, &ca4_res_under_ca_3).await;
    }

    // Expect that CA3 publishes two certificates for two resource classes
    {
        let mut expected_files = expected_mft_and_crl(&ca3, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca4, &rcn_0).await);
        expected_files.append(&mut expected_mft_and_crl(&ca3, &rcn_1).await);
        expected_files.push(expected_issued_cer(&ca4, &rcn_1).await);
        assert!(will_publish(&ca3, &expected_files).await);
    }

    // Expect that CA4 publishes two resource classes, with only crls and mfts
    {
        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);
        assert!(will_publish(&ca4, &expected_files).await);
    }

    //------------------------------------------------------------------------------------------
    // Test a key roll
    //------------------------------------------------------------------------------------------
    {
        ca_roll_init(&ca1).await;
        assert!(state_becomes_new_key(&ca1).await);
        ca_roll_activate(&ca1).await;
        assert!(state_becomes_active(&ca1).await);
    }

    //------------------------------------------------------------------------------------------
    // Test managing ROAs
    //------------------------------------------------------------------------------------------
    let route_rc0_1 = RoaDefinition::from_str("10.0.0.0/16-16 => 64496").unwrap();
    let route_rc0_2 = RoaDefinition::from_str("10.0.0.0/16-16 => 64497").unwrap();
    let route_rc0_3 = RoaDefinition::from_str("10.0.0.0/24-24 => 64496").unwrap();
    let route_rc0_4 = RoaDefinition::from_str("10.0.0.0/24-24 => 64497").unwrap();
    let route_rc1_1 = RoaDefinition::from_str("10.1.0.0/24-24 => 64496").unwrap();

    // short hand to expect ROAs under CA4
    async fn expect_roas_for_ca4(roas: &[RoaDefinition]) {
        let ca4 = handle_for("CA4");
        let rcn_0 = ResourceClassName::from(0);
        let rcn_1 = ResourceClassName::from(1);

        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);
        for roa in roas {
            expected_files.push(ObjectName::from(roa).to_string());
        }
        assert!(will_publish(&ca4, &expected_files).await);
    }

    // Add ROAs, expect that they will be published
    {
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_rc0_1);
        updates.add(route_rc0_2);
        updates.add(route_rc1_1);
        ca_route_authorizations_update(&ca4, updates).await;
        expect_roas_for_ca4(&[route_rc0_1, route_rc0_2, route_rc1_1]).await;
    }

    // Add ROAs beyond the aggregation threshold for RC0, we now expect ROAs under
    // RC0 to be aggregated by ASN
    {
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_rc0_3);
        updates.add(route_rc0_4);
        ca_route_authorizations_update(&ca4, updates).await;

        // expect MFT and CRL for RC0 and RC1
        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);

        // expect aggregated ROAs (under RC0)
        expected_files.push("AS64496.roa".to_string());
        expected_files.push("AS64497.roa".to_string());

        // and the roa for rc1
        expected_files.push(ObjectName::from(&route_rc1_1).to_string());

        assert!(will_publish(&ca4, &expected_files).await);
    }

    // Remove ROAs below the deaggregation threshold and we get
    // individual files again
    {
        let mut updates = RoaDefinitionUpdates::empty();
        updates.remove(route_rc0_2);
        updates.remove(route_rc0_3);
        updates.remove(route_rc0_4);
        ca_route_authorizations_update(&ca4, updates).await;

        expect_roas_for_ca4(&[route_rc0_1, route_rc1_1]).await;
    }

    //------------------------------------------------------------------------------------------
    // Test shrinking / growing resources
    //------------------------------------------------------------------------------------------

    // When resources are removed higher up in the tree, then resources to child
    // CAs should also be reduced. When resources for ROAs are lost, the ROAs should
    // be removed, but the authorization (config) is kept.
    {
        update_child(&testbed, &ca1, &ca1_res_reduced).await;
        ca_equals_resources(&ca1, &ca1_res_reduced).await;
        ca_equals_resources(&ca3, &ca3_res_reduced).await;
        ca_equals_resources(&ca4, &ca4_res_reduced).await;
        refresh_all().await; // if we skip this, then CA4 will not find out that it's resources were reduced

        expect_roas_for_ca4(&[route_rc1_1]).await;
    }

    // When resources are added back higher in the tree, then they will also
    // be added to the delegated children again. When resources for existing
    // authorizations are re-gained, ROAs will be created again.
    {
        update_child(&testbed, &ca1, &ca1_res).await;
        ca_equals_resources(&ca1, &ca1_res).await;
        ca_equals_resources(&ca3, &ca3_res_combined).await;
        ca_equals_resources(&ca4, &ca4_res_under_ca_3).await;
        refresh_all().await;

        // Expect that the ROA is re-added now that resources are back.
        expect_roas_for_ca4(&[route_rc0_1, route_rc1_1]).await;
    }

    //---------------------------------------------------------------------------------------
    // Single Signed RTA
    //---------------------------------------------------------------------------------------
    let rta_content = include_bytes!("../test-resources/test.tal");
    let rta_content = Bytes::copy_from_slice(rta_content);

    {
        let rta_single = "rta_single".to_string();

        rta_sign_sign(
            ca1.clone(),
            rta_single.clone(),
            ca1_res.clone(),
            vec![],
            rta_content.clone(),
        )
        .await;

        let rta_list = rta_list(ca1.clone()).await;
        assert_eq!(rta_list, RtaList::new(vec![rta_single.clone()]));

        let _single_rta = rta_show(ca1.clone(), rta_single).await;
    }

    //---------------------------------------------------------------------------------------
    // Multi Signed RTA
    //---------------------------------------------------------------------------------------

    {
        // combined resources of CA1 and CA2
        let multi_resources = resources("10.0.0.0/16, 10.1.0.0/16");
        let multi_rta_name = "multi_rta".to_string();

        // CA1 prepares, so that CA2 can include its key on the RTA it signs
        let ca1_prep = rta_multi_prep(ca1.clone(), multi_rta_name.clone(), multi_resources.clone()).await;

        // CA2 signs and includes CA1's key
        rta_sign_sign(
            ca2.clone(),
            multi_rta_name.clone(),
            multi_resources.clone(),
            ca1_prep.into(),
            rta_content,
        )
        .await;

        // CA1 co-signs the RTA containing CA1's signature (only)
        let multi_rta_ca2 = rta_show(ca2, multi_rta_name.clone()).await;
        rta_multi_cosign(ca1.clone(), multi_rta_name.clone(), multi_rta_ca2).await;

        let _multi_signed = rta_show(ca1, multi_rta_name).await;
    }

    let _ = fs::remove_dir_all(d);
}
