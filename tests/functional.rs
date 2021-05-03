//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;
use std::time::Duration;

use tokio::time::delay_for;

use bytes::Bytes;

use rpki::uri::Rsync;

use krill::cli::report::ApiResponse;
use krill::commons::api::{
    Handle, ObjectName, ParentCaReq, ParentHandle, PublisherHandle, ResourceClassKeysInfo, ResourceClassName,
    ResourceSet, RoaDefinition, RoaDefinitionUpdates, RtaList,
};
use krill::commons::remote::rfc8183;
use krill::daemon::ca::ta_handle;
use krill::test::*;
use krill::{
    cli::options::{BulkCaCommand, CaCommand, Command, PublishersCommand},
    commons::api::RepositoryContact,
};

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
    let command = PublishersCommand::RepositoryResponse(publisher.clone());
    match krill_embedded_pubd_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

async fn embedded_repo_add_publisher(req: rfc8183::PublisherRequest) {
    let command = PublishersCommand::AddPublisher(req);
    krill_embedded_pubd_admin(command).await;
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

async fn will_publish(test_msg: &str, publisher: &PublisherHandle, files: &[String]) -> bool {
    let objects: Vec<_> = files.iter().map(|s| s.as_str()).collect();
    // for _ in 0..6000 {
    for _ in 0..50 {
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

        delay_for(Duration::from_millis(100)).await;
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

async fn ca_roll_init(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollInit(handle.clone()))).await;
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

        delay_for(Duration::from_secs(1)).await
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

        delay_for(Duration::from_millis(100)).await
    }
    false
}

async fn refresh_all() {
    krill_admin(Command::Bulk(BulkCaCommand::Refresh)).await;
}

#[tokio::test]
async fn functional() {
    init_logging();

    info("##################################################################");
    info("#                                                                #");
    info("# --= The Big Functional parent/child/repo interaction Test =--  #");
    info("#                                                                #");
    info("# We will use a fairly complicated CA structure so that we can   #");
    info("# also test corner cases where a CA has multiple children, or    #");
    info("# or multiple parents, or a single parent with multiple resource #");
    info("# classes:                                                       #");
    info("#                                                                #");
    info("#                  TA                                            #");
    info("#                   |                                            #");
    info("#                testbed (two children)                          #");
    info("#                 |   |                                          #");
    info("#               CA1   CA2                                        #");
    info("#                 |   |                                          #");
    info("#                  CA3 (two parents, two resource classes)       #");
    info("#                  | |                                           #");
    info("#                  CA4 (two resource classes)                    #");
    info("#                                                                #");
    info("#                                                                #");
    info("# We will verify that:                                           #");
    info("#  * CAs can be set up as parent child using RFC6492             #");
    info("#  * CAs can publish using RFC8181                               #");
    info("#  * CAs can create ROAs                                         #");
    info("#  * CA resources can change:                                    #");
    info("#     - ROAs are cleaned up/created accordingly                  #");
    info("#  * CAs can perform key rolls:                                  #");
    info("#     - Content (ROAs) should be unaffected                      #");
    info("#                                                                #");
    info("#  * RTAs can be created and co-signed under multiple CAs        #");
    info("#                                                                #");
    info("##################################################################");

    info("##################################################################");
    info("#                                                                #");
    info("#                      Start Krill                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    let krill_dir = start_krill_with_default_test_config(true).await;

    let ta = ta_handle();
    let testbed = handle_for("testbed");

    let ca1 = handle_for("CA1");
    let ca1_res = resources("10.0.0.0/16");
    let ca1_res_reduced = resources("10.0.0.0/24");
    let ca1_route_definition = RoaDefinition::from_str("10.0.0.0/16-16 => 65000").unwrap();

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
            will_publish(
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
        info("#                      Set up CA2 under testbed                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca2).await;
        set_up_ca_under_parent_with_resources(&ca2, &testbed, &ca2_res).await;
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
        expected_files.push(expected_issued_cer(&ca2, &rcn_0).await);
        assert!(
            will_publish(
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
        info("#                      Set up CA3 under CA1                      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca3).await;
        set_up_ca_under_parent_with_resources(&ca3, &ca1, &ca3_res_under_ca_1).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#       Expect that CA1 publishes the certificate for CA3        #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca3, &rcn_0).await);
        assert!(will_publish("CA1 should publish the certificate for CA3", &ca1, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#       Let CA1 publish a ROA (covering CA3 resources)           #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(ca1_route_definition);
        ca_route_authorizations_update(&ca1, updates).await;

        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca3, &rcn_0).await);
        expected_files.push(ObjectName::from(&ca1_route_definition).to_string());
        assert!(
            will_publish(
                "CA1 should publish the certificate for CA3 and a ROA",
                &ca1,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Set up CA3 under CA2                      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_under_parent_with_resources(&ca3, &ca2, &ca3_res_under_ca_2).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#       Expect that CA2 publishes the certificate for CA3        #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&ca2, &rcn_0).await;
        // CA3 will have the certificate from CA2 under its resource class '1' rather than '0'
        expected_files.push(expected_issued_cer(&ca3, &rcn_1).await);
        assert!(will_publish("CA2 should have mft, crl and a cert for CA3", &ca2, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#     Set up CA4 under CA3 with resources from both parents      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca4).await;
        set_up_ca_under_parent_with_resources(&ca4, &ca3, &ca4_res_under_ca_3).await;
    }

    //
    {
        info("##################################################################");
        info("#                                                                #");
        info("#       Expect that CA3 publishes two certificates for CA4       #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&ca3, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca4, &rcn_0).await);
        expected_files.append(&mut expected_mft_and_crl(&ca3, &rcn_1).await);
        expected_files.push(expected_issued_cer(&ca4, &rcn_1).await);
        assert!(
            will_publish(
                "CA3 should have two resource classes and a cert for CA4 in each",
                &ca3,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Expect that CA4 publishes two resource classes, with only crls #");
        info("# and manifests                                                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);
        assert!(
            will_publish(
                "CA4 should now have two resource classes, each with a mft and crl",
                &ca4,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Let CA1 do a Key Roll                     #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        ca_roll_init(&ca1).await;
        assert!(state_becomes_new_key(&ca1).await);

        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca3, &rcn_0).await);
        expected_files.push(ObjectName::from(&ca1_route_definition).to_string());
        expected_files.append(&mut expected_new_key_mft_and_crl(&ca1, &rcn_0).await);
        assert!(
            will_publish(
                "CA1 should publish MFT and CRL for both keys and the certificate for CA3 and a ROA",
                &ca1,
                &expected_files
            )
            .await
        );

        ca_roll_activate(&ca1).await;
        assert!(state_becomes_active(&ca1).await);

        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(expected_issued_cer(&ca3, &rcn_0).await);
        expected_files.push(ObjectName::from(&ca1_route_definition).to_string());
        assert!(
            will_publish(
                "CA1 should now publish MFT and CRL for the activated key only, and the certificate for CA3 and a ROA",
                &ca1,
                &expected_files
            )
            .await
        );
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
    async fn expect_roas_for_ca4(test_msg: &str, roas: &[RoaDefinition]) {
        let ca4 = handle_for("CA4");
        let rcn_0 = ResourceClassName::from(0);
        let rcn_1 = ResourceClassName::from(1);

        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);
        for roa in roas {
            expected_files.push(ObjectName::from(roa).to_string());
        }
        assert!(will_publish(test_msg, &ca4, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Add ROAs to CA4                           #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_rc0_1);
        updates.add(route_rc0_2);
        updates.add(route_rc1_1);
        ca_route_authorizations_update(&ca4, updates).await;
        expect_roas_for_ca4(
            "CA4 should now have 2 roas in rc0 and 1 in rc1",
            &[route_rc0_1, route_rc0_2, route_rc1_1],
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Add ROAs beyond the aggregation threshold for RC0, we now      #");
        info("# expect ROAs under RC0 to be aggregated by ASN                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
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

        assert!(will_publish("CA4 should now aggregate ROAs", &ca4, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Remove ROAs below the de-aggregation threshold and we get      #");
        info("# separate files again                                           #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaDefinitionUpdates::empty();
        updates.remove(route_rc0_2);
        updates.remove(route_rc0_3);
        updates.remove(route_rc0_4);
        ca_route_authorizations_update(&ca4, updates).await;

        expect_roas_for_ca4("CA4 should now de-aggregate ROAS", &[route_rc0_1, route_rc1_1]).await;
    }

    //------------------------------------------------------------------------------------------
    // Test shrinking / growing resources
    //------------------------------------------------------------------------------------------

    {
        info("##################################################################");
        info("#                                                                #");
        info("# When resources are removed higher up in the tree, then any of  #");
        info("# resources delegated to child CAs should also be reduced. When  #");
        info("# resources for ROAs are lost, the ROAs should be removed, but   #");
        info("# the authorization (config) is kept.                            #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        update_child(&testbed, &ca1, &ca1_res_reduced).await;
        ca_equals_resources(&ca1, &ca1_res_reduced).await;
        ca_equals_resources(&ca3, &ca3_res_reduced).await;
        ca_equals_resources(&ca4, &ca4_res_reduced).await;
        refresh_all().await; // if we skip this, then CA4 will not find out that it's resources were reduced

        expect_roas_for_ca4(
            "CA4 resources are shrunk and we expect only one remaining roa",
            &[route_rc1_1],
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# When resources are added back higher in the tree, then they    #");
        info("# will also be added to the delegated children again. When       #");
        info("# resources for existing authorizations are re-gained, ROAs      #");
        info("# will be created again.                                         #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        update_child(&testbed, &ca1, &ca1_res).await;
        ca_equals_resources(&ca1, &ca1_res).await;
        ca_equals_resources(&ca3, &ca3_res_combined).await;
        ca_equals_resources(&ca4, &ca4_res_under_ca_3).await;
        refresh_all().await;

        // Expect that the ROA is re-added now that resources are back.
        expect_roas_for_ca4(
            "CA4 resources have been extended again, and we expect two roas",
            &[route_rc0_1, route_rc1_1],
        )
        .await;
    }

    let rta_content = include_bytes!("../test-resources/test.tal");
    let rta_content = Bytes::copy_from_slice(rta_content);

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Create a Single Signed RTA                                     #");
        info("#                                                                #");
        info("##################################################################");
        info("");
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

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Create a Multi Signed RTA                                      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
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

    info("##################################################################");
    info("#                                                                #");
    info("# Remove CA4, we expect that its objects are also removed since  #");
    info("# we are doing this all gracefully.                              #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    {
        delete_ca(&ca4).await;

        // Expect that CA3 no longer publishes certificates for CA4
        {
            let mut expected_files = expected_mft_and_crl(&ca3, &rcn_0).await;
            expected_files.append(&mut expected_mft_and_crl(&ca3, &rcn_1).await);
            assert!(
                will_publish(
                    "CA3 should no longer publish the cert for CA4 after CA4 has been deleted",
                    &ca3,
                    &expected_files
                )
                .await
            );
        }

        // Expect that CA4 withdraws all
        {
            assert!(will_publish("CA4 should withdraw all objects when it's deleted", &ca4, &[]).await);
        }
    }

    let _ = fs::remove_dir_all(krill_dir);
}
