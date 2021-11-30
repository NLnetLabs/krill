//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;

use bytes::Bytes;

use krill::{
    commons::api::{
        AspaCustomer, AspaDefinition, AspaDefinitionList, AspaProvidersUpdate, ObjectName, ResourceClassName,
        ResourceSet, RoaDefinition, RoaDefinitionUpdates, RtaList,
    },
    daemon::ca::ta_handle,
    test::*,
};
use rpki::repository::aspa::ProviderAs;

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
    info("#  * CAs can create ASPAs                                        #");
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
    let krill_dir = start_krill_with_default_test_config(true, false, false, false).await;

    let ta = ta_handle();
    let testbed = handle("testbed");

    let ca1 = handle("CA1");
    let ca1_res = resources("AS65000", "10.0.0.0/16", "");
    let ca1_res_reduced = resources("", "10.0.0.0/24", "");
    let ca1_route_definition = RoaDefinition::from_str("10.0.0.0/16-16 => 65000").unwrap();

    let ca2 = handle("CA2");
    let ca2_res = resources("AS65001", "10.1.0.0/16", "");

    let ca3 = handle("CA3");
    let ca3_res_under_ca_1 = resources("65000", "10.0.0.0/16", "");
    let ca3_res_under_ca_2 = resources("65001", "10.1.0.0/24", "");
    let ca3_res_combined = resources("65000-65001", "10.0.0.0/16, 10.1.0.0/24", "");
    let ca3_res_reduced = resources("65001", "10.0.0.0/24,10.1.0.0/24", "");

    let ca4 = handle("CA4");
    let ca4_res_under_ca_3 = resources("65000", "10.0.0.0-10.1.0.255", "");
    let ca4_res_reduced = resources("", "10.0.0.0/24,10.1.0.0/24", "");

    let rcn_0 = rcn(0);
    let rcn_1 = rcn(1);
    let rcn_2 = rcn(2);
    let rcn_3 = rcn(3);

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
        assert!(will_publish_embedded("CA1 should publish the certificate for CA3", &ca1, &expected_files).await);
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
            will_publish_embedded(
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
        assert!(will_publish_embedded("CA2 should have mft, crl and a cert for CA3", &ca2, &expected_files).await);
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
            will_publish_embedded(
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
            will_publish_embedded(
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
            will_publish_embedded(
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
            will_publish_embedded(
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
    let route_resource_set_10_0_0_0_def_1 = RoaDefinition::from_str("10.0.0.0/16-16 => 64496").unwrap();
    let route_resource_set_10_0_0_0_def_2 = RoaDefinition::from_str("10.0.0.0/16-16 => 64497").unwrap();
    let route_resource_set_10_0_0_0_def_3 = RoaDefinition::from_str("10.0.0.0/24-24 => 64496").unwrap();
    let route_resource_set_10_0_0_0_def_4 = RoaDefinition::from_str("10.0.0.0/24-24 => 64497").unwrap();
    let route_resource_set_10_1_0_0_def_1 = RoaDefinition::from_str("10.1.0.0/24-24 => 64496").unwrap();

    // short hand to expect ROAs under CA4
    async fn expect_objects_for_ca4(test_msg: &str, roas: &[RoaDefinition], aspas: &[AspaDefinition]) {
        let ca4 = handle("CA4");
        let rcn_0 = ResourceClassName::from(0);
        let rcn_1 = ResourceClassName::from(1);

        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);
        for roa in roas {
            expected_files.push(ObjectName::from(roa).to_string());
        }
        for aspa in aspas {
            expected_files.push(ObjectName::aspa(aspa.customer()).to_string());
        }
        assert!(will_publish_embedded(test_msg, &ca4, &expected_files).await);
    }

    // short hand to expect ROAs under CA4, re-added when parent comes back
    // i.e. it now has RC 2 and 3, but no more 0 and 1
    async fn expect_objects_for_ca4_re_added(test_msg: &str, roas: &[RoaDefinition], aspas: &[AspaDefinition]) {
        let ca4 = handle("CA4");
        let rcn_2 = ResourceClassName::from(2);
        let rcn_3 = ResourceClassName::from(3);

        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_2).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_3).await);
        for roa in roas {
            expected_files.push(ObjectName::from(roa).to_string());
        }
        for aspa in aspas {
            expected_files.push(ObjectName::aspa(aspa.customer()).to_string());
        }
        assert!(will_publish_embedded(test_msg, &ca4, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Add ROAs to CA4                           #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_resource_set_10_0_0_0_def_1);
        updates.add(route_resource_set_10_0_0_0_def_2);
        updates.add(route_resource_set_10_1_0_0_def_1);
        ca_route_authorizations_update(&ca4, updates).await;
        expect_objects_for_ca4(
            "CA4 should now have 2 roas in rc0 and 1 in rc1",
            &[
                route_resource_set_10_0_0_0_def_1,
                route_resource_set_10_0_0_0_def_2,
                route_resource_set_10_1_0_0_def_1,
            ],
            &[],
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
        updates.add(route_resource_set_10_0_0_0_def_3);
        updates.add(route_resource_set_10_0_0_0_def_4);
        ca_route_authorizations_update(&ca4, updates).await;

        // expect MFT and CRL for RC0 and RC1
        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_1).await);

        // expect aggregated ROAs (under RC0)
        expected_files.push("AS64496.roa".to_string());
        expected_files.push("AS64497.roa".to_string());

        // and the roa for rc1
        expected_files.push(ObjectName::from(&route_resource_set_10_1_0_0_def_1).to_string());

        assert!(will_publish_embedded("CA4 should now aggregate ROAs", &ca4, &expected_files).await);
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
        updates.remove(route_resource_set_10_0_0_0_def_2);
        updates.remove(route_resource_set_10_0_0_0_def_3);
        updates.remove(route_resource_set_10_0_0_0_def_4);
        ca_route_authorizations_update(&ca4, updates).await;

        expect_objects_for_ca4(
            "CA4 should now de-aggregate ROAS",
            &[route_resource_set_10_0_0_0_def_1, route_resource_set_10_1_0_0_def_1],
            &[],
        )
        .await;
    }

    //------------------------------------------------------------------------------------------
    // Test managing ASPAs
    //------------------------------------------------------------------------------------------

    let aspa_65000 = AspaDefinition::from_str("AS65000 => AS65002, AS65003(v4), AS65005(v6)").unwrap();
    let aspas = vec![aspa_65000.clone()];

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Add an ASPA under CA4                                          #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        ca_aspas_add(&ca4, aspa_65000.clone()).await;

        ca_aspas_expect(&ca4, AspaDefinitionList::new(vec![aspa_65000])).await;

        expect_objects_for_ca4(
            "CA4 should now de-aggregate ROAS",
            &[route_resource_set_10_0_0_0_def_1, route_resource_set_10_1_0_0_def_1],
            &aspas,
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Update an existing ASPA                                        #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let customer = AspaCustomer::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![ProviderAs::from_str("AS65006").unwrap()],
            vec![ProviderAs::from_str("AS65002").unwrap()],
        );

        ca_aspas_update(&ca4, customer, aspa_update).await;

        let updated_aspa = AspaDefinition::from_str("AS65000 => AS65003(v4), AS65005(v6), AS65006").unwrap();
        ca_aspas_expect(&ca4, AspaDefinitionList::new(vec![updated_aspa])).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Update ASPA to have no providers (explicit empty list)         #");
        info("#                                                                #");
        info("##################################################################");

        let customer = AspaCustomer::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![],
            vec![
                ProviderAs::from_str("AS65003(v4)").unwrap(),
                ProviderAs::from_str("AS65005(v6)").unwrap(),
                ProviderAs::from_str("AS65006").unwrap(),
            ],
        );

        ca_aspas_update(&ca4, customer, aspa_update).await;

        let updated_aspa = AspaDefinition::from_str("AS65000 => <none>").unwrap();
        ca_aspas_expect(&ca4, AspaDefinitionList::new(vec![updated_aspa])).await;
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
        info("# the authorization (config) is kept. Similarly ASPA objects are #");
        info("# removed, but the configuration is kept.                        #");
        info("##################################################################");
        info("");
        update_child(&testbed, &ca1, &ca1_res_reduced).await;
        ca_equals_resources(&ca1, &ca1_res_reduced).await;
        ca_equals_resources(&ca3, &ca3_res_reduced).await;
        ca_equals_resources(&ca4, &ca4_res_reduced).await;

        // One ROA gone, and the ASPA object is gone
        expect_objects_for_ca4(
            "CA4 resources are shrunk and we expect only one remaining roa",
            &[route_resource_set_10_1_0_0_def_1],
            &[],
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# When resources are added back higher in the tree, then they    #");
        info("# will also be added to the delegated children again. When       #");
        info("# resources for existing authorizations are re-gained, ROAs      #");
        info("# and ASPAs will be created again.                               #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        update_child(&testbed, &ca1, &ca1_res).await;
        ca_equals_resources(&ca1, &ca1_res).await;
        ca_equals_resources(&ca3, &ca3_res_combined).await;
        ca_equals_resources(&ca4, &ca4_res_under_ca_3).await;

        // Expect that the ROA is re-added now that resources are back.
        expect_objects_for_ca4(
            "CA4 resources have been extended again, and we expect two roas",
            &[route_resource_set_10_0_0_0_def_1, route_resource_set_10_1_0_0_def_1],
            &aspas,
        )
        .await;
    }

    let rta_content = include_bytes!("../test-resources/test.tal");
    let rta_content = Bytes::copy_from_slice(rta_content);

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Delete an existing ASPA                                        #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let customer = AspaCustomer::from_str("AS65000").unwrap();
        ca_aspas_remove(&ca4, customer).await;

        ca_aspas_expect(&ca4, AspaDefinitionList::new(vec![])).await;

        // Expect that the ASPA object is withdrawn
        expect_objects_for_ca4(
            "CA4 should now remove ASPA",
            &[route_resource_set_10_0_0_0_def_1, route_resource_set_10_1_0_0_def_1],
            &[],
        )
        .await;
    }

    // RTA support

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
        let multi_resources = ipv4_resources("10.0.0.0/16, 10.1.0.0/16");
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

        let _multi_signed = rta_show(ca1.clone(), multi_rta_name).await;
    }

    // Parent / Child

    info("##################################################################");
    info("#                                                                #");
    info("# Remove parent from CA4, we expect that objects are withdrawn   #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    {
        // Remove parent CA3 from CA4
        delete_parent(&ca4, &ca3).await;
        delete_child(&ca3, &ca4).await;

        // Expect that CA4 withdraws all
        {
            assert!(will_publish_embedded("CA4 should withdraw objects when parent is removed", &ca4, &[]).await);
        }
    }

    info("##################################################################");
    info("#                                                                #");
    info("# Add parent back to CA4, expect that ROAs are published again   #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    {
        // Add parent CA3 back to CA4
        set_up_ca_under_parent_with_resources(&ca4, &ca3, &ca4_res_under_ca_3).await;

        // Expect that the ROAs are published again when parent and resources are back.
        expect_objects_for_ca4_re_added(
            "CA4 resources have been extended again, and we expect two roas",
            &[route_resource_set_10_0_0_0_def_1, route_resource_set_10_1_0_0_def_1],
            &[],
        )
        .await;
    }

    info("##################################################################");
    info("#                                                                #");
    info("# Suspend CA4, expect that parent CA3 stops publishing its certs #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    {
        suspend_inactive_child(&ca3, &ca4).await;

        let mut expected_files = expected_mft_and_crl(&ca3, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca3, &rcn_1).await);
        assert!(
            will_publish_embedded(
                "CA3 should have two resource classes and no cert for CA4 in either",
                &ca3,
                &expected_files
            )
            .await
        );
    }

    info("##################################################################");
    info("#                                                                #");
    info("# Unsuspend CA4, expect that parent publishes its certs again    #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    {
        cas_refresh_all().await;

        let mut expected_files = expected_mft_and_crl(&ca3, &rcn_0).await;
        expected_files.append(&mut expected_mft_and_crl(&ca3, &rcn_1).await);
        expected_files.push(expected_issued_cer(&ca4, &rcn_2).await);
        expected_files.push(expected_issued_cer(&ca4, &rcn_3).await);
        assert!(
            will_publish_embedded(
                "CA3 should have two resource classes and a cert for CA4 in each",
                &ca3,
                &expected_files
            )
            .await
        );
    }

    info("##################################################################");
    info("#                                                                #");
    info("# Remove CA3, we expect that its objects are also removed since  #");
    info("# we are doing this all gracefully.                              #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    {
        delete_ca(&ca3).await;
        // Expect that CA3 no longer publishes anything
        {
            assert!(
                will_publish_embedded(
                    "CA3 should no longer publish anything after it has been deleted",
                    &ca3,
                    &[]
                )
                .await
            );
        }

        // Expect that CA1 no longer publishes the certificate for CA3
        // i.e. CA3 requested its revocation.
        {
            let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
            expected_files.push(ObjectName::from(&ca1_route_definition).to_string());
            assert!(
                will_publish_embedded(
                    "CA1 should no longer publish the cer for CA3 after CA3 has been deleted",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }
    }

    let _ = fs::remove_dir_all(krill_dir);
}
