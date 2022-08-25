//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;

use rpki::{
    ca::{idexchange::CaHandle, provisioning::ResourceClassName},
    repository::resources::ResourceSet,
};

use krill::{
    commons::api::{ObjectName, RoaConfigurationUpdates, RoaPayload},
    daemon::ca::ta_handle,
    test::*,
};

#[tokio::test]
async fn functional_roas() {
    let krill_dir = start_krill_with_default_test_config(true, false, false, false).await;

    info("##################################################################");
    info("#                                                                #");
    info("# Test ROA support.                                              #");
    info("#                                                                #");
    info("# Uses the following lay-out:                                    #");
    info("#                                                                #");
    info("#                  TA                                            #");
    info("#                   |                                            #");
    info("#                testbed                                         #");
    info("#                   |                                            #");
    info("#                  CA                                            #");
    info("#                                                                #");
    info("#                                                                #");
    info("##################################################################");
    info("");

    let ta = ta_handle();
    let testbed = ca_handle("testbed");
    let ca = ca_handle("CA");
    let ca_res = resources("AS65000", "10.0.0.0/8", "");
    let ca_res_shrunk = resources("AS65000", "10.0.0.0/16", "");

    let route_resource_set_10_0_0_0_def_1 = RoaPayload::from_str("10.0.0.0/16-16 => 64496").unwrap();
    let route_resource_set_10_0_0_0_def_2 = RoaPayload::from_str("10.0.0.0/16-16 => 64497").unwrap();
    let route_resource_set_10_0_0_0_def_3 = RoaPayload::from_str("10.0.0.0/24-24 => 64496").unwrap();
    let route_resource_set_10_0_0_0_def_4 = RoaPayload::from_str("10.0.0.0/24-24 => 64497").unwrap();

    // The following definition will be removed in the shrunk set
    let route_resource_set_10_1_0_0_def_1 = RoaPayload::from_str("10.1.0.0/24-24 => 64496").unwrap();

    let rcn_0 = rcn(0);

    info("##################################################################");
    info("#                                                                #");
    info("# Wait for the *testbed* CA to get its certificate, this means   #");
    info("# that all CAs which are set up as part of krill_start under the #");
    info("# testbed config have been set up.                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    assert!(ca_contains_resources(&testbed, &ResourceSet::all()).await);

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
        info("#                      Set up CA  under testbed                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca).await;
        set_up_ca_under_parent_with_resources(&ca, &testbed, &ca_res).await;
    }

    // short hand to expect ROAs under CA
    async fn expect_roa_objects(ca: &CaHandle, roas: &[RoaPayload]) {
        let rcn_0 = ResourceClassName::from(0);

        let mut expected_files = expected_mft_and_crl(ca, &rcn_0).await;

        for roa in roas {
            expected_files.push(ObjectName::from(roa).to_string());
        }

        assert!(will_publish_embedded("published ROAs do not match expectations", ca, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Add ROAs to CA4                           #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaConfigurationUpdates::empty();
        updates.add(route_resource_set_10_0_0_0_def_1.into());
        updates.add(route_resource_set_10_0_0_0_def_2.into());
        updates.add(route_resource_set_10_1_0_0_def_1.into());
        ca_route_authorizations_update(&ca, updates).await;

        expect_roa_objects(
            &ca,
            &[
                route_resource_set_10_0_0_0_def_1,
                route_resource_set_10_0_0_0_def_2,
                route_resource_set_10_1_0_0_def_1,
            ],
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Shrinking resources of CA should result in the removal of ROAs #");
        info("# for prefixes no longer held.                                   #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        update_child(&testbed, &ca.convert(), &ca_res_shrunk).await;
        ca_equals_resources(&ca, &ca_res_shrunk).await;

        expect_roa_objects(
            &ca,
            &[
                route_resource_set_10_0_0_0_def_1,
                route_resource_set_10_0_0_0_def_2,
                // route_resource_set_10_1_0_0_def_1, <-- in removed set
            ],
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Extending the resources of CA to what it was before should     #");
        info("# result in the removed ROA to be re-published                   #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        update_child(&testbed, &ca, &ca_res).await;
        ca_equals_resources(&ca, &ca_res).await;

        expect_roa_objects(
            &ca,
            &[
                route_resource_set_10_0_0_0_def_1,
                route_resource_set_10_0_0_0_def_2,
                route_resource_set_10_1_0_0_def_1, // <-- added back
            ],
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Add ROAs beyond the aggregation threshold of 3 definitions     #");
        info("# We now expect ROAs to be aggregated by ASN                     #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaConfigurationUpdates::empty();
        updates.add(route_resource_set_10_0_0_0_def_3.into());
        updates.add(route_resource_set_10_0_0_0_def_4.into());
        ca_route_authorizations_update(&ca, updates).await;

        // expect MFT and CRL and aggregated ROA files
        let mut expected_files = expected_mft_and_crl(&ca, &rcn_0).await;
        expected_files.push("AS64496.roa".to_string());
        expected_files.push("AS64497.roa".to_string());

        assert!(will_publish_embedded("CA4 should now aggregate ROAs", &ca, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Remove ROAs below the de-aggregation threshold (less than 2)   #");
        info("# We expect separate files again                                 #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaConfigurationUpdates::empty();
        updates.remove(route_resource_set_10_0_0_0_def_2);
        updates.remove(route_resource_set_10_0_0_0_def_3);
        updates.remove(route_resource_set_10_0_0_0_def_4);
        updates.remove(route_resource_set_10_1_0_0_def_1);
        ca_route_authorizations_update(&ca, updates).await;

        expect_roa_objects(&ca, &[route_resource_set_10_0_0_0_def_1]).await;
    }

    let _ = fs::remove_dir_all(krill_dir);
}
