//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;

use krill::{
    commons::api::{
        AspaCustomer, AspaDefinition, AspaDefinitionList, AspaProvidersUpdate, Handle, ObjectName, ResourceClassName,
        ResourceSet,
    },
    daemon::ca::ta_handle,
    test::*,
};
use rpki::repository::aspa::ProviderAs;

#[tokio::test]
async fn functional_aspa() {
    let krill_dir = start_krill_with_default_test_config(true, false, false, false).await;

    info("##################################################################");
    info("#                                                                #");
    info("# Test ASPA support.                                             #");
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
    let testbed = handle("testbed");
    let ca = handle("CA");
    let ca_res = resources("AS65000", "10.0.0.0/16", "");

    let rcn_0 = rcn(0);

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
        info("#                      Set up CA  under testbed                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca).await;
        set_up_ca_under_parent_with_resources(&ca, &testbed, &ca_res).await;
    }

    // short hand to expect ASPAs under CA
    async fn expect_aspa_objects(ca: &Handle, aspas: &[AspaDefinition]) {
        let rcn_0 = ResourceClassName::from(0);

        let mut expected_files = expected_mft_and_crl(ca, &rcn_0).await;

        for aspa in aspas {
            expected_files.push(ObjectName::aspa(aspa.customer()).to_string());
        }

        assert!(will_publish_embedded("published ASPAs do not match expectations", ca, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Add an ASPA under CA                                           #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let aspa_65000 = AspaDefinition::from_str("AS65000 => AS65002, AS65003(v4), AS65005(v6)").unwrap();

        ca_aspas_add(&ca, aspa_65000.clone()).await;

        let aspas = vec![aspa_65000];
        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
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

        ca_aspas_update(&ca, customer, aspa_update).await;

        let updated_aspa = AspaDefinition::from_str("AS65000 => AS65003(v4), AS65005(v6), AS65006").unwrap();
        let aspas = vec![updated_aspa.clone()];

        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
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

        ca_aspas_update(&ca, customer, aspa_update).await;

        let updated_aspa = AspaDefinition::from_str("AS65000 => <none>").unwrap();
        let aspas = vec![updated_aspa];

        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Delete an existing ASPA                                        #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let customer = AspaCustomer::from_str("AS65000").unwrap();
        ca_aspas_remove(&ca, customer).await;

        expect_aspa_objects(&ca, &[]).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(vec![])).await;
    }

    let _ = fs::remove_dir_all(krill_dir);
}
