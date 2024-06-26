//! Perform functional tests on a Krill instance, using the API
use std::str::FromStr;

use rpki::{
    ca::{idexchange::CaHandle, provisioning::ResourceClassName},
    repository::resources::ResourceSet,
};

use krill::{
    commons::api::{
        AspaDefinition, AspaDefinitionList, AspaProvidersUpdate, CustomerAsn,
        ObjectName, ProviderAsn,
    },
    test::*,
};

#[tokio::test]
async fn functional_aspa() {
    let cleanup =
        start_krill_with_default_test_config(true, false, false, false).await;

    info(
        "##################################################################",
    );
    info(
        "#                                                                #",
    );
    info(
        "# Test ASPA support.                                             #",
    );
    info(
        "#                                                                #",
    );
    info(
        "# Uses the following lay-out:                                    #",
    );
    info(
        "#                                                                #",
    );
    info(
        "#                  TA                                            #",
    );
    info(
        "#                   |                                            #",
    );
    info(
        "#                testbed                                         #",
    );
    info(
        "#                   |                                            #",
    );
    info(
        "#                  CA                                            #",
    );
    info(
        "#                                                                #",
    );
    info(
        "#                                                                #",
    );
    info(
        "##################################################################",
    );
    info("");

    let testbed = ca_handle("testbed");
    let ca = ca_handle("CA");
    let ca_res = resources("AS65000", "10.0.0.0/16", "");

    info(
        "##################################################################",
    );
    info(
        "#                                                                #",
    );
    info(
        "# Wait for the *testbed* CA to get its certificate, this means   #",
    );
    info(
        "# that all CAs which are set up as part of krill_start under the #",
    );
    info(
        "# testbed config have been set up.                               #",
    );
    info(
        "#                                                                #",
    );
    info(
        "##################################################################",
    );
    info("");
    assert!(ca_contains_resources(&testbed, &ResourceSet::all()).await);

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
    async fn expect_aspa_objects(ca: &CaHandle, aspas: &[AspaDefinition]) {
        let rcn_0 = ResourceClassName::from(0);

        let mut expected_files = expected_mft_and_crl(ca, &rcn_0).await;

        for aspa in aspas {
            expected_files
                .push(ObjectName::aspa(aspa.customer()).to_string());
        }

        assert!(
            will_publish_embedded(
                "published ASPAs do not match expectations",
                ca,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Reject ASPA without providers                                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let aspa_65000 =
            AspaDefinition::from_str("AS65000 => <none>").unwrap();

        ca_aspas_add_expect_error(&ca, aspa_65000.clone()).await;

        let expected_aspas = vec![];
        expect_aspa_objects(&ca, &expected_aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(expected_aspas))
            .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Reject ASPA using customer as provider                         #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let aspa_65000 =
            AspaDefinition::from_str("AS65000 => AS65000, AS65003, AS65005")
                .unwrap();

        ca_aspas_add_expect_error(&ca, aspa_65000.clone()).await;

        let aspas = vec![];
        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Add an ASPA under CA                                           #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let aspa_65000 =
            AspaDefinition::from_str("AS65000 => AS65002, AS65003, AS65005")
                .unwrap();

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

        let customer = CustomerAsn::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![ProviderAsn::from_str("AS65006").unwrap()],
            vec![ProviderAsn::from_str("AS65002").unwrap()],
        );

        ca_aspas_update(&ca, customer, aspa_update).await;

        let updated_aspa =
            AspaDefinition::from_str("AS65000 => AS65003, AS65005, AS65006")
                .unwrap();
        let aspas = vec![updated_aspa.clone()];

        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Reject update that adds customer as provider                   #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let customer = CustomerAsn::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![ProviderAsn::from_str("AS65000").unwrap()],
            vec![],
        );

        ca_aspas_update_expect_error(&ca, customer, aspa_update).await;

        let unmodified_aspa =
            AspaDefinition::from_str("AS65000 => AS65003, AS65005, AS65006")
                .unwrap();
        let aspas = vec![unmodified_aspa.clone()];

        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Update ASPA and remove all providers, should amount to delete  #");
        info("#                                                                #");
        info("##################################################################");

        let customer = CustomerAsn::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![],
            vec![
                ProviderAsn::from_str("AS65003").unwrap(),
                ProviderAsn::from_str("AS65005").unwrap(),
                ProviderAsn::from_str("AS65006").unwrap(),
            ],
        );

        ca_aspas_update(&ca, customer, aspa_update).await;

        // expect that the ASPA definition and object will be removed
        // when all providers are removed from the existing definition.
        let expected_aspas = vec![];
        expect_aspa_objects(&ca, &expected_aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(expected_aspas))
            .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Add provider to non-existing definition, this should create a  #");
        info("# a new AspaDefinition. This is useful for two reasons:          #");
        info("# 1) it allows for automation using just updates                 #");
        info("# 2) because empty provider lists were accepted in Krill <0.13.0 #");
        info("#    we need the code to deal with removing all providers, which #");
        info("#    will remove the AspaConfig when replayed, and then adding   #");
        info("#    some provider again.                                        #");
        info("#                                                                #");
        info("##################################################################");

        let customer = CustomerAsn::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![
                ProviderAsn::from_str("AS65003").unwrap(),
                ProviderAsn::from_str("AS65005").unwrap(),
                ProviderAsn::from_str("AS65006").unwrap(),
            ],
            vec![],
        );

        ca_aspas_update(&ca, customer, aspa_update).await;

        let updated_aspa =
            AspaDefinition::from_str("AS65000 => AS65003, AS65005, AS65006")
                .unwrap();
        let aspas = vec![updated_aspa.clone()];

        expect_aspa_objects(&ca, &aspas).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(aspas)).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Adding an existing provider, and removing a non-existing       #");
        info("# provider to/from an AspaDefinition should be idempotent.       #");
        info("#                                                                #");
        info("##################################################################");

        let customer = CustomerAsn::from_str("AS65000").unwrap();
        let aspa_update = AspaProvidersUpdate::new(
            vec![
                ProviderAsn::from_str("AS65002").unwrap(), // add
                ProviderAsn::from_str("AS65005").unwrap(), /* add, but was already present, so ignored */
            ],
            vec![
                ProviderAsn::from_str("AS65006").unwrap(), // remove
                ProviderAsn::from_str("AS65007").unwrap(), /* remove, but was not present, so ignored */
            ],
        );

        ca_aspas_update(&ca, customer, aspa_update).await;

        let updated_aspa =
            AspaDefinition::from_str("AS65000 => AS65002, AS65003, AS65005")
                .unwrap();
        let aspas = vec![updated_aspa.clone()];

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

        let customer = CustomerAsn::from_str("AS65000").unwrap();
        ca_aspas_remove(&ca, customer).await;

        expect_aspa_objects(&ca, &[]).await;
        expect_aspa_definitions(&ca, AspaDefinitionList::new(vec![])).await;
    }

    cleanup();
}
