//! Perform functional tests on a Krill instance, using the API
//!
use rpki::repository::resources::ResourceSet;

use krill::test::*;

#[tokio::test]
async fn functional_parent_child() {
    // let cleanup = start_krill_with_default_test_config(true, false, false, false).await;
    let cleanup = start_krill_with_default_test_config_disk(true, false, false, false).await;

    info("##################################################################");
    info("#                                                                #");
    info("# Test Krill parent - child interactions.                         #");
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
    info("#  * CA1 can perform a key roll                                  #");
    info("#  * We can remove and re-add parents / children                 #");
    info("#  * A CA will request revocation and withdraw objects when      #");
    info("#     it is deleted gracefully                                   #");
    info("#                                                                #");
    info("##################################################################");
    info("");

    let testbed = ca_handle("testbed");

    let ca1 = ca_handle("CA1");
    let ca1_res = resources("AS65000", "10.0.0.0/16", "");

    let ca2 = ca_handle("CA2");
    let ca2_res = resources("AS65001", "10.1.0.0/16", "");

    let ca3 = ca_handle("CA3");
    let ca3_res_under_ca_1 = resources("65000", "10.0.0.0/16", "");
    let ca3_res_under_ca_2 = resources("65001", "10.1.0.0/24", "");

    let ca4 = ca_handle("CA4");
    let ca4_res_under_ca_3 = resources("65000", "10.0.0.0-10.1.0.255", "");

    let rcn_0 = rcn(0);
    let rcn_1 = rcn(1);

    info("##################################################################");
    info("#                                                                #");
    info("# Wait for the *testbed* CA to get its certificate, this means   #");
    info("# that all CAs which are set up as part of krill_start under the #");
    info("# testbed config have been set up.                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    assert!(ca_contains_resources(&testbed, &ResourceSet::all()).await);

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
        assert!(
            will_publish_embedded(
                "CA1 should now publish MFT and CRL for the activated key only, and the certificate for CA3 and a ROA",
                &ca1,
                &expected_files
            )
            .await
        );
    }

    //--------------------------------------------------------------

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

        // We expect new resource classes to be used now:
        let rcn_2 = rcn(2);
        let rcn_3 = rcn(3);

        let mut expected_files = expected_mft_and_crl(&ca4, &rcn_2).await;
        expected_files.append(&mut expected_mft_and_crl(&ca4, &rcn_3).await);
        assert!(
            will_publish_embedded(
                "CA4 should now have two resource classes, each with a mft and crl",
                &ca4,
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
        assert!(ca_details_opt(&ca3).await.is_some());
        delete_ca(&ca3).await;
        assert!(ca_details_opt(&ca3).await.is_none());

        // Also checked manually that ca_objects/CA3.json is gone
        // using disk based storage. This is not so easy to check
        // here (automated) because we don't have direct access to
        // the in-memory store.

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
            let expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
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

    cleanup();
}
