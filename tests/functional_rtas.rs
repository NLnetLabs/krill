//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;

use bytes::Bytes;
use krill::{commons::api::RtaList, daemon::ca::ta_handle, test::*};
use rpki::repository::resources::ResourceSet;

#[tokio::test]
async fn functional_rtas() {
    let krill_dir = start_krill_with_default_test_config(true, false, false, false).await;

    info("##################################################################");
    info("#                                                                #");
    info("# Test Resource Tagged Attestation (RTA) support. (experimental) #");
    info("#                                                                #");
    info("# Uses the following lay-out:                                    #");
    info("#                                                                #");
    info("#                  TA                                            #");
    info("#                   |                                            #");
    info("#                testbed                                         #");
    info("#                 /   |                                          #");
    info("#               CA1   CA2                                        #");
    info("#                                                                #");
    info("# * We will then have a simple RTA under CA1                     #");
    info("# * And a multi-sign RTA under CA1 and CA2                       #");
    info("#                                                                #");
    info("##################################################################");
    info("");

    let ta = ta_handle();
    let testbed = handle("testbed");

    let ca1 = handle("CA1");
    let ca1_res = resources("", "10.0.0.0/16", "");

    let ca2 = handle("CA2");
    let ca2_res = resources("", "10.1.0.0/16", "");

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

    // RTA support
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

    let _ = fs::remove_dir_all(krill_dir);
}
