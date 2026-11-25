//! Tests parent/child interactions.

use krill::api::admin::UpdateChildRequest;
use rpki::repository::resources::ResourceSet;

mod common;


//------------ Test Function -------------------------------------------------

/// This test tests whether a child gets an error when it tries to renew a 
/// certificate with no resources.
/// 
/// See https://github.com/NLnetLabs/krill/issues/1397
/// 
/// Setup: testbed -> CA1 -> CA2. CA1 revokes resources for CA2.
#[tokio::test]
async fn functional_no_resources() {
    let server
        = common::KrillServer::start_with_config_testbed(|config| {
            config.issuance_timing.timing_child_certificate_reissue_weeks_before = 999;
        }).await;

    let testbed = common::ca_handle("testbed");

    let ca1 = common::ca_handle("CA1");
    let ca1_res = common::resources("AS65000", "10.0.0.0/24", "abcd::/32");
    let ca1_new_res = common::resources("AS65000", "", "abcd::/32");

    let ca2 = common::ca_handle("CA2");
    let ca2_res = common::resources("", "10.0.0.0/24", "");

    let rcn0 = common::rcn(0);

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up CA1 under testbed.");
    server.create_ca_with_repo(&ca1).await;
    server.register_ca_with_parent(&ca1, &testbed, &ca1_res).await;

    eprintln!(">>>> Set up CA2 under CA1.");
    server.create_ca_with_repo(&ca2).await;
    server.register_ca_with_parent(&ca2, &ca1, &ca2_res).await;

    eprintln!(">>>> Verify that the testbed published the expected objects");
    let mut files = server.expected_objects(&testbed);
    files.push_mft_and_crl(&rcn0).await;
    files.push_cer(&ca1, &rcn0).await;
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Verify that CA1 published the expected objects");
    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0).await;
    files.push_cer(&ca2, &rcn0).await;
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Reduce resources for CA1");
    server.client().child_update(&testbed, &ca1.convert(), 
        UpdateChildRequest::resources(ca1_new_res.clone())
    ).await.unwrap();
    common::sleep_millis(500).await;
    server.client().ca_sync_parents(&ca2).await.unwrap();
    common::sleep_millis(500).await;
    assert_eq!(server.client().ca_details(&ca2).await.unwrap().resources, ResourceSet::empty());
    assert_eq!(server.client().ca_details(&ca1).await.unwrap().resources, ca1_new_res.clone());

    server.client().ca_sync_parents(&ca2).await.unwrap();
    server.client().repo_refresh(&ca2).await.unwrap();
    common::sleep_millis(500).await;

}
