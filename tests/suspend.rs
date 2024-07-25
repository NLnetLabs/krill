//! Test suspension and un-suspension logic.
use rpki::ca::idexchange::CaHandle;
use rpki::repository::resources::ResourceSet;
use krill::commons::api::UpdateChildRequest;

mod common;

//------------ Test Function -------------------------------------------------

/// Tests suspension and un-suspension.
///
/// Uses the following layout:
/// ```test
///     TA
///      |
///   testbed
///      |
///     CA
/// ```
#[tokio::test]
async fn test_suspension() {
    let (config, _tmpdir) = common::TestConfig::mem_storage()
        .enable_testbed().enable_suspend().finalize();
    let server = common::KrillServer::start_with_config(config).await;

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::ipv4_resources("10.0.0.0/16");

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up CA under testbed and its cert is published.");
    server.create_ca_with_repo(&ca).await;
    server.register_ca_with_parent(&ca, &testbed, &ca_res).await;

    eprintln!(">>>> Verify that testbed publishes the cert and it is active");
    server.expect_not_suspended(&testbed, &ca).await;

    eprintln!(">>>> Wait a bit.");
    common::sleep_seconds(15).await;

    eprintln!(">>>> Refresh testbed only, check that CA is suspended.");
    // This happens because CA isn’t updating.
    server.client().ca_sync_parents(&testbed).await.unwrap();
    server.client().bulk_suspend().await.unwrap();
    server.expect_suspended(&testbed, &ca).await;

    eprintln!(">>>> Let CA refresh with testbed, this should un-suspend it.");
    server.client().ca_sync_parents(&ca).await.unwrap();
    server.client().bulk_suspend().await.unwrap();
    server.expect_not_suspended(&testbed, &ca).await;

    eprintln!(">>>> Explicitly suspend CA.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::suspend()
    ).await.unwrap();
    server.expect_suspended(&testbed, &ca).await;

    eprintln!(">>>> Explicitly un-suspend CA.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::unsuspend()
    ).await.unwrap();
    server.expect_not_suspended(&testbed, &ca).await;
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    async fn expect_not_suspended(&self, ca: &CaHandle, child: &CaHandle)  {
        let rcn0 = common::rcn(0);
        let child_handle = child.convert();

        let mut files = self.expected_objects(&ca);
        files.push_mft_and_crl(&rcn0).await;
        files.push_cer(child, &rcn0).await;
        assert!(files.wait_for_published().await);

        let ca_info = self.client().ca_details(ca).await.unwrap();
        assert!(ca_info.children().contains(&child_handle));
        assert!(!ca_info.suspended_children().contains(&child_handle));
    }

    async fn expect_suspended(&self, ca: &CaHandle, child: &CaHandle) {
        let rcn0 = common::rcn(0);
        let child_handle = child.convert();

        let mut files = self.expected_objects(&ca);
        files.push_mft_and_crl(&rcn0).await;
        assert!(files.wait_for_published().await);
        
        let ca_info = self.client().ca_details(ca).await.unwrap();
        assert!(ca_info.children().contains(&child_handle));
        assert!(ca_info.suspended_children().contains(&child_handle));
    }

}

