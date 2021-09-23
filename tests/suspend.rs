//! Test suspension and un-suspension logic.

use std::fs;

use krill::{
    commons::api::{ChildHandle, Handle, ResourceSet},
    test::*,
};

#[tokio::test]
async fn test_suspension() {
    init_logging();

    info("##################################################################");
    info("#                                                                #");
    info("#  Test that suspension and un-suspension of child CAs works.    #");
    info("#                                                                #");
    info("#   Uses the following lay-out:                                  #");
    info("#                                                                #");
    info("#                  TA                                            #");
    info("#                   |                                            #");
    info("#                testbed                                         #");
    info("#                   |                                            #");
    info("#                  CA                                            #");
    info("#                                                                #");
    info("#  - Disable the normal background jobs for this test            #");
    info("#  - Set suspension threshold to 5 seconds                       #");
    info("#  - Test that a certificate is published for CA                 #");
    info("#  - Wait 6 seconds                                              #");
    info("#  - Trigger refresh of testbed                                  #");
    info("#  - Test that CA is suspended and certificate withdrawn         #");
    info("#  - Trigger refresh of CA                                       #");
    info("#  - Test that CA is unsuspended and certificate published       #");
    info("#  - Explicitly suspend CA                                       #");
    info("#  - Test that CA is suspended and certificate withdrawn         #");
    info("#  - Explicitly unsuspend CA                                     #");
    info("#  - Test that CA is unsuspended and certificate published       #");
    info("#                                                                #");
    info("##################################################################");

    // Start krill with testbed
    let krill_dir = start_krill_with_default_test_config(true, false, true).await;

    let testbed = handle("testbed");
    let ca = handle("CA");
    let ca_res = resources("10.0.0.0/16");

    async fn expect_not_suspended(ca: &Handle, child: &ChildHandle) {
        let rcn_0 = rcn(0);

        let mut expected_files = expected_mft_and_crl(&ca, &rcn_0).await;
        expected_files.push(expected_issued_cer(&child, &rcn_0).await);
        assert!(will_publish_embedded("CA should have mft, crl and cert for child", &ca, &expected_files).await);

        let ca_info = ca_details(&ca).await;
        assert!(ca_info.children().contains(&child));
        assert!(!ca_info.suspended_children().contains(&child));
    }

    async fn expect_suspended(ca: &Handle, child: &ChildHandle) {
        let rcn_0 = rcn(0);

        let expected_files = expected_mft_and_crl(&ca, &rcn_0).await;
        assert!(will_publish_embedded("CA should have mft, crl only", &ca, &expected_files).await);

        let ca_info = ca_details(&ca).await;
        assert!(ca_info.children().contains(&child));
        assert!(ca_info.suspended_children().contains(&child));
    }

    // Wait for testbed to come up
    {
        assert!(ca_contains_resources(&testbed, &ResourceSet::all_resources()).await);
    }

    // Set up CA under testbed and verify that the certificate is published
    {
        set_up_ca_with_repo(&ca).await;
        set_up_ca_under_parent_with_resources(&ca, &testbed, &ca_res).await;
    }

    // Verify that testbed published the certificate for CA, and that its state is 'active'
    {
        expect_not_suspended(&testbed, &ca).await;
    }

    // Wait a bit, and then refresh testbed only, it should find that
    // the child 'CA' has not been updating, and will suspend it.
    {
        sleep_seconds(5).await;

        cas_refresh_single(&testbed).await;
        expect_suspended(&testbed, &ca).await;
    }

    // Let "CA" refresh with testbed, this should 'un-suspend' it.
    {
        cas_refresh_single(&ca).await;
        expect_not_suspended(&testbed, &ca).await;
    }

    // CAs can also be suspended explicitly, regardless of their last known connection
    {
        ca_suspend_child(&testbed, &ca).await;
        expect_suspended(&testbed, &ca).await;
    }

    // And they can be manually unsuspended as well
    {
        ca_unsuspend_child(&testbed, &ca).await;
        expect_not_suspended(&testbed, &ca).await;
    }

    let _ = fs::remove_dir_all(krill_dir);
}
