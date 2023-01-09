//! Perform functional tests on a Krill instance, using the API
//!
use std::{fs, str::FromStr, time::Duration};

use tokio::time::sleep;

use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::ResourceSet;

use krill::{
    commons::api::{ObjectName, RepoFileDeleteCriteria, RoaConfigurationUpdates, RoaPayload},
    daemon::ca::ta_handle,
    test::*,
};

#[tokio::test]
async fn migrate_repository() {
    init_logging();

    info("##################################################################");
    info("#                                                                #");
    info("#                --= Test Migrating a Repository  =--            #");
    info("#                                                                #");
    info("##################################################################");

    info("##################################################################");
    info("#                                                                #");
    info("#                      Start Krill                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    // Use a 5 second RRDP update interval for the Krill server, so that we can also
    // test here that the re-scheduling of delayed RRDP deltas works.
    let krill_dir = start_krill_testbed_with_rrdp_interval(5).await;

    info("##################################################################");
    info("#                                                                #");
    info("#               Start Secondary Publication Server               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    let pubd_dir = start_krill_pubd(5).await;

    let ta = ta_handle();
    let testbed = ca_handle("testbed");

    let ca1 = ca_handle("CA1");
    let ca1_res = ipv4_resources("10.0.0.0/16");
    let ca1_route_definition = RoaPayload::from_str("10.0.0.0/16-16 => 65000").unwrap();

    let rcn_0 = ResourceClassName::from(0);

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

    // Test the repository purging and re-syncing (healing from the CA's perspective) works as well.
    {
        info("##################################################################");
        info("#                                                                #");
        info("# Test that purging files and re-syncing works:                  #");
        info("#   - remove a single file under the TA                          #");
        info("#   - remove the complete TA dir                                 #");
        info("#   - re-sync, now it should all be published again              #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        {
            // Remove single file - let's remove the issued certificate
            let issued = expected_issued_cer(&testbed, &rcn_0).await;
            let issued_uri = rsync(&format!("rsync://localhost/repo/ta/0/{}", issued));
            let criteria = RepoFileDeleteCriteria::new(issued_uri);
            krill_admin(krill::cli::options::Command::PubServer(
                krill::cli::options::PubServerCommand::DeleteFiles(criteria),
            ))
            .await;
            let expected_files = expected_mft_and_crl(&ta, &rcn_0).await;
            assert!(
                will_publish_embedded(
                    "TA should have manifest, crl but NO more cert for testbed",
                    &ta,
                    &expected_files
                )
                .await
            );
        }

        {
            // removing a directory should also work
            let criteria = RepoFileDeleteCriteria::new(rsync("rsync://localhost/repo/ta/"));
            krill_admin(krill::cli::options::Command::PubServer(
                krill::cli::options::PubServerCommand::DeleteFiles(criteria),
            ))
            .await;
            assert!(will_publish_embedded("TA should have NO content now", &ta, &[]).await);
        }

        {
            // re-sync - all should be back
            cas_sync_all().await;
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
        info("#                      Create a ROA for CA1                      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut updates = RoaConfigurationUpdates::empty();
        updates.add(ca1_route_definition.into());
        ca_route_authorizations_update(&ca1, updates).await;
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
        info("#       Expect that CA1 publishes in the embedded repo           #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
        expected_files.push(ObjectName::from(&ca1_route_definition).to_string());

        assert!(will_publish_embedded("CA1 should publish the certificate for CA3", &ca1, &expected_files).await);
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("# Migrate a Repository for CA1 (using a keyroll)                 #");
        info("#                                                                #");
        info("# CA1 currently uses the embedded publication server. In order   #");
        info("# to migrate it, we will need to do the following:               #");
        info("#                                                                #");
        info("# - get the RFC 8183 publisher request from CA1                  #");
        info("# - add CA1 as a publisher under the dedicated (separate) pubd,  #");
        info("# - get the response                                             #");
        info("# - update the repo config for CA1 using the 8183 response       #");
        info("#    -- this should initiate a key roll                          #");
        info("#    -- the new key publishes in the new repo                    #");
        info("# - complete the key roll                                        #");
        info("#    -- the old key should be cleaned up,                        #");
        info("#    -- nothing published for CA1 in the embedded repo           #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        // Add CA1 to dedicated repo
        let publisher_request = publisher_request(&ca1).await;
        dedicated_repo_add_publisher(publisher_request).await;
        let response = dedicated_repository_response(&ca1).await;

        // Wait a tiny bit.. when we add a new repo we check that it's available or
        // it will be rejected.
        sleep(Duration::from_secs(1)).await;

        // Update CA1 to use dedicated repo
        repo_update(&ca1, response).await;

        // This should result in a key roll and content published in both repos
        assert!(state_becomes_new_key(&ca1).await);

        // Expect that CA1 still publishes two current keys in the embedded repo
        {
            let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
            expected_files.push(ObjectName::from(&ca1_route_definition).to_string());

            assert!(
                will_publish_embedded(
                    "CA1 should publish the MFT and CRL for both current keys in the embedded repo",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }

        // Expect that CA1 publishes two new keys in the dedicated repo
        {
            let expected_files = expected_new_key_mft_and_crl(&ca1, &rcn_0).await;
            assert!(
                will_publish_dedicated(
                    "CA1 should publish the MFT and CRL for both new keys in the dedicated repo",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }

        // Complete the keyroll, this should remove the content in the embedded repo
        ca_roll_activate(&ca1).await;
        assert!(state_becomes_active(&ca1).await);

        // Expect that CA1 publishes two current keys in the dedicated repo
        {
            let mut expected_files = expected_mft_and_crl(&ca1, &rcn_0).await;
            expected_files.push(ObjectName::from(&ca1_route_definition).to_string());

            assert!(
                will_publish_dedicated(
                    "CA1 should publish the MFT and CRL for both current keys in the dedicated repo",
                    &ca1,
                    &expected_files
                )
                .await
            );
        }

        // Expect that CA1 publishes nothing in the embedded repo
        {
            assert!(
                will_publish_embedded("CA1 should no longer publish anything in the embedded repo", &ca1, &[]).await
            );
        }
    }

    let _ = fs::remove_dir_all(krill_dir);
    let _ = fs::remove_dir_all(pubd_dir);
}
