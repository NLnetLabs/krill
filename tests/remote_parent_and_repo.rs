//! Perform functional tests on a Krill instance, using the API
use rpki::{
    ca::provisioning::ResourceClassName, repository::resources::ResourceSet,
};
use std::str::FromStr;

use krill::{
    commons::api::{
        ObjectName, ParentCaReq, RoaConfigurationUpdates, RoaPayload,
    },
    test::*,
};

#[tokio::test]
async fn remote_parent_and_repo() {
    let cleanup_logging = init_logging();

    info("test running a CA under a remote parent and repo");

    let cleanup_krill_storage =
        start_krill_testbed_with_rrdp_interval(5).await;
    let cleanup_second_krill_storage = start_second_krill().await;

    let testbed = ca_handle("testbed");
    let ca1 = ca_handle("CA1");
    let ca1_res = ipv4_resources("10.0.0.0/16");
    let ca1_route_definition =
        RoaPayload::from_str("10.0.0.0/16-16 => 65000").unwrap();
    let rcn_0 = ResourceClassName::from(0);

    // Verify that the TA and testbed are ready
    assert!(ca_contains_resources(&testbed, &ResourceSet::all()).await);

    // Create up CA1 in second server
    {
        init_ca_krill2(&ca1).await;
    }

    // Set up CA1 as a child to testbed
    {
        let req = request_krill2(&ca1).await;
        let parent = {
            let response = add_child_rfc6492(
                testbed.convert(),
                ca1.convert(),
                req,
                ca1_res.clone(),
            )
            .await;
            ParentCaReq::new(testbed.convert(), response)
        };
        add_parent_to_ca_krill2(&ca1, parent).await;
    }

    // Set up CA1 as a publisher
    {
        let publisher_request = publisher_request_krill2(&ca1).await;
        embedded_repo_add_publisher(publisher_request).await;

        // Get a Repository Response for the CA
        let response = embedded_repository_response(ca1.convert()).await;

        // Update the repo for the child
        repo_update_krill2(&ca1, response).await;
    }

    // Wait a bit so that CA1 can request a certificate from testbed
    assert!(ca_contains_resources_krill2(&ca1, &ca1_res).await);

    // Create a ROA for CA1
    {
        let mut updates = RoaConfigurationUpdates::empty();
        updates.add(ca1_route_definition.into());
        ca_route_authorizations_update_krill2(&ca1, updates).await;
    }

    // Verify that CA1 publishes
    {
        let mut expected_files =
            expected_mft_and_crl_krill2(&ca1, &rcn_0).await;
        expected_files
            .push(ObjectName::from(&ca1_route_definition).to_string());

        assert!(
            will_publish_embedded(
                "CA1 should publish manifest, crl and roa",
                &ca1,
                &expected_files
            )
            .await
        );
    }

    cleanup_krill_storage();
    cleanup_second_krill_storage();
    cleanup_logging();
}
