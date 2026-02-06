//! Tests grandchild resources updated.

use krill::api;
use rpki::repository::resources::ResourceSet;

use crate::common::sleep_seconds;

mod common;


//------------ Test Function -------------------------------------------------

/// Test Krill parent/child/grandchild interactions.
/// 
/// The setup is:
///
/// ```text
///       TA
///        |
///      parent
///        |
///      child
///        |
///    grandchild
/// ```
///
/// The test verifies that:
///  * Grandchild gets the resources from child,
///  * Parent can restrict the resources on child,
///  * Grandchild will learn about those resource changes and adjust the 
///  effective resources accordingly

#[tokio::test]
async fn functional_resource_updates() {
    let (server, _tmpdir)
        = common::KrillServer::start_with_file_storage_and_testbed().await;

    let testbed = common::ca_handle("testbed");

    let ca_parent = common::ca_handle("parent");
    let ca_parent_res = common::resources("AS65000", "10.0.0.0/16", "");

    let ca_child = common::ca_handle("child");
    let ca_child_res = common::resources("AS65000", "10.0.0.0/16", "");

    let ca_grandchild = common::ca_handle("grandchild");
    let ca_grandchild_res = common::resources("AS65000", "10.0.0.0/23", "");

    let rcn0 = common::rcn(0);

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up CA parent under testbed.");
    server.create_ca_with_repo(&ca_parent).await;
    server.register_ca_with_parent(&ca_parent, &testbed, &ca_parent_res).await;

    eprintln!(">>>> Set up CA child under parent.");
    server.create_ca_with_repo(&ca_child).await;
    server.register_ca_with_parent(&ca_child, &ca_parent, &ca_child_res).await;

    eprintln!(">>>> Set up CA grandchild under child.");
    server.create_ca_with_repo(&ca_grandchild).await;
    server.register_ca_with_parent(&ca_grandchild, &ca_child, &ca_grandchild_res).await;

    eprintln!(">>>> Expect that CA child publishes the certificate for CA grandchild.");
    let mut files = server.expected_objects(&ca_child);
    files.push_mft_and_crl(&rcn0).await;
    files.push_cer(&ca_grandchild, &rcn0).await;
    assert!(files.wait_for_published().await);

    sleep_seconds(3).await;

    eprintln!(">>>> Update resources given to the child.");
    let ca_child_new_res = common::resources("65000", "10.0.0.0/24", "");
    let ca_grandchild_new_res = 
        ca_grandchild_res.clone().intersection(&ca_child_new_res);
    eprintln!("New resources: {}", &ca_grandchild_new_res);
    server.client().child_update(
        &ca_parent, 
        &ca_child.convert(), 
        api::admin::UpdateChildRequest::resources(ca_child_new_res.clone())
    ).await.unwrap();
    assert!(server.wait_for_ca_resources(&ca_child, &ca_child_new_res).await);

    // Wait before the child gets aware of the new resources
    sleep_seconds(3).await;

    eprintln!(">>>> Check new resources given to the child.");
    assert_eq!(
        server.client().ca_details(&ca_child).await.unwrap().resources,
        ca_child_new_res.clone()
    );
    // We want the 'parent' and 'child' to agree on the new resources.
    // i.e. that the 'child' learnt that the new resource set it smaller.
    assert_eq!(
        server.client().ca_details(&ca_child).await.unwrap().resources,
        server.client().child_details(
            &ca_parent, &ca_child.convert()
        ).await.unwrap().entitled_resources,
    );

    sleep_seconds(3).await;

    eprintln!(">>>> Check resources updated on grandchild.");
    // We do not want the 'child' to update the entitled resources of the
    // 'grandchild'. The resources of the grandchild will shrink automatically
    // and grow again when the child gets more resources again.
    // This checks the entitled resources have not changed.
    assert_eq!(
        server.client().child_details(
            &ca_child, &ca_grandchild.convert()
        ).await.unwrap().entitled_resources,
        ca_grandchild_res.clone()
    );
    // We do want 'grandchild' to learn of the effective resources after 
    // shrinking.
    assert_ne!(
        server.client().ca_details(&ca_grandchild).await.unwrap().resources,
        ca_grandchild_res.clone()
    );
    assert_eq!(
        server.client().ca_details(&ca_grandchild).await.unwrap().resources,
        ca_grandchild_new_res.clone()
    );

    eprintln!(">>>> Revert the resources given to the child.");
    server.client().child_update(
        &ca_parent, 
        &ca_child.convert(), 
        api::admin::UpdateChildRequest::resources(ca_child_res.clone())
    ).await.unwrap();
    assert!(server.wait_for_ca_resources(&ca_child, &ca_child_new_res).await);

    sleep_seconds(3).await;

    // Everything should be back to the original state again
    assert_eq!(
        server.client().ca_details(&ca_child).await.unwrap().resources,
        ca_child_res.clone()
    );
    assert_eq!(
        server.client().child_details(
            &ca_child, &ca_grandchild.convert()
        ).await.unwrap().entitled_resources,
        ca_grandchild_res.clone()
    );
    assert_eq!(
        server.client().ca_details(&ca_grandchild).await.unwrap().resources,
        ca_grandchild_res.clone()
    );
}
