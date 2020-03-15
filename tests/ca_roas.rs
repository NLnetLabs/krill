extern crate krill;

use std::str::FromStr;

use krill::commons::api::{
    Handle, ObjectName, ParentCaReq, ResourceSet, RoaDefinition, RoaDefinitionUpdates,
};
use krill::daemon::ca::ta_handle;
use krill::daemon::test::*;
use std::fs;

#[tokio::test]
/// Test the CAs can issue and publish ROAs for their resources, and that
/// ROAs get updated and published properly when resources change, as well
/// as during and after key rolls.
async fn ca_roas() {
    let dir = start_krill().await;

    let ta_handle = ta_handle();
    let child = Handle::from_str_unsafe("child");
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "2001:DB8::/32").unwrap();

    init_child_with_embedded_repo(&child).await;

    // Set up under parent  ----------------------------------------------------------------
    {
        let parent = {
            let parent_contact = add_child_to_ta_embedded(&child, child_resources.clone()).await;
            ParentCaReq::new(ta_handle.clone(), parent_contact)
        };
        add_parent_to_ca(&child, parent).await;
        assert!(ca_gets_resources(&child, &child_resources).await);
    }

    // Add some Route Authorizations
    let route_1 = RoaDefinition::from_str("10.0.0.0/24 => 64496").unwrap();
    let route_2 = RoaDefinition::from_str("2001:DB8::/32-48 => 64496").unwrap();
    let route_3 = RoaDefinition::from_str("192.168.0.0/24 => 64496").unwrap();

    let crl_file = ".crl";
    let mft_file = ".mft";
    let route1_file = ObjectName::from(&route_1).to_string();
    let route1_file = route1_file.as_str();
    let route2_file = ObjectName::from(&route_2).to_string();
    let route2_file = route2_file.as_str();
    let route3_file = ObjectName::from(&route_3).to_string();
    let route3_file = route3_file.as_str();

    let mut updates = RoaDefinitionUpdates::empty();
    updates.add(route_1);
    updates.add(route_2);
    ca_route_authorizations_update(&child, updates).await;
    will_publish_objects(&child, &[crl_file, mft_file, route1_file, route2_file]).await;

    // Remove a Route Authorization
    let mut updates = RoaDefinitionUpdates::empty();
    updates.remove(route_1);
    ca_route_authorizations_update(&child, updates).await;
    will_publish_objects(&child, &[crl_file, mft_file, route2_file]).await;

    // Refuse authorization for prefix not held by CA
    let mut updates = RoaDefinitionUpdates::empty();
    updates.add(route_3);
    ca_route_authorizations_update_expect_error(&child, updates).await;

    // Shrink resources and see that ROA is removed
    let child_resources = ResourceSet::from_strs("", "192.168.0.0/16", "").unwrap();
    update_child(&ta_handle, &child, &child_resources).await;
    will_publish_objects(&child, &[crl_file, mft_file]).await;

    // Now route3 can be added
    let mut updates = RoaDefinitionUpdates::empty();
    updates.add(route_3);
    ca_route_authorizations_update(&child, updates).await;
    will_publish_objects(&child, &[crl_file, mft_file, route3_file]).await;

    // And route3 should remain there during a roll.
    ca_roll_init(&child).await;
    rc_state_becomes_new_key(&child).await;
    will_publish_objects(
        &child,
        &[crl_file, mft_file, crl_file, mft_file, route3_file],
    )
    .await;

    ca_roll_activate(&child).await;
    rc_state_becomes_active(&child).await;
    will_publish_objects(&child, &[crl_file, mft_file, route3_file]).await;

    let route_invalid_length = RoaDefinition::from_str("10.0.0.0/24-33 => 64496").unwrap();
    let mut updates = RoaDefinitionUpdates::empty();
    updates.add(route_invalid_length);
    ca_route_authorizations_update_expect_error(&child, updates).await;

    let _ = fs::remove_dir_all(dir);
}
