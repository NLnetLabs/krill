extern crate krill;

use std::str::FromStr;

use krill::commons::api::{
    Handle, ObjectName, ParentCaReq, ResourceSet, RoaDefinition, RoaDefinitionUpdates,
};
use krill::daemon::ca::ta_handle;
use krill::daemon::test::*;

#[test]
/// Test the CAs can issue and publish ROAs for their resources, and that
/// ROAs get updated and published properly when resources change, as well
/// as during and after key rolls.
fn ca_roas() {
    test_with_krill_server(|_d| {
        let ta_handle = ta_handle();
        let child = Handle::from_str_unsafe("child");
        let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "2001:DB8::/32").unwrap();

        init_child_with_embedded_repo(&child);

        // Set up under parent  ----------------------------------------------------------------
        {
            let parent = {
                let parent_contact = add_child_to_ta_embedded(&child, child_resources.clone());
                ParentCaReq::new(ta_handle.clone(), parent_contact)
            };
            add_parent_to_ca(&child, parent);
            wait_for_current_resources(&child, &child_resources);
        }

        // Add some Route Authorizations
        let route_1 = RoaDefinition::from_str("10.0.0.0/24 => 64496").unwrap();
        let route_2 = RoaDefinition::from_str("2001:DB8::/32-48 => 64496").unwrap();
        let route_3 = RoaDefinition::from_str("192.168.0.0/24 => 64496").unwrap();

        let crl_file = ".crl";
        let mft_file = ".mft";
        let route1_file = ObjectName::from(&route_1).to_string();
        let route1_file = route1_file.as_str();
        let route2_file = ObjectName::from(&route_2).to_string();;
        let route2_file = route2_file.as_str();
        let route3_file = ObjectName::from(&route_3).to_string();
        let route3_file = route3_file.as_str();

        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_1);
        updates.add(route_2);
        ca_route_authorizations_update(&child, updates);
        wait_for_published_objects(&child, &[crl_file, mft_file, route1_file, route2_file]);

        // Remove a Route Authorization
        let mut updates = RoaDefinitionUpdates::empty();
        updates.remove(route_1);
        ca_route_authorizations_update(&child, updates);
        wait_for_published_objects(&child, &[crl_file, mft_file, route2_file]);

        // Refuse authorization for prefix not held by CA
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_3);
        ca_route_authorizations_update_expect_error(&child, updates);

        // Shrink resources and see that ROA is removed
        let child_resources = ResourceSet::from_strs("", "192.168.0.0/16", "").unwrap();
        update_child(&ta_handle, &child, &child_resources);
        wait_for_published_objects(&child, &[crl_file, mft_file]);

        // Now route3 can be added
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_3);
        ca_route_authorizations_update(&child, updates);
        wait_for_published_objects(&child, &[crl_file, mft_file, route3_file]);

        // And route3 should remain there during a roll.
        ca_roll_init(&child);
        wait_for_new_key(&child);
        wait_for_published_objects(
            &child,
            &[crl_file, mft_file, crl_file, mft_file, route3_file],
        );

        ca_roll_activate(&child);
        wait_for_key_roll_complete(&child);
        wait_for_published_objects(&child, &[crl_file, mft_file, route3_file]);

        let route_invalid_length = RoaDefinition::from_str("10.0.0.0/24-33 => 64496").unwrap();
        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(route_invalid_length);
        ca_route_authorizations_update_expect_error(&child, updates);
    });
}
