extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;
extern crate krill_pubc;

use std::str::FromStr;

use krill_commons::api::admin::{AddParentRequest, Handle, Token};
use krill_commons::api::ca::ResourceSet;
use krill_commons::api::{RouteAuthorization, RouteAuthorizationUpdates};
use krill_daemon::ca::ta_handle;
use krill_daemon::test::*;

#[test]
fn ca_roas() {
    test_with_krill_server(|_d| {
        let child = Handle::from("child");
        let child_token = Token::from("child");
        let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&child, &child_token);

        // Set up under parent  ----------------------------------------------------------------
        {
            init_ta();
            let parent = {
                let parent_contact = add_child_to_ta_embedded(&child, child_resources.clone());
                AddParentRequest::new(ta_handle(), parent_contact)
            };
            add_parent_to_ca(&child, parent);
            wait_for_current_resources(&child, &child_resources);
        }

        let mut updates = RouteAuthorizationUpdates::empty();
        updates.add(RouteAuthorization::from_str("10.0.0.0/24 => 64496").unwrap());
        updates.add(RouteAuthorization::from_str("10.0.1.0/24 => 64496").unwrap());
        ca_route_authorizations_update(&child, updates);

        let mut updates = RouteAuthorizationUpdates::empty();
        updates.remove(RouteAuthorization::from_str("10.0.1.0/24 => 64496").unwrap());
        ca_route_authorizations_update(&child, updates);

        // TODO: Check that repository content, and validate! ..and check CRL for revoke of ROA
    });
}
