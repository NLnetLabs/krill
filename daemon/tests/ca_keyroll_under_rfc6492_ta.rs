extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;
extern crate krill_pubc;

use krill_commons::api::admin::{AddParentRequest, Handle, Token};
use krill_commons::api::ca::ResourceSet;
use krill_daemon::ca::ta_handle;
use krill_daemon::test::*;

#[test]
fn ca_keyroll_under_rfc6492_ta() {
    test_with_krill_server(|_d| {
        let ta_handle = ta_handle();
        init_ta();

        let child = Handle::from("rfc6492");
        let child_token = Token::from("rfc6492");
        let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&child, &child_token);
        let req = child_request(&child);

        // RFC6492 parent --------------------------------------------------------------------
        let parent = {
            let contact = add_child_to_ta_rfc6492(&child, req, child_resources.clone());
            AddParentRequest::new(ta_handle.clone(), contact)
        };

        add_parent_to_ca(&child, parent);
        wait_for_current_resources(&child, &child_resources);
        wait_for_ta_to_have_number_of_issued_certs(1);

        ca_roll_init(&child);
        wait_for_new_key(&child);
        wait_for_ta_to_have_number_of_issued_certs(2);

        ca_roll_activate(&child);
        wait_for_key_roll_complete(&child);
        wait_for_ta_to_have_number_of_issued_certs(1);
    });
}
