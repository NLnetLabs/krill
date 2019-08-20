extern crate krill_client;
extern crate krill_commons;
extern crate krill_daemon;
extern crate krill_pubc;

use krill_commons::api::admin::{AddParentRequest, Handle, Token};
use krill_commons::api::ca::ResourceSet;
use krill_daemon::ca::ta_handle;
use krill_daemon::test::*;

#[test]
fn grand_children() {
    test_with_krill_server(|_d| {
        // Test that we can delegate from normal CAs to child CAs, and that these child CAs
        // can have multiple parents.
        //
        //                   TA
        //                 /    \
        //               CA1    CA2
        //                 \    /
        //                   CA3 (two resource classes)
        //                   | |
        //                   CA4 (two resource classes)
        //

        // -------------------- TA -----------------------------------------------

        let ta_handle = ta_handle();
        init_ta();

        // -------------------- CA1 -----------------------------------------------
        let ca1 = Handle::from("CA1");
        let ca1_res = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&ca1, &Token::from("CA1"));
        let req = child_request(&ca1);
        let parent = {
            let contact = add_child_to_ta_rfc6492(&ca1, req, ca1_res.clone());
            AddParentRequest::new(ta_handle.clone(), contact)
        };
        add_parent_to_ca(&ca1, parent);
        wait_for_current_resources(&ca1, &ca1_res);

        // -------------------- CA2 -----------------------------------------------
        let ca2 = Handle::from("CA2");
        let ca2_res = ResourceSet::from_strs("", "10.1.0.0/16", "").unwrap();

        init_child(&ca2, &Token::from("CA2"));
        let req = child_request(&ca2);
        let parent = {
            let contact = add_child_to_ta_rfc6492(&ca2, req, ca2_res.clone());
            AddParentRequest::new(ta_handle.clone(), contact)
        };
        add_parent_to_ca(&ca2, parent);
        wait_for_current_resources(&ca2, &ca2_res);

        // -------------------- CA3 -----------------------------------------------
        let ca3 = Handle::from("CA3");
        let ca_3_res_under_ca_1 = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&ca3, &Token::from("CA3"));
        let req = child_request(&ca3);
        let parent = {
            let contact = add_child_rfc6492(&ca1, &ca3, req, ca_3_res_under_ca_1.clone());
            AddParentRequest::new(ca1.clone(), contact)
        };
        add_parent_to_ca(&ca3, parent);
        wait_for_current_resources(&ca3, &ca_3_res_under_ca_1);

        let ca_3_res_under_ca_2 = ResourceSet::from_strs("", "10.1.0.0/24", "").unwrap();
        let ca_3_res = ca_3_res_under_ca_1.union(&ca_3_res_under_ca_2);
        let req = child_request(&ca3);
        let parent = {
            let contact = add_child_rfc6492(&ca2, &ca3, req, ca_3_res_under_ca_2.clone());
            AddParentRequest::new(ca2.clone(), contact)
        };
        add_parent_to_ca(&ca3, parent);
        wait_for_current_resources(&ca3, &ca_3_res);

        // -------------------- CA4 -----------------------------------------------
        let ca4 = Handle::from("CA4");
        let ca_4_res_under_ca_3 = ResourceSet::from_strs("", "10.0.0.0-10.1.0.255", "").unwrap();

        init_child(&ca4, &Token::from("CA4"));
        let req = child_request(&ca4);
        let parent = {
            let contact = add_child_rfc6492(&ca3, &ca4, req, ca_4_res_under_ca_3.clone());
            AddParentRequest::new(ca3.clone(), contact)
        };
        add_parent_to_ca(&ca4, parent);
        wait_for_current_resources(&ca4, &ca_4_res_under_ca_3);
    });
}
