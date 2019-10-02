extern crate krill;

use krill::commons::api::{AddParentRequest, Handle, ResourceSet, Token};
use krill::daemon::ca::ta_handle;
use krill::daemon::test::*;

#[test]
fn ca_under_rfc6492_ta() {
    test_with_krill_server(|_d| {
        let ta_handle = ta_handle();

        let child = Handle::from_str_unsafe("rfc6492");
        let child_token = Token::from("rfc6492");
        let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&child, &child_token);
        let req = child_request(&child);

        // RFC6492 parent --------------------------------------------------------------------
        let parent = {
            let contact = add_child_to_ta_rfc6492(&child, req, child_resources.clone());
            AddParentRequest::new(ta_handle.clone(), contact)
        };

        // When the parent is added, a child CA will immediately request a certificate.
        add_parent_to_ca(&child, parent);
        wait_for_current_resources(&child, &child_resources);
        wait_for_ta_to_have_number_of_issued_certs(1);

        // When the parent adds resources to a CA, it can request a new resource certificate.
        let new_child_resources = ResourceSet::from_strs("AS65000", "10.0.0.0/16", "").unwrap();
        update_child(&child, &new_child_resources);
        wait_for_current_resources(&child, &new_child_resources);
        wait_for_ta_to_have_number_of_issued_certs(1);
        assert_eq!(ta_issued_resources(&child), new_child_resources);

        // When the removes child resources, the child will get a reduced certificate when it syncs.
        let child_resources = ResourceSet::from_strs("", "10.0.0.0/24", "").unwrap();
        update_child(&child, &child_resources);
        wait_for_current_resources(&child, &child_resources);
        assert_eq!(ta_issued_resources(&child), child_resources);

        // When all resources are removed, the child will request that its certificate is revoked,
        // and remove the resource class.
        let child_resources = ResourceSet::default();
        update_child(&child, &child_resources);
        wait_for_resource_class_to_disappear(&child);
        wait_for_ta_to_have_number_of_issued_certs(0);
    });
}
