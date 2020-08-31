#![type_length_limit = "1500000"]

extern crate krill;

use std::fs;

use krill::commons::api::{Handle, ParentCaReq, ResourceSet};
use krill::daemon::ca::ta_handle;
use krill::test::*;

#[tokio::test]
async fn ca_rfc6492() {
    let dir = start_krill().await;
    let ta_handle = ta_handle();

    let child = unsafe { Handle::from_str_unsafe("rfc6492") };
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&child).await;

    // Add child to parent (ta)
    let parent = {
        let req = child_request(&child).await;
        let contact = add_child_to_ta_rfc6492(&child, req, child_resources.clone()).await;
        ParentCaReq::new(ta_handle.clone(), contact)
    };

    // When the parent is added, a child CA will immediately request a certificate.
    add_parent_to_ca(&child, parent).await;
    assert!(ca_gets_resources(&child, &child_resources).await);
    assert!(ta_will_have_issued_n_certs(1).await);

    // When the parent adds resources to a CA, it can request a new resource certificate.
    let new_child_resources = ResourceSet::from_strs("AS65000", "10.0.0.0/16", "").unwrap();
    update_child(&ta_handle, &child, &new_child_resources).await;
    assert!(ca_gets_resources(&child, &new_child_resources).await);
    assert!(ta_will_have_issued_n_certs(1).await);

    // When the removes child resources, the child will get a reduced certificate when it syncs.
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/24", "").unwrap();
    update_child(&ta_handle, &child, &child_resources).await;
    assert!(ca_gets_resources(&child, &child_resources).await);

    // When all resources are removed, the child will request that its certificate is revoked,
    // and remove the resource class.
    let child_resources = ResourceSet::default();
    update_child(&ta_handle, &child, &child_resources).await;
    assert!(rc_is_removed(&child).await);
    assert!(ta_will_have_issued_n_certs(0).await);

    // Update the ID of the parent, and therefore tell child as well
    generate_new_id(&ta_handle).await;
    let contact = parent_contact(&ta_handle, &child).await;
    update_parent_contact(&child, &ta_handle, contact).await;

    // The child should be able to get updated resources again
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/24", "").unwrap();
    update_child(&ta_handle, &child, &child_resources).await;
    assert!(ca_gets_resources(&child, &child_resources).await);

    // Update the ID of the child, and tell parent
    generate_new_id(&child).await;
    let req = child_request(&child).await;
    update_child_id(&ta_handle, &child, req).await;

    // The child should be able to get updated resources again
    let child_resources = ResourceSet::from_strs("AS65000", "10.0.0.0/16", "").unwrap();
    update_child(&ta_handle, &child, &child_resources).await;
    assert!(ca_gets_resources(&child, &child_resources).await);

    // Remove parent
    delete_parent(&child, &ta_handle).await;
    will_publish_objects(&child, &[]).await; // should withdraw everything

    // Remove child
    delete_child(&ta_handle, &child).await;
    assert!(ta_will_have_issued_n_certs(0).await);

    // Can now add child again
    let parent = {
        let req = child_request(&child).await;
        let contact = add_child_to_ta_rfc6492(&child, req, child_resources.clone()).await;
        ParentCaReq::new(ta_handle, contact)
    };

    // And can add the parent back to the child, and it will request resources again.
    add_parent_to_ca(&child, parent).await;
    assert!(ca_gets_resources(&child, &child_resources).await);
    assert!(ta_will_have_issued_n_certs(1).await);

    let _ = fs::remove_dir_all(dir);
}
