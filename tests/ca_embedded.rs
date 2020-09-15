#![type_length_limit = "5000000"]

extern crate krill;

use std::fs;
use std::str::FromStr;

use krill::commons::api::{Handle, ParentCaReq, ResourceSet};
use krill::daemon::ca::ta_handle;
use krill::daemon::config::CONFIG;
use krill::test::*;

#[tokio::test]
async fn ca_embedded() {
    let dir = start_krill().await;

    let ta_handle = ta_handle();

    let child = Handle::from_str("child").unwrap();
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&child).await;

    let base_cert_count = if CONFIG.testbed_enabled { 1 } else { 0 };

    // Embedded parent --------------------------------------------------------------------
    let parent = {
        let parent_contact = add_child_to_ta_embedded(&child, child_resources.clone()).await;
        ParentCaReq::new(ta_handle.clone(), parent_contact)
    };

    // When the parent is added, a child CA will immediately request a certificate.
    add_parent_to_ca(&child, parent).await;
    assert!(ca_gets_resources(&child, &child_resources).await);
    assert!(ta_will_have_issued_n_certs(base_cert_count+1).await);

    // When the parent adds resources to a CA, it can request a new resource certificate.
    let new_child_resources = ResourceSet::from_strs("AS65000", "10.0.0.0/16", "").unwrap();
    update_child(&ta_handle, &child, &new_child_resources).await;
    assert!(ca_gets_resources(&child, &new_child_resources).await);
    assert!(ta_will_have_issued_n_certs(base_cert_count+1).await);

    // When the removes child resources, the child will get a reduced certificate when it syncs.
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/24", "").unwrap();
    update_child(&ta_handle, &child, &child_resources).await;
    assert!(ca_gets_resources(&child, &child_resources).await);

    // When all resources are removed, the child will request that its certificate is revoked,
    // and remove the resource class.
    let child_resources = ResourceSet::default();
    update_child(&ta_handle, &child, &child_resources).await;
    assert!(rc_is_removed(&child).await);
    assert!(ta_will_have_issued_n_certs(base_cert_count).await);

    let _ = fs::remove_dir_all(dir);
}
