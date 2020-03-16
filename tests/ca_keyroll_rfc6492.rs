extern crate krill;

use std::fs;

use krill::commons::api::{Handle, ParentCaReq, ResourceSet};
use krill::daemon::ca::ta_handle;
use krill::test::*;

#[tokio::test]
async fn ca_keyroll_rfc6492() {
    let dir = start_krill().await;

    let ta_handle = ta_handle();

    let child = Handle::from_str_unsafe("rfc6492");
    let child_resources = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&child).await;
    let req = child_request(&child).await;

    // RFC6492 parent --------------------------------------------------------------------
    let parent = {
        let contact = add_child_to_ta_rfc6492(&child, req, child_resources.clone()).await;
        ParentCaReq::new(ta_handle, contact)
    };

    add_parent_to_ca(&child, parent).await;
    assert!(ca_gets_resources(&child, &child_resources).await);
    assert!(ta_will_have_issued_n_certs(1).await);

    ca_roll_init(&child).await;
    assert!(rc_state_becomes_new_key(&child).await);
    assert!(ta_will_have_issued_n_certs(2).await);

    ca_roll_activate(&child).await;
    assert!(rc_state_becomes_active(&child).await);
    assert!(ta_will_have_issued_n_certs(1).await);

    let _ = fs::remove_dir_all(dir);
}
