extern crate krill;

use std::fs;
use std::str::FromStr;

use bytes::Bytes;
use krill::commons::api::{Handle, ParentCaReq, ResourceSet};
use krill::daemon::ca::ta_handle;
use krill::test::*;

#[tokio::test]
/// Test that a Resource Tagged Attestation can be signed
async fn rta_signing() {
    let dir = start_krill().await;

    let ta_handle = ta_handle();
    let child = Handle::from_str("child").unwrap();
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

    // Now create the signed RTA
    let content = include_bytes!("../test-resources/test.tal");
    let content = Bytes::copy_from_slice(content);

    sign_one_off_rta(child.clone(), child_resources.clone(), content, None).await;

    let _ = fs::remove_dir_all(dir);
}
