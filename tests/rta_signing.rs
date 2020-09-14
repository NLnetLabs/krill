#![type_length_limit = "5000000"]

extern crate krill;

use std::fs;
use std::str::FromStr;

use bytes::Bytes;
use krill::commons::api::{Handle, ParentCaReq, ResourceSet, RtaList};
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

    //---------------------------------------------------------------------------------------
    // Single Signed RTA
    //---------------------------------------------------------------------------------------

    let content = include_bytes!("../test-resources/test.tal");
    let content = Bytes::copy_from_slice(content);

    let rta_single = "rta_single".to_string();

    rta_sign_single(child.clone(), rta_single.clone(), child_resources.clone(), content).await;

    let rta_list = rta_list(child.clone()).await;
    assert_eq!(rta_list, RtaList::new(vec![rta_single.clone()]));

    let _single_rta = rta_show(child.clone(), rta_single).await;

    //---------------------------------------------------------------------------------------
    // Multi Signed RTA
    //---------------------------------------------------------------------------------------

    // prepare multi-signed RTA
    let multi_resources = ResourceSet::from_strs("", "10.0.0.0/16", "2001:DB8::/32").unwrap();

    let multi_v4 = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();
    let multi_v4_rta_name = "multi_v4".to_string();
    let multi_v4_prep_res = rta_multi_prep(child.clone(), multi_v4_rta_name.clone(), multi_v4).await;

    let _ = fs::remove_dir_all(dir);
}
