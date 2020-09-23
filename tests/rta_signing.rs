#![type_length_limit = "5000000"]

extern crate krill;

#[tokio::test]
#[cfg(feature = "functional-tests")]
/// Test that a Resource Tagged Attestation can be signed
async fn rta_signing() {
    use std::fs;
    use std::str::FromStr;

    use bytes::Bytes;
    use krill::commons::api::{Handle, ParentCaReq, ResourceSet, RtaList};
    use krill::daemon::ca::ta_handle;
    use krill::test::*;

    let dir = start_krill().await;

    let ta_handle = ta_handle();

    // We are going to need two CAs for co-signed RTA, meet Alice and Bob

    let alice = Handle::from_str("alice").unwrap();
    let alice_resources = ResourceSet::from_strs("", "10.0.0.0/16", "2001:DB8::/32").unwrap();

    init_child_with_embedded_repo(&alice).await;

    // Set up under parent  ----------------------------------------------------------------
    {
        let parent = {
            let parent_contact = add_child_to_ta_embedded(&alice, alice_resources.clone()).await;
            ParentCaReq::new(ta_handle.clone(), parent_contact)
        };
        add_parent_to_ca(&alice, parent).await;
        assert!(ca_gets_resources(&alice, &alice_resources).await);
    }

    let bob = Handle::from_str("bob").unwrap();
    let bob_resources = ResourceSet::from_strs("", "192.168.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&bob).await;

    // Set up under parent  ----------------------------------------------------------------
    {
        let parent = {
            let parent_contact = add_child_to_ta_embedded(&bob, bob_resources.clone()).await;
            ParentCaReq::new(ta_handle.clone(), parent_contact)
        };
        add_parent_to_ca(&bob, parent).await;
        assert!(ca_gets_resources(&bob, &bob_resources).await);
    }

    //---------------------------------------------------------------------------------------
    // Single Signed RTA
    //---------------------------------------------------------------------------------------

    let content = include_bytes!("../test-resources/test.tal");
    let content = Bytes::copy_from_slice(content);

    let rta_single = "rta_single".to_string();

    rta_sign_sign(
        alice.clone(),
        rta_single.clone(),
        alice_resources.clone(),
        vec![],
        content.clone(),
    )
    .await;

    let rta_list = rta_list(alice.clone()).await;
    assert_eq!(rta_list, RtaList::new(vec![rta_single.clone()]));

    let _single_rta = rta_show(alice.clone(), rta_single).await;

    //---------------------------------------------------------------------------------------
    // Multi Signed RTA
    //---------------------------------------------------------------------------------------

    // prepare multi-signed RTA
    let multi_resources = ResourceSet::from_strs("", "10.0.0.0/16, 192.168.0.0/16", "2001:DB8::/32").unwrap();
    let multi_rta_name = "multi_rta".to_string();

    // Alice prepares, so that Bob can include her keys
    let alice_prep = rta_multi_prep(alice.clone(), multi_rta_name.clone(), multi_resources.clone()).await;

    rta_sign_sign(
        bob.clone(),
        multi_rta_name.clone(),
        multi_resources.clone(),
        alice_prep.into(),
        content,
    )
    .await;

    let multi_rta_bob = rta_show(bob, multi_rta_name.clone()).await;

    rta_multi_cosign(alice.clone(), multi_rta_name.clone(), multi_rta_bob).await;

    let _multi_signed = rta_show(alice, multi_rta_name).await;

    let _ = fs::remove_dir_all(dir);
}
