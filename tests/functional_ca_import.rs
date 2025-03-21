//! Test importing a CA.

mod common;


//------------ Test Function -------------------------------------------------

#[cfg(not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11")))]
#[tokio::test]
async fn functional_ca_import() {
    let (mut config, _tempdir) = common::TestConfig::mem_storage().finalize();
    config.ta_support_enabled = true;
    config.ta_signer_enabled = true;
    let server = common::KrillServer::start_with_config(config).await;

    eprintln!(">>>> Import CA structure.");
    // We expect:
    //
    //        TA
    //        |
    //      parent
    //      /    \
    //   child1  child2
    //      \    /
    //     grandchild (two parents)
    //
    let rc0 = common::rcn(0);
    let rc1 = common::rcn(1);

    let ca_imports_json =
        include_str!("../test-resources/bulk-ca-import/structure.json");
    let ca_imports: krill::api::import::Structure =
        serde_json::from_str(ca_imports_json).unwrap();

    let parent = common::ca_handle("parent");
    let parent_resources = common::resources(
        "AS65000-AS65535", "10.0.0.0/8, 192.168.0.0/16", "fc00::/7",
    );

    let child1 = common::ca_handle("child1");
    let child1_resources = common::resources(
        "AS65000", "192.168.0.0/16", "fc00::/56"
    );
    let child1_roas = vec![
        common::roa_conf("192.168.0.0/23-24 => 65000 # my precious route"),
        common::roa_conf("192.168.2.0/23 => 65001"),
        common::roa_conf("fc00::/56 => 65000"),
    ];

    let child2 = common::ca_handle("child2");
    let child2_resources = common::resources("AS65001", "10.0.0.0/16", "");

    let grandchild = common::ca_handle("grandchild");
    let grandchild_resources = common::resources(
        "AS65001", "10.0.0.0/24, 192.168.0.0/24", ""
    );
    let grandchild_roas = [
        common::roa_conf("192.168.0.0/24 => 65000"),
        common::roa_conf("10.0.0.0/24 => 65001"),
    ];

    server.client().bulk_import(ca_imports).await.unwrap();


    eprintln!(">>>> Check 'parent'.");
    assert!(server.wait_for_ca_resources(&parent, &parent_resources).await);

    eprintln!(">>>> Check 'child1'.");
    // resources
    assert!(server.wait_for_ca_resources(&child1, &child1_resources).await);
    // ROAs
    assert!(server.check_configured_roas(&child1, &child1_roas).await);
    // Published objects, including cer for grandchild.
    let mut files = server.expected_objects(&child1);
    files.push_mft_and_crl(&rc0).await;
    files.push_cer(&grandchild, &rc0).await;
    files.push_roas(&child1_roas);
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Check 'child2'.");
    // resources
    assert!(server.wait_for_ca_resources(&child2, &child2_resources).await);
    // no ROAs
    // Published objects, including cer for grandchild in RC1.
    let mut files = server.expected_objects(&child2);
    files.push_mft_and_crl(&rc0).await;
    files.push_cer(&grandchild, &rc1).await;
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Check 'grandchild'.");
    // resources
    assert!(
        server.wait_for_ca_resources(&grandchild, &grandchild_resources).await
    );
    // configured ROAs
    assert!(server.check_configured_roas(&grandchild, &grandchild_roas).await);
    // publish objects in rc0 under parent child1
    // publish objects in rc1 under parent child2
    let mut files = server.expected_objects(&grandchild);
    files.push_mft_and_crl(&rc0).await;
    files.push_mft_and_crl(&rc1).await;
    files.push_roas(&grandchild_roas);
    assert!(files.wait_for_published().await);
}

