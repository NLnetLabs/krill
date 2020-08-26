extern crate krill;

use std::fs;
use std::str::FromStr;
use krill::commons::api::{Handle, ObjectName, ParentCaReq, ResourceClassName, ResourceSet};
use krill::daemon::ca::ta_handle;
use krill::daemon::config::CONFIG;
use krill::test::*;

#[tokio::test]
/// Test that we can delegate from normal CAs to child CAs, and that these child CAs
/// can have multiple parents.
///
///                   TA
///                 /    \
///               CA1    CA2
///                 \    /
///                  CA3 (two resource classes)
///                  | |
///                  CA4 (two resource classes)
///
/// Also tests that everything is published properly.
async fn ca_grandchildren() {
    let dir = start_krill().await;

    let rcn_0 = ResourceClassName::from(0);
    let rcn_1 = ResourceClassName::from(1);

    // -------------------- TA -----------------------------------------------

    let ta_handle = ta_handle();

    let ta_key = ca_key_for_rcn(&ta_handle, &rcn_0).await;
    let ta_mft_file = ta_key.incoming_cert().mft_name().to_string();
    let ta_mft_file = ta_mft_file.as_str();
    let ta_crl_file = ta_key.incoming_cert().crl_name().to_string();
    let ta_crl_file = ta_crl_file.as_str();

    // -------------------- CA1 -----------------------------------------------
    let ca1 = Handle::from_str("CA1").unwrap();
    let ca1_res = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&ca1).await;
    let req = child_request(&ca1).await;
    let parent = {
        let contact = add_child_to_ta_rfc6492(&ca1, req, ca1_res.clone()).await;
        ParentCaReq::new(ta_handle.clone(), contact)
    };
    add_parent_to_ca(&ca1, parent).await;
    assert!(ca_gets_resources(&ca1, &ca1_res).await);

    let ca1_key = ca_key_for_rcn(&ca1, &rcn_0).await;
    let ca1_cert_file = ObjectName::from(ca1_key.incoming_cert().cert()).to_string();
    let ca1_cert_file = ca1_cert_file.as_str();
    let ca1_mft_file = ca1_key.incoming_cert().mft_name().to_string();
    let ca1_mft_file = ca1_mft_file.as_str();
    let ca1_crl_file = ca1_key.incoming_cert().crl_name().to_string();
    let ca1_crl_file = ca1_crl_file.as_str();

    // Check that the TA publishes the certificate
    let base_cert_files = if CONFIG.testbed_enabled {
        let testbed_ca_handle = Handle::from_str("testbed").unwrap();
        let testbed_ca = ca_details(&testbed_ca_handle).await;
        let testbed_ca_rc = testbed_ca.resource_classes().keys().next().unwrap();
        let testbed_ca_key = ca_key_for_rcn(&testbed_ca_handle, &testbed_ca_rc).await;
        vec!(ObjectName::from(testbed_ca_key.incoming_cert().cert()).to_string())
    } else {
        Vec::new()
    };
    let base_objects = base_cert_files.iter().map(|f| f.as_str()).collect::<Vec<&str>>();

    let mut expected_objects = vec!(ta_crl_file, ta_mft_file, ca1_cert_file);
    expected_objects.extend(&base_objects);
    assert!(will_publish_objects(&ta_handle, &expected_objects).await);

    // -------------------- CA2 -----------------------------------------------
    let ca2 = Handle::from_str("CA2").unwrap();
    let ca2_res = ResourceSet::from_strs("", "10.1.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&ca2).await;
    let req = child_request(&ca2).await;
    let parent = {
        let contact = add_child_to_ta_rfc6492(&ca2, req, ca2_res.clone()).await;
        ParentCaReq::new(ta_handle.clone(), contact)
    };
    add_parent_to_ca(&ca2, parent).await;
    assert!(ca_gets_resources(&ca2, &ca2_res).await);

    let ca2_key = ca_key_for_rcn(&ca2, &rcn_0).await;
    let ca2_cert_file = ObjectName::from(ca2_key.incoming_cert().cert()).to_string();
    let ca2_cert_file = ca2_cert_file.as_str();
    let ca2_mft_file = ca2_key.incoming_cert().mft_name().to_string();
    let ca2_mft_file = ca2_mft_file.as_str();
    let ca2_crl_file = ca2_key.incoming_cert().crl_name().to_string();
    let ca2_crl_file = ca2_crl_file.as_str();

    // Check that the TA publishes the certificate
    let mut expected_objects = vec!(ta_crl_file, ta_mft_file, ca1_cert_file, ca2_cert_file);
    expected_objects.extend(&base_objects);
    assert!(will_publish_objects(&ta_handle, &expected_objects).await);

    // -------------------- CA3 -----------------------------------------------
    let ca3 = Handle::from_str("CA3").unwrap();
    let ca_3_res_under_ca_1 = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

    init_child_with_embedded_repo(&ca3).await;
    let req = child_request(&ca3).await;
    let parent = {
        let contact = add_child_rfc6492(&ca1, &ca3, req, ca_3_res_under_ca_1.clone()).await;
        ParentCaReq::new(ca1.clone(), contact)
    };
    add_parent_to_ca(&ca3, parent).await;
    assert!(ca_gets_resources(&ca3, &ca_3_res_under_ca_1).await);

    let ca3_1_key = ca_key_for_rcn(&ca3, &rcn_0).await;
    let ca3_1_cert_file = ObjectName::from(ca3_1_key.incoming_cert().cert()).to_string();
    let ca3_1_cert_file = ca3_1_cert_file.as_str();
    let ca3_1_mft_file = ca3_1_key.incoming_cert().mft_name().to_string();
    let ca3_1_mft_file = ca3_1_mft_file.as_str();
    let ca3_1_crl_file = ca3_1_key.incoming_cert().crl_name().to_string();
    let ca3_1_crl_file = ca3_1_crl_file.as_str();

    // Check that CA1 publishes
    assert!(will_publish_objects(&ca1, &[ca1_mft_file, ca1_crl_file, ca3_1_cert_file]).await);

    let ca_3_res_under_ca_2 = ResourceSet::from_strs("", "10.1.0.0/24", "").unwrap();
    let ca_3_res = ca_3_res_under_ca_1.union(&ca_3_res_under_ca_2);
    let req = child_request(&ca3).await;
    let parent = {
        let contact = add_child_rfc6492(&ca2, &ca3, req, ca_3_res_under_ca_2).await;
        ParentCaReq::new(ca2.clone(), contact)
    };
    add_parent_to_ca(&ca3, parent).await;
    assert!(ca_gets_resources(&ca3, &ca_3_res).await);

    let ca3_2_key = ca_key_for_rcn(&ca3, &rcn_1).await;
    let ca3_2_cert_file = ObjectName::from(ca3_2_key.incoming_cert().cert()).to_string();
    let ca3_2_cert_file = ca3_2_cert_file.as_str();
    let ca3_2_mft_file = ca3_2_key.incoming_cert().mft_name().to_string();
    let ca3_2_mft_file = ca3_2_mft_file.as_str();
    let ca3_2_crl_file = ca3_2_key.incoming_cert().crl_name().to_string();
    let ca3_2_crl_file = ca3_2_crl_file.as_str();

    // Check that CA2 publishes
    assert!(will_publish_objects(&ca2, &[ca2_mft_file, ca2_crl_file, ca3_2_cert_file]).await);

    // -------------------- CA4 -----------------------------------------------
    let ca4 = Handle::from_str("CA4").unwrap();
    let ca_4_res_under_ca_3 = ResourceSet::from_strs("", "10.0.0.0-10.1.0.255", "").unwrap();

    init_child_with_embedded_repo(&ca4).await;
    let req = child_request(&ca4).await;
    let parent = {
        let contact = add_child_rfc6492(&ca3, &ca4, req, ca_4_res_under_ca_3.clone()).await;
        ParentCaReq::new(ca3.clone(), contact)
    };
    add_parent_to_ca(&ca4, parent).await;
    assert!(ca_gets_resources(&ca4, &ca_4_res_under_ca_3).await);

    let ca4_1_key = ca_key_for_rcn(&ca4, &rcn_0).await;
    let ca4_1_cert_file = ObjectName::from(ca4_1_key.incoming_cert().cert()).to_string();
    let ca4_1_cert_file = ca4_1_cert_file.as_str();
    let ca4_1_mft_file = ca4_1_key.incoming_cert().mft_name().to_string();
    let ca4_1_mft_file = ca4_1_mft_file.as_str();
    let ca4_1_crl_file = ca4_1_key.incoming_cert().crl_name().to_string();
    let ca4_1_crl_file = ca4_1_crl_file.as_str();

    let ca4_2_key = ca_key_for_rcn(&ca4, &rcn_1).await;
    let ca4_2_cert_file = ObjectName::from(ca4_2_key.incoming_cert().cert()).to_string();
    let ca4_2_cert_file = ca4_2_cert_file.as_str();
    let ca4_2_mft_file = ca4_2_key.incoming_cert().mft_name().to_string();
    let ca4_2_mft_file = ca4_2_mft_file.as_str();
    let ca4_2_crl_file = ca4_2_key.incoming_cert().crl_name().to_string();
    let ca4_2_crl_file = ca4_2_crl_file.as_str();

    // Check that CA3 publishes both certs in its two resource classes
    assert!(
        will_publish_objects(
            &ca3,
            &[
                ca3_1_mft_file,
                ca3_1_crl_file,
                ca4_1_cert_file,
                ca3_2_mft_file,
                ca3_2_crl_file,
                ca4_2_cert_file,
            ],
        )
        .await
    );

    // Check that CA4 publishes two resource classes, with only crls and mfts
    assert!(will_publish_objects(&ca4, &[ca4_1_mft_file, ca4_1_crl_file, ca4_2_mft_file, ca4_2_crl_file,],).await);

    let _ = fs::remove_dir_all(dir);
}
