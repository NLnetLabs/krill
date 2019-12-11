extern crate krill;

use krill::commons::api::{Handle, ObjectName, ParentCaReq, ResourceClassName, ResourceSet};
use krill::daemon::ca::ta_handle;
use krill::daemon::test::*;

#[test]
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
#[ignore]
fn ca_grandchildren() {
    test_with_krill_server(|_d| {
        let rcn_0 = ResourceClassName::from(0);
        let rcn_1 = ResourceClassName::from(1);

        // -------------------- TA -----------------------------------------------

        let ta_handle = ta_handle();

        let ta_key = ca_key_for_rcn(&ta_handle, &rcn_0);
        let ta_mft_file = ta_key.incoming_cert().mft_name().to_string();
        let ta_mft_file = ta_mft_file.as_str();
        let ta_crl_file = ta_key.incoming_cert().crl_name().to_string();
        let ta_crl_file = ta_crl_file.as_str();

        // -------------------- CA1 -----------------------------------------------
        let ca1 = Handle::from_str_unsafe("CA1");
        let ca1_res = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&ca1);
        let req = child_request(&ca1);
        let parent = {
            let contact = add_child_to_ta_rfc6492(&ca1, req, ca1_res.clone());
            ParentCaReq::new(ta_handle.clone(), contact)
        };
        add_parent_to_ca(&ca1, parent);
        wait_for_current_resources(&ca1, &ca1_res);

        let ca1_key = ca_key_for_rcn(&ca1, &rcn_0);
        let ca1_cert_file = ObjectName::from(ca1_key.incoming_cert().cert()).to_string();
        let ca1_cert_file = ca1_cert_file.as_str();
        let ca1_mft_file = ca1_key.incoming_cert().mft_name().to_string();
        let ca1_mft_file = ca1_mft_file.as_str();
        let ca1_crl_file = ca1_key.incoming_cert().crl_name().to_string();
        let ca1_crl_file = ca1_crl_file.as_str();

        // Check that the TA publishes the certificate
        wait_for_published_objects(&ta_handle, &[ta_crl_file, ta_mft_file, ca1_cert_file]);

        // -------------------- CA2 -----------------------------------------------
        let ca2 = Handle::from_str_unsafe("CA2");
        let ca2_res = ResourceSet::from_strs("", "10.1.0.0/16", "").unwrap();

        init_child(&ca2);
        let req = child_request(&ca2);
        let parent = {
            let contact = add_child_to_ta_rfc6492(&ca2, req, ca2_res.clone());
            ParentCaReq::new(ta_handle.clone(), contact)
        };
        add_parent_to_ca(&ca2, parent);
        wait_for_current_resources(&ca2, &ca2_res);

        let ca2_key = ca_key_for_rcn(&ca2, &rcn_0);
        let ca2_cert_file = ObjectName::from(ca2_key.incoming_cert().cert()).to_string();
        let ca2_cert_file = ca2_cert_file.as_str();
        let ca2_mft_file = ca2_key.incoming_cert().mft_name().to_string();
        let ca2_mft_file = ca2_mft_file.as_str();
        let ca2_crl_file = ca2_key.incoming_cert().crl_name().to_string();
        let ca2_crl_file = ca2_crl_file.as_str();

        // Check that the TA publishes the certificate
        wait_for_published_objects(
            &ta_handle,
            &[ta_crl_file, ta_mft_file, ca1_cert_file, ca2_cert_file],
        );

        // -------------------- CA3 -----------------------------------------------
        let ca3 = Handle::from_str_unsafe("CA3");
        let ca_3_res_under_ca_1 = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        init_child(&ca3);
        let req = child_request(&ca3);
        let parent = {
            let contact = add_child_rfc6492(&ca1, &ca3, req, ca_3_res_under_ca_1.clone());
            ParentCaReq::new(ca1.clone(), contact)
        };
        add_parent_to_ca(&ca3, parent);
        wait_for_current_resources(&ca3, &ca_3_res_under_ca_1);

        let ca3_1_key = ca_key_for_rcn(&ca3, &rcn_0);
        let ca3_1_cert_file = ObjectName::from(ca3_1_key.incoming_cert().cert()).to_string();
        let ca3_1_cert_file = ca3_1_cert_file.as_str();
        let ca3_1_mft_file = ca3_1_key.incoming_cert().mft_name().to_string();
        let ca3_1_mft_file = ca3_1_mft_file.as_str();
        let ca3_1_crl_file = ca3_1_key.incoming_cert().crl_name().to_string();
        let ca3_1_crl_file = ca3_1_crl_file.as_str();

        // Check that CA1 publishes
        wait_for_published_objects(&ca1, &[ca1_mft_file, ca1_crl_file, ca3_1_cert_file]);

        let ca_3_res_under_ca_2 = ResourceSet::from_strs("", "10.1.0.0/24", "").unwrap();
        let ca_3_res = ca_3_res_under_ca_1.union(&ca_3_res_under_ca_2);
        let req = child_request(&ca3);
        let parent = {
            let contact = add_child_rfc6492(&ca2, &ca3, req, ca_3_res_under_ca_2.clone());
            ParentCaReq::new(ca2.clone(), contact)
        };
        add_parent_to_ca(&ca3, parent);
        wait_for_current_resources(&ca3, &ca_3_res);

        let ca3_2_key = ca_key_for_rcn(&ca3, &rcn_1);
        let ca3_2_cert_file = ObjectName::from(ca3_2_key.incoming_cert().cert()).to_string();
        let ca3_2_cert_file = ca3_2_cert_file.as_str();
        let ca3_2_mft_file = ca3_2_key.incoming_cert().mft_name().to_string();
        let ca3_2_mft_file = ca3_2_mft_file.as_str();
        let ca3_2_crl_file = ca3_2_key.incoming_cert().crl_name().to_string();
        let ca3_2_crl_file = ca3_2_crl_file.as_str();

        // Check that CA2 publishes
        wait_for_published_objects(&ca2, &[ca2_mft_file, ca2_crl_file, ca3_2_cert_file]);

        // -------------------- CA4 -----------------------------------------------
        let ca4 = Handle::from_str_unsafe("CA4");
        let ca_4_res_under_ca_3 = ResourceSet::from_strs("", "10.0.0.0-10.1.0.255", "").unwrap();

        init_child(&ca4);
        let req = child_request(&ca4);
        let parent = {
            let contact = add_child_rfc6492(&ca3, &ca4, req, ca_4_res_under_ca_3.clone());
            ParentCaReq::new(ca3.clone(), contact)
        };
        add_parent_to_ca(&ca4, parent);
        wait_for_current_resources(&ca4, &ca_4_res_under_ca_3);

        let ca4_1_key = ca_key_for_rcn(&ca4, &rcn_0);
        let ca4_1_cert_file = ObjectName::from(ca4_1_key.incoming_cert().cert()).to_string();
        let ca4_1_cert_file = ca4_1_cert_file.as_str();
        let ca4_1_mft_file = ca4_1_key.incoming_cert().mft_name().to_string();
        let ca4_1_mft_file = ca4_1_mft_file.as_str();
        let ca4_1_crl_file = ca4_1_key.incoming_cert().crl_name().to_string();
        let ca4_1_crl_file = ca4_1_crl_file.as_str();

        let ca4_2_key = ca_key_for_rcn(&ca4, &rcn_1);
        let ca4_2_cert_file = ObjectName::from(ca4_2_key.incoming_cert().cert()).to_string();
        let ca4_2_cert_file = ca4_2_cert_file.as_str();
        let ca4_2_mft_file = ca4_2_key.incoming_cert().mft_name().to_string();
        let ca4_2_mft_file = ca4_2_mft_file.as_str();
        let ca4_2_crl_file = ca4_2_key.incoming_cert().crl_name().to_string();
        let ca4_2_crl_file = ca4_2_crl_file.as_str();

        // Check that CA3 publishes both certs in its two resource classes
        wait_for_published_objects(
            &ca3,
            &[
                ca3_1_mft_file,
                ca3_1_crl_file,
                ca4_1_cert_file,
                ca3_2_mft_file,
                ca3_2_crl_file,
                ca4_2_cert_file,
            ],
        );

        // Check that CA4 publishes two resource classes, with only crls and mfts
        wait_for_published_objects(
            &ca4,
            &[
                ca4_1_mft_file,
                ca4_1_crl_file,
                ca4_2_mft_file,
                ca4_2_crl_file,
            ],
        );
    });
}
