//! Tests parent/child interactions.

use std::{fs, io};
use rpki::repository::resources::ResourceSet;

mod common;


//------------ Test Function -------------------------------------------------

/// Test Krill parent/child interactions.
///
/// The setup is:
///
/// ```text
///       TA
///        |
///     testbed
///      |   |
///    CA1   CA2
///      |   |
///       CA3     (two parents, two resource classes)
///       | |
///       CA4     (one parent, two resources classes)
/// ```
///
/// The test verifies that:
///  * CAs can be set up as parent child using RFC6492,
///  * CAs can publish using RFC8181,
///  * CA1 can perform a key roll,
///  * we can remove and re-add parents / children,
///  * a CA will request revocation and withdraw objects when it is deleted
///    gracefully
#[test]
fn functional_parent_child() {
    let (server, tmpdir)
        = common::KrillServer::start_with_file_storage_and_testbed();

    let testbed = common::ca_handle("testbed");

    let ca1 = common::ca_handle("CA1");
    let ca1_res = common::resources("AS65000", "10.0.0.0/16", "");

    let ca2 = common::ca_handle("CA2");
    let ca2_res = common::resources("AS65001", "10.1.0.0/16", "");

    let ca3 = common::ca_handle("CA3");
    let ca3_res_under_ca_1 = common::resources("65000", "10.0.0.0/16", "");
    let ca3_res_under_ca_2 = common::resources("65001", "10.1.0.0/24", "");

    let ca4 = common::ca_handle("CA4");
    let ca4_res_under_ca_3 = common::resources(
        "65000", "10.0.0.0-10.1.0.255", ""
    );

    let rcn0 = common::rcn(0);
    let rcn1 = common::rcn(1);
    let rcn2 = common::rcn(2);
    let rcn3 = common::rcn(3);

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all())
    );

    eprintln!(">>>> Set up CA1 under testbed.");
    server.create_ca_with_repo(&ca1);
    server.register_ca_with_parent(&ca1, &testbed, &ca1_res);

    eprintln!(">>>> Set up CA2 under testbed.");
    server.create_ca_with_repo(&ca2);
    server.register_ca_with_parent(&ca2, &testbed, &ca2_res);

    eprintln!(">>>> Verify that the testbed published the expected objects");
    let mut files = server.expected_objects(&testbed);
    files.push_mft_and_crl(&rcn0);
    files.push_cer(&ca1, &rcn0);
    files.push_cer(&ca2, &rcn0);
    assert!(files.wait_for_published());

    eprintln!(">>>> Set up CA3 under CA1.");
    server.create_ca_with_repo(&ca3);
    server.register_ca_with_parent(&ca3, &ca1, &ca3_res_under_ca_1);

    eprintln!(">>>> Expect that CA1 publishes the certificate for CA3.");
    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0);
    files.push_cer(&ca3, &rcn0);
    assert!(files.wait_for_published());
    
    eprintln!(">>>> Set up CA3 under CA2.");
    server.register_ca_with_parent(&ca3, &ca2, &ca3_res_under_ca_2);

    eprintln!(">>>> Expect that CA2 publishes the certificate for CA3.");
    let mut files = server.expected_objects(&ca2);
    files.push_mft_and_crl(&rcn0);
    // CA3 will have the certificate from CA2 under its resource class '1'
    // rather than '0'
    files.push_cer(&ca3, &rcn1);
    assert!(files.wait_for_published());

    eprintln!(">>>> Set up CA4 under CA3 with resources from both parents.");
    server.create_ca_with_repo(&ca4);
    server.register_ca_with_parent(&ca4, &ca3, &ca4_res_under_ca_3);

    eprintln!(">>>> Expect that CA3 publishes two certificates for CA4.");
    let mut files = server.expected_objects(&ca3);
    files.push_mft_and_crl(&rcn0);
    files.push_cer(&ca4, &rcn0);
    files.push_mft_and_crl(&rcn1);
    files.push_cer(&ca4, &rcn1);
    assert!(files.wait_for_published());

    eprintln!(">>>> Expect that CA4 publishes two resource classes.");
    let mut files = server.expected_objects(&ca4);
    files.push_mft_and_crl(&rcn0);
    files.push_mft_and_crl(&rcn1);
    assert!(files.wait_for_published());

    eprintln!(">>>> Let CA1 do a keyroll.");
    server.client().ca_init_keyroll(&ca1).unwrap();
    assert!(server.wait_for_state_new_key(&ca1));

    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0);
    files.push_cer(&ca3, &rcn0);
    files.push_new_key_mft_and_crl(&rcn0);
    assert!(files.wait_for_published());

    server.client().ca_activate_keyroll(&ca1).unwrap();
    assert!(server.wait_for_state_active(&ca1));

    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0);
    files.push_cer(&ca3, &rcn0);
    assert!(files.wait_for_published());

    eprintln!(">>>> Remove parent from CA4, expect objects to be withdrawn.");
    server.client().parent_delete(&ca4, &ca3.convert()).unwrap();
    server.client().child_delete(&ca3, &ca4.convert()).unwrap();
    assert!(server.expected_objects(&ca4).wait_for_published());

    eprintln!(">>>> Add parent back to CA4, expect objects published again.");
    server.register_ca_with_parent(&ca4, &ca3, &ca4_res_under_ca_3);

    // We expect new resource classes 2 and 3 to be used now
    let mut files = server.expected_objects(&ca4);
    files.push_mft_and_crl(&rcn2);
    files.push_mft_and_crl(&rcn3);
    assert!(files.wait_for_published());

    eprintln!(">>>> Remove CA3, expect that its objects are also removed.");
    
    // Check that CA3 exists both according to the API and on disk.
    assert!(server.client().ca_details(&ca3).is_ok());
    assert!(
        fs::metadata(
            tmpdir.path().join("data/ca_objects/CA3.json")
        ).unwrap().is_file()
    );

    server.client().ca_delete(&ca3).unwrap();

    // Now it should be gone.
    assert!(server.client().ca_details(&ca3).is_err());
    assert_eq!(
        fs::metadata(
            tmpdir.path().join("data/ca_objects/CA3.json")
        ).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );

    // Nothing published any more.
    assert!(server.expected_objects(&ca3).wait_for_published());

    // CA1 doesn’t publish the certificate for CA3 any more.
    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0);
    assert!(files.wait_for_published());
}
