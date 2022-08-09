//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;
use std::str::FromStr;

use bytes::Bytes;
use rpki::{
    ca::{csr::BgpsecCsr, idexchange::CaHandle},
    repository::{
        resources::{Asn, ResourceSet},
        x509::Serial,
        Manifest,
    },
};

use krill::{
    commons::api::{AspaDefinition, BgpSecDefinition, ObjectName, ReceivedCert, RoaDefinitionUpdates, RoaPayload},
    daemon::ca::ta_handle,
    test::*,
};

#[tokio::test]
async fn functional_keyroll() {
    let krill_dir = tmp_dir();
    let config = test_config(&krill_dir, true, false, false, false);
    start_krill(config).await;

    info("##################################################################");
    info("#                                                                #");
    info("#               Test Key Roll                                    #");
    info("#                                                                #");
    info("# We will verify that:                                           #");
    info("#  * CAs can initiate a key roll:                                #");
    info("#      * create new key, request certificate for it.             #");
    info("#      * publish (empty) manifest and CRL                        #");
    info("#      * renew both new and current manifest and CRL when needed #");
    info("#  * CAs can activate the new key:                               #");
    info("#      * republish all objects under the new key                 #");
    info("#      * revoke and retire old key, mft and crl                  #");
    info("#                                                                #");
    info("##################################################################");
    info("");

    let ta = ta_handle();
    let testbed = ca_handle("testbed");
    let ca = ca_handle("CA");
    let ca_resources = resources("AS65000", "10.0.0.0/16", "");

    let dflt_rc_name = rcn(0);

    // ROA, ASPA, and BGPSec definitions and filenames for objects which will
    // be re-issued during the roll.
    let roa_def = RoaPayload::from_str("10.0.0.0/16-16 => 64496").unwrap();
    let aspa_def = AspaDefinition::from_str("AS65000 => AS65002, AS65003(v4), AS65005(v6)").unwrap();
    let bgpsec_def = {
        let csr_bytes = include_bytes!("../test-resources/bgpsec/router-csr.der");
        let csr_bytes = Bytes::copy_from_slice(csr_bytes);
        let csr = BgpsecCsr::decode(csr_bytes.as_ref()).unwrap();
        BgpSecDefinition::new(Asn::from_u32(65000), csr.clone())
    };

    let roa_file = ObjectName::from(&roa_def).to_string();
    let aspa_file = ObjectName::aspa(aspa_def.customer()).to_string();
    let bgpsec_file = ObjectName::bgpsec(bgpsec_def.asn(), bgpsec_def.csr().public_key().key_identifier()).to_string();

    info("##################################################################");
    info("#                                                                #");
    info("# Wait for the *testbed* CA to get its certificate, this means   #");
    info("# that all CAs which are set up as part of krill_start under the #");
    info("# testbed config have been set up.                               #");
    info("#                                                                #");
    info("##################################################################");
    info("");
    assert!(ca_contains_resources(&testbed, &ResourceSet::all()).await);

    // Verify that the TA published expected objects
    {
        let mut expected_files = expected_mft_and_crl(&ta, &dflt_rc_name).await;
        expected_files.push(expected_issued_cer(&testbed, &dflt_rc_name).await);
        assert!(
            will_publish_embedded(
                "TA should have manifest, crl and cert for testbed",
                &ta,
                &expected_files
            )
            .await
        );
        assert_manifest_files_current_key("List CRL and issued cert on mft", &ta, &expected_files).await;
    }

    // Verify that the Testbed publishes a new empty key set
    {
        assert_manifest_number_current_key("Publish a new empty manifest with serial 1", &testbed, 1).await;
        let expected_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        assert_manifest_files_current_key("List CRL and issued cert on mft", &testbed, &expected_files).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Set up CA under testbed                   #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca).await;
        set_up_ca_under_parent_with_resources(&ca, &testbed, &ca_resources).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#    Verify that the testbed published the expected objects      #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        let mut expected_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        expected_files.push(expected_issued_cer(&ca, &dflt_rc_name).await);
        let msg = "testbed CA should have mft, crl and cert for CA";
        assert!(will_publish_embedded(msg, &testbed, &expected_files).await);
        assert_manifest_files_current_key(msg, &testbed, &expected_files).await;

        // The testbed CA should have re-issued a manifest when the certificate
        // was published.
        assert_manifest_number_current_key(
            "Testbed should update manifest when publishing cert for child",
            &testbed,
            2,
        )
        .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#   Set up ROAs, ASPA and BGPSec under testbed, they should be   #");
        info("#   be re-issued as part of the coming key roll.                 #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        let mut updates = RoaDefinitionUpdates::empty();
        updates.add(roa_def);
        ca_route_authorizations_update(&testbed, updates).await;
        assert_manifest_number_current_key("Testbed should update manifest when publishing ROA", &testbed, 3).await;

        ca_aspas_add(&testbed, aspa_def.clone()).await;
        assert_manifest_number_current_key("Testbed should update manifest when publishing ASPA", &testbed, 4).await;

        ca_bgpsec_add(&testbed, bgpsec_def).await;
        assert_manifest_number_current_key(
            "Testbed should update manifest when publishing bgpsec cert",
            &testbed,
            5,
        )
        .await;

        // Check that it's all published
        let mut expected_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        expected_files.push(expected_issued_cer(&ca, &dflt_rc_name).await);
        expected_files.push(roa_file.clone());
        expected_files.push(aspa_file.clone());
        expected_files.push(bgpsec_file.clone());

        let msg = "Testbed should publish MFT and CRL and the objects under the (only) current key";
        assert!(will_publish_embedded(msg, &testbed, &expected_files).await);
        assert_manifest_files_current_key(msg, &testbed, &expected_files).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                  testbed initiates new key                     #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        ca_roll_init(&testbed).await;
        assert!(state_becomes_new_key(&testbed).await);

        // Expect that the MFT, CRL and objects are still published under the
        // current key. But we will also have a new key with just a MFT and CRL.
        let mut expected_current_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        expected_current_files.push(expected_issued_cer(&ca, &dflt_rc_name).await);
        expected_current_files.push(roa_file.clone());
        expected_current_files.push(aspa_file.clone());
        expected_current_files.push(bgpsec_file.clone());

        let msg = "Testbed should publish MFT and CRL and the objects under the current key";
        assert_manifest_files_current_key(msg, &testbed, &expected_current_files).await;

        let mut expected_new_files = expected_new_key_mft_and_crl(&testbed, &dflt_rc_name).await;
        let msg = "Testbed should publish MFT and CRL only under the new key";
        assert_manifest_files_new_key(msg, &testbed, &expected_new_files).await;

        let mut expected_files = expected_current_files;
        expected_files.append(&mut expected_new_files);

        assert!(
            will_publish_embedded(
                "Testbed should publish MFT and CRL for both keys and the objects issued under the current key",
                &testbed,
                &expected_files
            )
            .await
        );

        // The testbed CA should issue an empty mft for the new key, with serial 1
        assert_manifest_number_new_key("testbed should issue empty mft for new key", &testbed, 1).await;

        // Even though there are no changes for the current key, we still re-issue
        // manifests and CRLs for all keys together.
        assert_manifest_number_current_key("no need to update the current mft when new key is added", &testbed, 5)
            .await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                  renew MFT/CRL should update both keys         #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        cas_force_publish_all().await;
        assert_manifest_number_current_key("testbed should re-issue mft for current key", &testbed, 6).await;
        assert_manifest_number_new_key("testbed should re-issue mft for new key", &testbed, 2).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                  testbed activates new key                     #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        ca_roll_activate(&testbed).await;

        // We now expect that the old key has become the current key and its mft, crl
        // and all objects are published as a single update.
        //
        // The old key will be revoked and its mft and crl will no longer be published.
        assert!(state_becomes_active(&testbed).await);

        let mut expected_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        expected_files.push(expected_issued_cer(&ca, &dflt_rc_name).await);
        expected_files.push(roa_file);
        expected_files.push(aspa_file);
        expected_files.push(bgpsec_file);

        let msg = "Testbed should now publish MFT and CRL for the activated key only, and the certificate for CA";
        assert!(will_publish_embedded(msg, &testbed, &expected_files).await);
        assert_manifest_files_current_key(msg, &testbed, &expected_files).await;

        assert_manifest_number_current_key(
            "testbed should issue new mft under promoted key, with all objects, as a single update.",
            &testbed,
            3,
        )
        .await;
    }

    let _ = fs::remove_dir_all(krill_dir);
}

async fn assert_manifest_number_current_key(msg: &str, ca: &CaHandle, nr: u64) {
    let current_key = ca_key_for_rcn(ca, &rcn(0)).await;
    assert_manifest_number_key(msg, ca, current_key.incoming_cert(), nr).await
}

async fn assert_manifest_files_current_key(msg: &str, ca: &CaHandle, files_expected: &[String]) {
    let current_key = ca_key_for_rcn(ca, &rcn(0)).await;
    assert_manifest_files_key(msg, ca, current_key.incoming_cert(), files_expected).await
}

async fn assert_manifest_number_new_key(msg: &str, ca: &CaHandle, nr: u64) {
    let new_key = ca_new_key_for_rcn(ca, &rcn(0)).await;
    assert_manifest_number_key(msg, ca, new_key.incoming_cert(), nr).await
}

async fn assert_manifest_files_new_key(msg: &str, ca: &CaHandle, files_expected: &[String]) {
    let new_key = ca_new_key_for_rcn(ca, &rcn(0)).await;
    assert_manifest_files_key(msg, ca, new_key.incoming_cert(), files_expected).await
}

async fn assert_manifest_number_key(msg: &str, ca: &CaHandle, incoming: &ReceivedCert, nr: u64) {
    let mut number_found = Serial::from(0_u64); // will be overwritten
    for _ in 0..10 {
        let published = publisher_details(ca.convert()).await;
        if let Some(mft) = published
            .current_files()
            .iter()
            .find(|file| file.uri() == &incoming.mft_uri())
            .map(|file| Manifest::decode(file.base64().to_bytes().as_ref(), true).unwrap())
        {
            number_found = mft.content().manifest_number();
            if number_found == Serial::from(nr) {
                return;
            }
        }

        sleep_millis(500).await;
    }

    panic!("Test: {}. Expected serial: {}, found: {}", msg, nr, number_found);
}

// Will ignore any .mft files on the expected files - to make it easier to use the
// same expected list for files published (which includes the mft) and mft entries
async fn assert_manifest_files_key(msg: &str, ca: &CaHandle, incoming: &ReceivedCert, files_expected: &[String]) {
    let mut files_found: Vec<String> = vec![];
    for _ in 0..10 {
        let published = publisher_details(ca.convert()).await;
        if let Some(mft) = published
            .current_files()
            .iter()
            .find(|file| file.uri() == &incoming.mft_uri())
            .map(|file| Manifest::decode(file.base64().to_bytes().as_ref(), true).unwrap())
        {
            files_found = mft
                .content()
                .iter()
                .map(|file_and_hash| unsafe {
                    std::str::from_utf8_unchecked(file_and_hash.file().as_ref()).to_string()
                })
                .collect();

            // We expect all files - except that .mft file
            if files_expected.len() == files_found.len() + 1 {
                for expected in files_expected {
                    if !expected.ends_with(".mft") && !files_found.contains(expected) {
                        continue;
                    }
                }
                return;
            }
        }

        sleep_millis(500).await;
    }

    panic!(
        "Test: {}. Expected files: {:?}, found: {:?}",
        msg, files_expected, files_found
    );
}
