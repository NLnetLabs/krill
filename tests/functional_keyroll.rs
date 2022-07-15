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
    commons::api::{AspaDefinition, BgpSecDefinition, ObjectName, RcvdCert, RoaDefinition, RoaDefinitionUpdates},
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
    let roa_def = RoaDefinition::from_str("10.0.0.0/16-16 => 64496").unwrap();
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

        manifest_number_current_key("Publish a new empty manifest with serial 1", &testbed, 1).await;
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
        assert!(
            will_publish_embedded(
                "testbed CA should have mft, crl and cert for CA",
                &testbed,
                &expected_files
            )
            .await
        );

        // The testbed CA should have re-issued a manifest when the certificate
        // was published.
        manifest_number_current_key(
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
        manifest_number_current_key("Testbed should update manifest when publishing ROA", &testbed, 3).await;

        ca_aspas_add(&testbed, aspa_def.clone()).await;
        manifest_number_current_key("Testbed should update manifest when publishing ASPA", &testbed, 4).await;

        ca_bgpsec_add(&testbed, bgpsec_def).await;
        manifest_number_current_key(
            "Testbed should update manifest when publishing bgpsec cert",
            &testbed,
            5,
        )
        .await;
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

        let mut expected_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        expected_files.push(expected_issued_cer(&ca, &dflt_rc_name).await);
        expected_files.push(roa_file.clone());
        expected_files.push(aspa_file.clone());
        expected_files.push(bgpsec_file.clone());
        expected_files.append(&mut expected_new_key_mft_and_crl(&testbed, &dflt_rc_name).await);
        assert!(
            will_publish_embedded(
                "Testbed should publish MFT and CRL for both keys and the objects issued under the current key",
                &testbed,
                &expected_files
            )
            .await
        );

        // The testbed CA should issue an empty mft for the new key, with serial 1
        manifest_number_new_key("testbed should issue empty mft for new key", &testbed, 1).await;

        // Even though there are no changes for the current key, we still re-issue
        // manifests and CRLs for all keys together.
        manifest_number_current_key("no need to update the current mft when new key is added", &testbed, 5).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                  renew MFT/CRL should update both keys         #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        cas_force_publish_all().await;
        manifest_number_current_key("testbed should re-issue mft for current key", &testbed, 6).await;
        manifest_number_new_key("testbed should re-issue mft for new key", &testbed, 2).await;
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                  testbed activates new key                     #");
        info("#                                                                #");
        info("##################################################################");
        info("");

        ca_roll_activate(&testbed).await;
        assert!(state_becomes_active(&testbed).await);

        let mut expected_files = expected_mft_and_crl(&testbed, &dflt_rc_name).await;
        expected_files.push(expected_issued_cer(&ca, &dflt_rc_name).await);
        expected_files.push(roa_file);
        expected_files.push(aspa_file);
        expected_files.push(bgpsec_file);
        assert!(
            will_publish_embedded(
                "Testbed should now publish MFT and CRL for the activated key only, and the certificate for CA",
                &testbed,
                &expected_files
            )
            .await
        );

        // We now expect that the old key has become the current key and its mft, crl
        // and all objects are published as a single update. So, we could be forgiven
        // to expect that the serial for this manifest will become 3.
        //
        // However.. the child will drop the old key, and ask for its revocation. This
        // is a separate publication event. So, the testbed mft serial number will be 4.
        manifest_number_current_key(
            "testbed should issue new mft under promoted key, with all objects, as a single update. Then publish updated CRL and mft for revoked child certificate for old key.",
            &testbed,
            4,
        )
        .await;
    }

    let _ = fs::remove_dir_all(krill_dir);
}

async fn manifest_number_current_key(msg: &str, ca: &CaHandle, nr: u64) {
    let current_key = ca_key_for_rcn(ca, &rcn(0)).await;
    manifest_number_key(msg, ca, current_key.incoming_cert(), nr).await
}

async fn manifest_number_new_key(msg: &str, ca: &CaHandle, nr: u64) {
    let new_key = ca_new_key_for_rcn(ca, &rcn(0)).await;
    manifest_number_key(msg, ca, new_key.incoming_cert(), nr).await
}

async fn manifest_number_key(msg: &str, ca: &CaHandle, incoming: &RcvdCert, nr: u64) {
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
