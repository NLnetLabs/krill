//! Test a CA keyroll.

use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idexchange::CaHandle;
use rpki::repository::Manifest;
use rpki::repository::resources::{Asn, ResourceSet};
use rpki::repository::x509::Serial;
use krill::api::ca::{ObjectName, ReceivedCert};
use krill::api::roa::RoaConfigurationUpdates;

mod common;


//------------ Test Function -------------------------------------------------

/// Test a key roll.
///
/// We will verify that:
///  * CAs can initiate a key roll:
///      * create new key, request certificate for it. 
///      * publish (empty) manifest and CRL
///      * renew both new and current manifest and CRL when needed
///  * CAs can activate the new key:
///      * republish all objects under the new key
///      * revoke and retire old key, mft and crl
#[tokio::test]
async fn functional_keyroll() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed().await;

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_resources = common::resources("AS65000", "10.0.0.0/16", "");

    let rc0 = common::rcn(0);

    // ROA, ASPA, and BGPSec definitions and filenames for objects which will
    // be re-issued during the roll.
    let roa_conf = common::roa_conf("10.0.0.0/16-16 => 64496");
    let aspa_def = common::aspa_def("AS65000 => AS65002, AS65003, AS65005");
    let bgpsec_asn = Asn::from_u32(65000);
    let bgpsec_csr = BgpsecCsr::decode(
        include_bytes!("../test-resources/bgpsec/router-csr.der").as_ref()
    ).unwrap();

    let roa_file = ObjectName::from(roa_conf.payload).to_string();
    let aspa_file = ObjectName::aspa_from_customer(
        aspa_def.customer
    ).to_string();
    let bgpsec_file = ObjectName::bgpsec(
        bgpsec_asn,
        bgpsec_csr.public_key().key_identifier(),
    ).to_string();

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Verify that the Testbed publishes a new empty key set.");
    assert!(server.wait_manifest_number_current_key(&testbed, 1).await);
    let mut files = server.expected_objects(&testbed);
    files.push_mft_and_crl(&rc0).await;
    assert!(files.wait_for_manifest_current_key().await);

    eprintln!(">>>> Set up CA under testbed.");
    server.create_ca_with_repo(&ca).await;
    server.register_ca_with_parent(&ca, &testbed, &ca_resources).await;

    eprintln!(">>>> Verify that the testbed published the expected objects");
    files.push_cer(&ca, &rc0).await;
    assert!(files.wait_for_published().await);
    assert!(files.wait_for_manifest_current_key().await);

    eprintln!(">>>> Set up ROAs, ASPA and BGPSec under testbed.");
    server.client().roas_update(
        &testbed,
        RoaConfigurationUpdates { added: vec![roa_conf], removed: vec![] }
    ).await.unwrap();
    assert!(server.wait_manifest_number_current_key(&testbed, 3).await);
    server.client().aspas_add_single(
        &testbed, aspa_def.clone()
    ).await.unwrap();
    assert!(server.wait_manifest_number_current_key(&testbed, 4).await);
    server.client().bgpsec_add_single(
        &testbed, bgpsec_asn, bgpsec_csr
    ).await.unwrap();
    assert!(server.wait_manifest_number_current_key(&testbed, 5).await);

    eprintln!(">>>> Check that everything is published.");
    files.push(roa_file.clone());
    files.push(aspa_file.clone());
    files.push(bgpsec_file.clone());
    assert!(files.wait_for_published().await);
    assert!(files.wait_for_manifest_current_key().await);

    eprintln!(">>>> Initiate new key for testbed.");
    server.client().ca_init_keyroll(&testbed).await.unwrap();
    assert!(server.wait_for_state_new_key(&testbed).await);

    // Objects are still published under the current key.
    assert!(files.wait_for_manifest_current_key().await);

    // A manifest and CRL are present under the new key.
    let mut new_files = server.expected_objects(&testbed);
    new_files.push_mft_and_crl(&rc0).await;
    assert!(new_files.wait_for_manifest_new_key().await);

    // Old objects and new manifest and CRL are all published under the
    // current key.
    files.extend(new_files.files.iter().cloned());
    assert!(files.wait_for_published().await);

    // The testbed CA should issue an empty mft for the new key, with
    // serial 1
    assert!(server.wait_manifest_number_new_key(&testbed, 1).await);

    // The manifest for the current key isn’t updated when the new key is
    // added.
    assert!(server.wait_manifest_number_current_key(&testbed, 5).await);

    eprintln!(">>>> Renewing MFT/CRL should update both keys.");
    server.client().bulk_force_publish().await.unwrap();
    assert!(server.wait_manifest_number_current_key(&testbed, 6).await);
    assert!(server.wait_manifest_number_new_key(&testbed, 2).await);

    eprintln!(">>>> Activate new key for testbed.");
    server.client().ca_activate_keyroll(&testbed).await.unwrap();

    // We now expect that the new key has become the current key and its
    // mft, crl and all objects are published as a single update.
    //
    // The old key will be revoked and its mft and crl will no longer be
    // published.
    assert!(server.wait_for_state_active(&testbed).await);

    // Testbed should now publish MFT and CRL for the activated key only,
    // and the certificate for CA
    let mut files = server.expected_objects(&testbed);
    files.push_mft_and_crl(&rc0).await;
    files.push_cer(&ca, &rc0).await;
    files.push(roa_file.clone());
    files.push(aspa_file.clone());
    files.push(bgpsec_file.clone());
    assert!(files.wait_for_published().await);
    assert!(files.wait_for_manifest_current_key().await);
    assert!(server.wait_manifest_number_current_key(&testbed, 3).await);
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    pub async fn wait_manifest_number_current_key(
        &self, ca: &CaHandle, nr: u64
    ) -> bool {
        let current_key = self.ca_key_for_rcn(ca, &common::rcn(0)).await;
        self.wait_manifest_number_key(
            ca, &current_key.incoming_cert, nr
        ).await
    }

    pub async fn wait_manifest_number_new_key(
        &self, ca: &CaHandle, nr: u64
    ) -> bool {
        let new_key = self.ca_new_key_for_rcn(ca, &common::rcn(0)).await;
        self.wait_manifest_number_key(ca, &new_key.incoming_cert, nr).await
    }

    async fn wait_manifest_number_key(
        &self, ca: &CaHandle, incoming: &ReceivedCert, nr: u64,
    ) -> bool {
        let mut number_found = Serial::from(0_u64); // will be overwritten
        for _ in 0..10 {
            let published = self.client().publisher_details(
                &ca.convert()
            ).await.unwrap();
            if let Some(mft) = published
                .current_files
                .iter()
                .find(|file| file.uri == incoming.mft_uri())
                .map(|file| {
                    Manifest::decode(file.base64.to_bytes().as_ref(), true)
                        .unwrap()
                })
            {
                number_found = mft.content().manifest_number();
                if number_found == Serial::from(nr) {
                    return true;
                }
            }

            common::sleep_millis(500).await;
        }

        eprintln!("Expected serial: {nr}, found: {number_found}");
        false
    }
}


//------------ Extend ExpectedObjects ----------------------------------------

impl common::ExpectedObjects<'_> {
    pub async fn wait_for_manifest_current_key(&self) -> bool {
        let current_key = self.server.ca_key_for_rcn(
            self.ca, &common::rcn(0)
        ).await;
        self.wait_manifest_files_key(&current_key.incoming_cert) .await
    }

    pub async fn wait_for_manifest_new_key(&self) -> bool {
        let new_key = self.server.ca_new_key_for_rcn(
            self.ca, &common::rcn(0)
        ).await;
        self.wait_manifest_files_key(&new_key.incoming_cert).await
    }

    // Will ignore any .mft files on the expected files - to make it easier
    // to use the same expected list for files published (which includes the
    // mft) and mft entries
    async fn wait_manifest_files_key(
        &self,
        incoming: &ReceivedCert,
    ) -> bool {
        let mut files_found: Vec<String> = vec![];
        for _ in 0..10 {
            let published = self.server.client().publisher_details(
                &self.ca.convert()
            ).await.unwrap();
            if let Some(mft) = published
                .current_files
                .iter()
                .find(|file| file.uri == incoming.mft_uri())
                .map(|file| {
                    Manifest::decode(file.base64.to_bytes().as_ref(), true)
                        .unwrap()
                })
            {
                files_found = mft
                    .content()
                    .iter()
                    .map(|file_and_hash| unsafe {
                        std::str::from_utf8_unchecked(
                            file_and_hash.file().as_ref(),
                        )
                        .to_string()
                    })
                    .collect();

                // We expect all files - except that .mft file
                if self.files.len() == files_found.len() + 1 {
                    for expected in &self.files {
                        if !expected.ends_with(".mft")
                            && !files_found.contains(expected)
                        {
                            continue;
                        }
                    }
                    return true;
                }
            }

            common::sleep_millis(500).await;
        }

        eprintln!(
            "Expected files: {:?}, found: {:?}",
            self.files, files_found
        );
        false
    }
}

