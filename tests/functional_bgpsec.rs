//! Perform functional tests on a Krill instance, using the API
//!
use std::fs;

use bytes::Bytes;
use rpki::{
    ca::{csr::BgpsecCsr, idexchange::CaHandle, provisioning::ResourceClassName},
    repository::resources::{Asn, ResourceSet},
};

use krill::{
    commons::api::{BgpSecAsnKey, BgpSecCsrInfo, BgpSecDefinition},
    daemon::ta::ta_handle,
    test::*,
};

#[tokio::test]
async fn functional_bgpsec() {
    let krill_dir = start_krill_with_default_test_config(true, false, false, false).await;

    info("##################################################################");
    info("#                                                                #");
    info("# Test BGPSec support.                                             #");
    info("#                                                                #");
    info("# Uses the following lay-out:                                    #");
    info("#                                                                #");
    info("#                  TA                                            #");
    info("#                   |                                            #");
    info("#                testbed                                         #");
    info("#                   |                                            #");
    info("#                  CA                                            #");
    info("#                                                                #");
    info("#                                                                #");
    info("##################################################################");
    info("");

    let ta = ta_handle();
    let testbed = ca_handle("testbed");
    let ca = ca_handle("CA");
    let ca_res = resources("AS65000", "10.0.0.0/16", "");
    let ca_res_shrunk = resources("", "10.0.0.0/16", "");

    let rcn_0 = rcn(0);

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
        let mut expected_files = expected_mft_and_crl(&ta, &rcn_0).await;
        expected_files.push(expected_issued_cer(&testbed, &rcn_0).await);
        assert!(
            will_publish_embedded(
                "TA should have manifest, crl and cert for testbed",
                &ta,
                &expected_files
            )
            .await
        );
    }

    {
        info("##################################################################");
        info("#                                                                #");
        info("#                      Set up CA  under testbed                  #");
        info("#                                                                #");
        info("##################################################################");
        info("");
        set_up_ca_with_repo(&ca).await;
        set_up_ca_under_parent_with_resources(&ca, &testbed, &ca_res).await;
    }

    // short hand to expect published BGPSec certs under CA
    async fn expect_bgpsec_objects(ca: &CaHandle, definitions: &[BgpSecCsrInfo]) {
        let rcn_0 = ResourceClassName::from(0);

        let mut expected_files = expected_mft_and_crl(ca, &rcn_0).await;

        for csr_info in definitions {
            expected_files.push(csr_info.object_name().to_string());
        }

        assert!(
            will_publish_embedded(
                "published BGPSec certificates do not match expectations",
                ca,
                &expected_files
            )
            .await
        );
    }

    let csr_bytes = include_bytes!("../test-resources/bgpsec/router-csr.der");
    let csr_bytes = Bytes::copy_from_slice(csr_bytes);
    let csr = BgpsecCsr::decode(csr_bytes.as_ref()).unwrap();

    let asn_owned = Asn::from_u32(65000);
    let asn_not_owned = Asn::from_u32(65001);

    let bgpsec_def_owned = BgpSecDefinition::new(asn_owned, csr.clone());
    let bgpsec_def_not_owned = BgpSecDefinition::new(asn_not_owned, csr);
    let bgpsec_def_key = BgpSecAsnKey::from(&bgpsec_def_owned);

    // Refuse adding BGPSec definition for ASN which is not held
    ca_bgpsec_add_expect_error(&ca, bgpsec_def_not_owned).await;

    // Add BGPSec definition
    {
        ca_bgpsec_add(&ca, bgpsec_def_owned).await;

        // List definitions
        let definitions = ca_bgpsec_list(&ca).await.unpack();
        assert_eq!(1, definitions.len());

        // Expect it's published
        expect_bgpsec_objects(&ca, &definitions).await;
    }

    // Shrink resources.
    {
        update_child(&testbed, &ca.convert(), &ca_res_shrunk).await;
        ca_equals_resources(&ca, &ca_res_shrunk).await;

        // Expect the definition still exists
        let definitions = ca_bgpsec_list(&ca).await.unpack();
        assert_eq!(1, definitions.len());

        // But expect that the BGPSec certificate is removed.
        expect_bgpsec_objects(&ca, &[]).await;
    }

    // Grow resources
    {
        update_child(&testbed, &ca.convert(), &ca_res).await;
        ca_equals_resources(&ca, &ca_res).await;

        // Expect the definition still exists
        let definitions = ca_bgpsec_list(&ca).await.unpack();
        assert_eq!(1, definitions.len());

        // And expect that the BGPSec certificate is published again.
        expect_bgpsec_objects(&ca, &definitions).await;
    }

    // Remove BGPSec definition
    {
        ca_bgpsec_remove(&ca, bgpsec_def_key).await;

        // Expect the definition is removed
        let definitions = ca_bgpsec_list(&ca).await.unpack();
        assert_eq!(0, definitions.len());

        // Expect that the BGPSec certificate is removed.
        expect_bgpsec_objects(&ca, &[]).await;
    }

    let _ = fs::remove_dir_all(krill_dir);
}
