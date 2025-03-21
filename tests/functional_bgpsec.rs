//! Tests manipulating BGPsec router keys.

use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::{Asn, ResourceSet};
use krill::api::admin::UpdateChildRequest;
use krill::api::bgpsec::BgpSecCsrInfo;

mod common;


//------------ Test Function -------------------------------------------------

/// Tests sdding, updating, and deleting router keys.
///
/// Uses the following layout:
///
/// ```text
///   TA
///    |
///   testbed
///    |
///   CA
/// ```
#[tokio::test]
async fn functional_bgpsec() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed().await;

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS65000", "10.0.0.0/16", "");
    let ca_res_shrunk = common::resources("", "10.0.0.0/16", "");

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up 'CA' under 'testbed'.");
    server.create_ca_with_repo(&ca).await;
    server.register_ca_with_parent(&ca, &testbed, &ca_res).await;

    let csr = BgpsecCsr::decode(
        include_bytes!("../test-resources/bgpsec/router-csr.der").as_ref()
    ).unwrap();

    let asn_owned = Asn::from_u32(65000);
    let asn_not_owned = Asn::from_u32(65001);

    eprintln!(">>>> Reject BGPsec definition for ASN not held.");
    assert!(common::check_bad_request(
        server.client().bgpsec_add_single(
            &ca, asn_not_owned, csr.clone()
        ).await
    ));
    assert!(server.wait_for_objects(&ca, &[]).await);

    eprintln!(">>>> Add BGPsec definition.");
    server.client().bgpsec_add_single(
        &ca, asn_owned, csr.clone()
    ).await.unwrap();
    let definitions = server.client().bgpsec_list(&ca).await.unwrap();
    assert_eq!(definitions.as_slice().len(), 1);
    assert_eq!(definitions.as_slice().first().unwrap().asn, asn_owned);
    assert!(server.wait_for_objects(&ca, definitions.as_slice()).await);

    eprintln!(">>>> Shrink resources: definition but no certificate.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::resources(ca_res_shrunk.clone())
    ).await.unwrap();
    let definitions = server.client().bgpsec_list(&ca).await.unwrap();
    assert_eq!(definitions.as_slice().len(), 1);
    assert_eq!(definitions.as_slice().first().unwrap().asn, asn_owned);
    assert!(server.wait_for_objects(&ca, &[]).await);

    eprintln!(">>>> Grow resources: certificate comes back.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::resources(ca_res.clone())
    ).await.unwrap();
    let definitions = server.client().bgpsec_list(&ca).await.unwrap();
    assert_eq!(definitions.as_slice().len(), 1);
    assert_eq!(definitions.as_slice().first().unwrap().asn, asn_owned);
    assert!(server.wait_for_objects(&ca, definitions.as_slice()).await);

    eprintln!(">>>> Remove BGPsec definition.");
    server.client().bgpsec_delete_single(
        &ca, asn_owned, csr.public_key().key_identifier()
    ).await.unwrap();
    let definitions = server.client().bgpsec_list(&ca).await.unwrap();
    assert_eq!(definitions.as_slice().len(), 0);
    assert!(server.wait_for_objects(&ca, &[]).await);
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    /// Checks that the given CA has the given ASPA definitions.
    async fn wait_for_objects(
        &self, ca: &CaHandle, definitions: &[BgpSecCsrInfo]
    ) -> bool {
        let mut files = self.expected_objects(ca);
        files.push_mft_and_crl(&ResourceClassName::from(0)).await;
        files.extend(definitions.iter().map(|csr_info| {
            csr_info.object_name().to_string()
        }));
        files.wait_for_published().await
    }
}

