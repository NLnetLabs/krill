//! Tests manipulating BGPsec router keys.

use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::{Asn, ResourceSet};
use krill::commons::api::{BgpSecCsrInfo, UpdateChildRequest};

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
#[test]
fn functional_bgpsec() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed();

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS65000", "10.0.0.0/16", "");
    let ca_res_shrunk = common::resources("", "10.0.0.0/16", "");

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all())
    );

    eprintln!(">>>> Set up 'CA' under 'testbed'.");
    server.create_ca_with_repo(&ca);
    server.register_ca_with_parent(&ca, &testbed, &ca_res);

    let csr = BgpsecCsr::decode(
        include_bytes!("../test-resources/bgpsec/router-csr.der").as_ref()
    ).unwrap();

    let asn_owned = Asn::from_u32(65000);
    let asn_not_owned = Asn::from_u32(65001);

    eprintln!(">>>> Reject BGPsec definition for ASN not held.");
    assert!(common::check_bad_request(
        server.client().bgpsec_add_single(
            &ca, asn_not_owned, csr.clone()
        )
    ));
    assert!(server.wait_for_objects(&ca, &[]));

    eprintln!(">>>> Add BGPsec definition.");
    server.client().bgpsec_add_single(
        &ca, asn_owned, csr.clone()
    ).unwrap();
    let definitions = server.client().bgpsec_list(&ca).unwrap().unpack();
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions.first().unwrap().asn(), asn_owned);
    assert!(server.wait_for_objects(&ca, &definitions));

    eprintln!(">>>> Shrink resources: definition but no certificate.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::resources(ca_res_shrunk.clone())
    ).unwrap();
    let definitions = server.client().bgpsec_list(&ca).unwrap().unpack();
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions.first().unwrap().asn(), asn_owned);
    assert!(server.wait_for_objects(&ca, &[]));

    eprintln!(">>>> Grow resources: certificate comes back.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::resources(ca_res.clone())
    ).unwrap();
    let definitions = server.client().bgpsec_list(&ca).unwrap().unpack();
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions.first().unwrap().asn(), asn_owned);
    assert!(server.wait_for_objects(&ca, &definitions));

    eprintln!(">>>> Remove BGPsec definition.");
    server.client().bgpsec_delete_single(
        &ca, asn_owned, csr.public_key().key_identifier()
    ).unwrap();
    let definitions = server.client().bgpsec_list(&ca).unwrap().unpack();
    assert_eq!(definitions.len(), 0);
    assert!(server.wait_for_objects(&ca, &[]));
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    /// Checks that the given CA has the given ASPA definitions.
    fn wait_for_objects(
        &self, ca: &CaHandle, definitions: &[BgpSecCsrInfo]
    ) -> bool {
        let mut files = self.expected_objects(ca);
        files.push_mft_and_crl(&ResourceClassName::from(0));
        files.extend(definitions.iter().map(|csr_info| {
            csr_info.object_name().to_string()
        }));
        files.wait_for_published()
    }
}

