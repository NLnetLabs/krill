//! Test manipulating ASPA definitions.

use std::slice;
use std::str::FromStr;
use reqwest::StatusCode;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::ResourceSet;
use krill::commons::api::{
    AspaDefinition, AspaDefinitionList, AspaProvidersUpdate, CustomerAsn,
    ObjectName, ProviderAsn,
};
use krill::commons::util::httpclient;

mod common;


//------------ Test Function -------------------------------------------------

/// Tests sdding, updating, and deleting ASPA definitions.
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
fn functional_aspa() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed();

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS65000", "10.0.0.0/16", "");

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all())
    );

    eprintln!(">>>> Set up 'CA' under 'testbed'.");
    server.create_ca_with_repo(&ca);
    server.register_ca_with_parent(&ca, &testbed, &ca_res);

    eprintln!(">>>> Reject ASPA without providers.");
    let aspa = aspa_definition("AS65000 => <none>");
    assert!(!server.try_add_aspa(&ca, aspa.clone()));
    assert!(server.wait_for_objects(&ca, &[]));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), &[]);

    eprintln!(">>>> Reject ASPA using customer as provider.");
    let aspa = aspa_definition("AS65000 => AS65000, AS65003, AS65005");
    assert!(!server.try_add_aspa(&ca, aspa.clone()));
    assert!(server.wait_for_objects(&ca, &[]));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), &[]);

    eprintln!(">>>> Add an ASPA under CA.");
    let aspa = aspa_definition("AS65000 => AS65002, AS65003, AS65005");
    assert!(server.try_add_aspa(&ca, aspa.clone()));
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), aspas);

    eprintln!(">>>> Update an existing ASPA.");
    assert!(server.try_update_aspa(
        &ca, "AS65000", ["AS65006"], ["AS65002"]
    ));
    let aspa = aspa_definition("AS65000 => AS65003, AS65005, AS65006");
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), aspas);

    eprintln!(">>>> Reject update that adds customer as provider.");
    assert!(!server.try_update_aspa(&ca, "AS65000", ["AS65000"], []));
    // Use `aspas` from before.
    assert!(server.wait_for_objects(&ca, aspas));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), aspas);

    eprintln!(">>>> Removing all providers should result in delete.");
    assert!(server.try_update_aspa(
        &ca, "AS65000", [], ["AS65003", "AS65005", "AS65006"]
    ));
    assert!(server.wait_for_objects(&ca, &[]));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), &[]);

    eprintln!(">>>> Adding provider to non-existing customer should add it.");
    // This is useful for two reasons:
    // 1) it allows for automation using just updates
    // 2) because empty provider lists were accepted in Krill <0.13.0
    //    we need the code to deal with removing all providers, which
    //    will remove the AspaConfig when replayed, and then adding
    //    some provider again.
    assert!(server.try_update_aspa(
        &ca, "AS65000", ["AS65003", "AS65005", "AS65006"], []
    ));
    let aspa = aspa_definition("AS65000 => AS65003, AS65005, AS65006");
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), aspas);

    eprintln!(">>>> Add existing and remove nonexisting provider.");
    assert!(server.try_update_aspa(
        &ca, "AS65000",
        ["AS65002", "AS65005"],
        ["AS65006", "AS65007"],
    ));
    let aspa = aspa_definition("AS65000 => AS65002, AS65003, AS65005");
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), aspas);

    eprintln!(">>>> Delete an existing ASPA.");
    server.client().aspas_delete_single(
        &ca, customer("AS65000")
    ).unwrap();
    assert!(server.wait_for_objects(&ca, &[]));
    assert_eq!(server.aspa_definitions(&ca).as_ref(), &[]);
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    /// Adds a single ASPA definition.
    ///
    /// Returns whether adding succeeded. Panics on error if anything other
    /// than the server refusing to add the ASPA happened.
    fn try_add_aspa(
        &self, ca: &CaHandle, aspa: AspaDefinition
    ) -> bool {
        match self.client().aspas_add_single(ca, aspa) {
            Ok(_) => true,
            Err(err) => {
                assert!(matches!(
                    err,
                    httpclient::Error::ErrorResponseWithJson(
                        _, StatusCode::BAD_REQUEST, _
                    )
                ));
                false
            }
        }
    }

    /// Updates a single ASPA definition.
    ///
    /// Returns whether adding succeeded. Panics on error if anything other
    /// than the server refusing to add the ASPA happened.
    fn try_update_aspa<'a>(
        &'a self,
        ca: &CaHandle,
        customer_str: &str,
        add: impl IntoIterator<Item=&'a str>,
        remove: impl IntoIterator<Item=&'a str>,
    ) -> bool {
        match self.client().aspas_update_single(
            ca,
            customer(customer_str),
            AspaProvidersUpdate::new(
                add.into_iter().map(provider).collect(),
                remove.into_iter().map(provider).collect(),
            )
        ) {
            Ok(_) => true,
            Err(err) => {
                assert!(matches!(
                    err,
                    httpclient::Error::ErrorResponseWithJson(
                        _, StatusCode::BAD_REQUEST, _
                    )
                ));
                false
            }
        }
    }

    /// Checks that the given CA has the given ASPA definitions.
    fn wait_for_objects<'s>(
        &'s self, ca: &'s CaHandle, aspas: &'s [AspaDefinition]
    ) -> bool {
        let mut files = self.expected_objects(ca);
        files.push_mft_and_crl(&ResourceClassName::from(0));
        files.extend(aspas.iter().map(|aspa| {
            ObjectName::aspa(aspa.customer()).to_string()
        }));
        files.wait_for_published()
    }

    /// Returns the current ASPA definitions.
    fn aspa_definitions(&self, ca: &CaHandle) -> AspaDefinitionList {
        self.client().aspas_list(ca).unwrap()
    }
}


//------------ Misc Helpers --------------------------------------------------

pub fn aspa_definition(s: &str) -> AspaDefinition {
    AspaDefinition::from_str(s).unwrap()
}

pub fn customer(s: &str) -> CustomerAsn {
    CustomerAsn::from_str(s).unwrap()
}

pub fn provider(s: &str) -> ProviderAsn {
    ProviderAsn::from_str(s).unwrap()
}

