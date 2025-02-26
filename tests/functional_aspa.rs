//! Test manipulating ASPA definitions.

use std::slice;
use std::str::FromStr;
use reqwest::StatusCode;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use rpki::repository::resources::ResourceSet;
use krill::commons::api::aspa::{
    AspaDefinition, AspaDefinitionList, AspaProvidersUpdate, CustomerAsn,
    ProviderAsn,
};
use krill::commons::api::ca::ObjectName;
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
#[tokio::test]
async fn functional_aspa() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed().await;

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS65000", "10.0.0.0/16", "");

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up 'CA' under 'testbed'.");
    server.create_ca_with_repo(&ca).await;
    server.register_ca_with_parent(&ca, &testbed, &ca_res).await;

    eprintln!(">>>> Reject ASPA without providers.");
    let aspa = aspa_definition("AS65000 => <none>");
    assert!(!server.try_add_aspa(&ca, aspa.clone()).await);
    assert!(server.wait_for_objects(&ca, &[]).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), &[]);

    eprintln!(">>>> Reject ASPA using customer as provider.");
    let aspa = aspa_definition("AS65000 => AS65000, AS65003, AS65005");
    assert!(!server.try_add_aspa(&ca, aspa.clone()).await);
    assert!(server.wait_for_objects(&ca, &[]).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), &[]);

    eprintln!(">>>> Add an ASPA under CA.");
    let aspa = aspa_definition("AS65000 => AS65002, AS65003, AS65005");
    assert!(server.try_add_aspa(&ca, aspa.clone()).await);
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), aspas);

    eprintln!(">>>> Update an existing ASPA.");
    assert!(server.try_update_aspa(
        &ca, "AS65000", ["AS65006"], ["AS65002"]
    ).await);
    let aspa = aspa_definition("AS65000 => AS65003, AS65005, AS65006");
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), aspas);

    eprintln!(">>>> Reject update that adds customer as provider.");
    assert!(!server.try_update_aspa(&ca, "AS65000", ["AS65000"], []).await);
    // Use `aspas` from before.
    assert!(server.wait_for_objects(&ca, aspas).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), aspas);

    eprintln!(">>>> Removing all providers should result in delete.");
    assert!(server.try_update_aspa(
        &ca, "AS65000", [], ["AS65003", "AS65005", "AS65006"]
    ).await);
    assert!(server.wait_for_objects(&ca, &[]).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), &[]);

    eprintln!(">>>> Adding provider to non-existing customer should add it.");
    // This is useful for two reasons:
    // 1) it allows for automation using just updates
    // 2) because empty provider lists were accepted in Krill <0.13.0
    //    we need the code to deal with removing all providers, which
    //    will remove the AspaConfig when replayed, and then adding
    //    some provider again.
    assert!(server.try_update_aspa(
        &ca, "AS65000", ["AS65003", "AS65005", "AS65006"], []
    ).await);
    let aspa = aspa_definition("AS65000 => AS65003, AS65005, AS65006");
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), aspas);

    eprintln!(">>>> Add existing and remove nonexisting provider.");
    assert!(server.try_update_aspa(
        &ca, "AS65000",
        ["AS65002", "AS65005"],
        ["AS65006", "AS65007"],
    ).await);
    let aspa = aspa_definition("AS65000 => AS65002, AS65003, AS65005");
    let aspas = slice::from_ref(&aspa);
    assert!(server.wait_for_objects(&ca, aspas).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), aspas);

    eprintln!(">>>> Delete an existing ASPA.");
    server.client().aspas_delete_single(
        &ca, customer("AS65000")
    ).await.unwrap();
    assert!(server.wait_for_objects(&ca, &[]).await);
    assert_eq!(server.aspa_definitions(&ca).await.as_slice(), &[]);
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    /// Adds a single ASPA definition.
    ///
    /// Returns whether adding succeeded. Panics on error if anything other
    /// than the server refusing to add the ASPA happened.
    async fn try_add_aspa(
        &self, ca: &CaHandle, aspa: AspaDefinition
    ) -> bool {
        match self.client().aspas_add_single(ca, aspa).await {
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
    async fn try_update_aspa(
        &self,
        ca: &CaHandle,
        customer_str: &str,
        add: impl IntoIterator<Item=&str>,
        remove: impl IntoIterator<Item=&str>,
    ) -> bool {
        match self.client().aspas_update_single(
            ca,
            customer(customer_str),
            AspaProvidersUpdate {
                added: add.into_iter().map(provider).collect(),
                removed: remove.into_iter().map(provider).collect(),
            }
        ).await {
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
    async fn wait_for_objects<'s>(
        &'s self, ca: &'s CaHandle, aspas: &'s [AspaDefinition]
    ) -> bool {
        let mut files = self.expected_objects(ca);
        files.push_mft_and_crl(&ResourceClassName::from(0)).await;
        files.extend(aspas.iter().map(|aspa| {
            ObjectName::aspa_from_customer(aspa.customer).to_string()
        }));
        files.wait_for_published().await
    }

    /// Returns the current ASPA definitions.
    async fn aspa_definitions(&self, ca: &CaHandle) -> AspaDefinitionList {
        self.client().aspas_list(ca).await.unwrap()
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

