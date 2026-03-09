//! Various test cases for the publication server.

use std::str::FromStr;
use rpki::uri;
use rpki::ca::idexchange::CaHandle;
use rpki::repository::resources::ResourceSet;
use krill::api::ca::ObjectName;
use krill::api::roa::{RoaConfiguration, RoaConfigurationUpdates};

mod common;

//------------ clear_and_init ------------------------------------------------

/// This tests clears and then re-initialises the publication server.
///
/// The main point is to check that after re-registering a CA as publisher,
/// it publishes again.
#[tokio::test]
async fn clear_and_init() {
    let server = common::KrillServer::start_with_testbed().await;

    let ta = common::ca_handle("ta");
    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS65000", "10.0.0.0/8", "");

    let route_resource_set_10_0_0_0_def_1 =
        common::roa_conf("10.0.0.0/16-16 => 64496");

    // Wait for the *testbed* CA to get its certificate.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up CA under testbed.");
    server.create_ca_with_repo(&ca).await;
    server.register_ca_with_parent(&ca, &testbed, &ca_res).await;
    
    eprintln!(">>>> Add ROAs to CA.");
    eprintln!(">>>> Add ROAs to CA.");
    server.client().roas_update(
        &ca,
        RoaConfigurationUpdates {
            added: vec![
                route_resource_set_10_0_0_0_def_1.clone(),
            ],
            removed: vec![],
        }
    ).await.unwrap();

    assert!(
        server.wait_for_objects(
            &ca,
            &[
                &route_resource_set_10_0_0_0_def_1,
            ]
        ).await
    );

    // Delete the publisher and clear the repo.
    server.client().publisher_delete(&ta.convert()).await.unwrap();
    server.client().publisher_delete(&testbed.convert()).await.unwrap();
    server.client().publisher_delete(&ca.convert()).await.unwrap();
    server.client().pubserver_clear().await.unwrap();

    
    server.client().pubserver_init(
        uri::Https::from_str("https://localhost/rrdp/").unwrap(),
        uri::Rsync::from_str("rsync://localhost/repo/").unwrap(),
    ).await.unwrap();

    server.register_ca_with_repo(&ca).await;
    server.client().repo_refresh(&ca).await.unwrap();

    assert!(
        server.wait_for_objects(
            &ca,
            &[
                &route_resource_set_10_0_0_0_def_1,
            ]
        ).await
    );
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    pub async fn wait_for_objects(
        &self,
        ca: &CaHandle,
        roas: &[&RoaConfiguration]
    ) -> bool {
        let mut files = self.expected_objects(ca);
        files.push_mft_and_crl(&common::rcn(0)).await;
        for roa in roas {
            files.push(ObjectName::from(roa.payload).to_string());
        }
        files.wait_for_published().await
    }
}


