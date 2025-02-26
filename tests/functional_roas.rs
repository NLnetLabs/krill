//! Test ROA management.

use rpki::ca::idexchange::CaHandle;
use rpki::repository::resources::ResourceSet;
use krill::commons::api::admin::UpdateChildRequest;
use krill::commons::api::ca::ObjectName;
use krill::commons::api::roa::{RoaConfiguration, RoaConfigurationUpdates};

mod common;


//------------ Test Function -------------------------------------------------

/// Test ROA management.
///
/// The setup:
///
/// ```text
///      TA
///       |
///    testbed
///       |
///      CA
/// ```
#[tokio::test]
async fn functional_roas() {
    let (server, _tmpdir) = common::KrillServer::start_with_testbed().await;

    let testbed = common::ca_handle("testbed");
    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS65000", "10.0.0.0/8", "");
    let ca_res_shrunk = common::resources("AS65000", "10.0.0.0/16", "");

    let route_resource_set_10_0_0_0_def_1 =
        common::roa_conf("10.0.0.0/16-16 => 64496");
    let route_resource_set_10_0_0_0_def_2 =
        common::roa_conf("10.0.0.0/16-16 => 64497");
    let route_resource_set_10_0_0_0_def_3 =
        common::roa_conf("10.0.0.0/24-24 => 64496");
    let route_resource_set_10_0_0_0_def_4 =
        common::roa_conf("10.0.0.0/24-24 => 64497");

    // The following definition will be removed in the shrunk set
    let route_resource_set_10_1_0_0_def_1 =
        common::roa_conf("10.1.0.0/24-24 => 64496 # will be shrunk");

    let rcn0 = common::rcn(0);

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up CA under testbed.");
    server.create_ca_with_repo(&ca).await;
    server.register_ca_with_parent(&ca, &testbed, &ca_res).await;

    eprintln!(">>>> Add ROAs to CA.");
    server.client().roas_update(
        &ca,
        RoaConfigurationUpdates {
            added: vec![
                route_resource_set_10_0_0_0_def_1.clone(),
                route_resource_set_10_0_0_0_def_2.clone(),
                route_resource_set_10_1_0_0_def_1.clone(),
            ],
            removed: vec![],
        }
    ).await.unwrap();
    assert!(
        server.check_configured_roas(
            &ca,
            &[
                route_resource_set_10_0_0_0_def_1.clone(),
                route_resource_set_10_0_0_0_def_2.clone(),
                route_resource_set_10_1_0_0_def_1.clone(),
            ]
        ).await
    );
    assert!(
        server.wait_for_objects(
            &ca,
            &[
                &route_resource_set_10_0_0_0_def_1,
                &route_resource_set_10_0_0_0_def_2,
                &route_resource_set_10_1_0_0_def_1,
            ]
        ).await
    );

    eprintln!(">>>> Shrink resources, expect affected ROAs to disappear.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::resources(ca_res_shrunk.clone())
    ).await.unwrap();
    assert!(
        server.wait_for_objects(
            &ca,
            &[
                &route_resource_set_10_0_0_0_def_1,
                &route_resource_set_10_0_0_0_def_2,
                //&route_resource_set_10_1_0_0_def_1, // gone.
            ]
        ).await
    );

    eprintln!(">>>> Extend resources, expect affected ROAs to reappear.");
    server.client().child_update(
        &testbed, &ca.convert(),
        UpdateChildRequest::resources(ca_res.clone())
    ).await.unwrap();
    assert!(
        server.wait_for_objects(
            &ca,
            &[
                &route_resource_set_10_0_0_0_def_1,
                &route_resource_set_10_0_0_0_def_2,
                &route_resource_set_10_1_0_0_def_1, // back
            ]
        ).await
    );

    eprintln!(">>>> Add ROAs beyond aggregation limit and they aggregate.");
    server.client().roas_update(
        &ca,
        RoaConfigurationUpdates {
            added: vec![
                route_resource_set_10_0_0_0_def_3.clone(),
                route_resource_set_10_0_0_0_def_4.clone()
            ],
            removed: vec![],
        }
    ).await.unwrap();
    let mut files = server.expected_objects(&ca);
    files.push_mft_and_crl(&rcn0).await;
    files.push("AS64496.roa".into());
    files.push("AS64497.roa".into());
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Remove ROAs below the de-aggregation threshold again.");
    server.client().roas_update(
        &ca,
        RoaConfigurationUpdates {
            added: vec![],
            removed: vec![
                route_resource_set_10_0_0_0_def_2.payload,
                route_resource_set_10_0_0_0_def_3.payload,
                route_resource_set_10_0_0_0_def_4.payload,
                route_resource_set_10_1_0_0_def_1.payload,
            ],
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

    eprintln!(">>>> Sanity check the operation of the RRDP endpoint.");
    // Verify that requesting rrdp/ on a CA-only instance of Krill results
    // in an error rather than a panic.
    assert!(server.http_get_404("rrdp/").await);
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

