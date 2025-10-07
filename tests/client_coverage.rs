//! Tests that all the client commands are working.

use std::str::FromStr;
use rpki::uri;
use rpki::repository::resources::ResourceSet;
use rpki::repository::x509::Time;
use krill::api;

use crate::common::KrillServer;

mod common;


//------------ Test Function -------------------------------------------------

/// Test various client commands.
///
/// This test executes all `KrillClient` API methods. It just runs the
/// methods to make sure the path of the request is recognised by the Krill
/// server and that output can be parsed.
///
/// The test is _not_ intended to check that the server processes these
/// commands correctly. This happens in other tests.
async fn client_coverage(server: KrillServer) {
    let ta = common::ca_handle("ta");
    let testbed = common::ca_handle("testbed");
    let parent = common::ca_handle("parent");
    let child = common::ca_handle("child");
    let surplus = common::ca_handle("surplus");
    let ca_res = common::resources("AS65000", "10.0.0.0/8", "");

    // Wait for the *testbed* CA to get its certificate, then set up two
    // CAs, “parent” directly under “testbed” and “child” under “parent.”
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );
    server.create_ca_with_repo(&parent).await;
    server.create_ca_with_repo(&child).await;
    server.register_ca_with_parent(&parent, &testbed, &ca_res).await;
    server.register_ca_with_parent(&child, &parent, &ca_res).await;

    server.client().authorized().await.unwrap();
    server.client().info().await.unwrap();
    server.client().bulk_issues().await.unwrap();
    server.client().bulk_sync_parents().await.unwrap();
    server.client().bulk_sync_repo().await.unwrap();
    server.client().bulk_publish().await.unwrap();
    server.client().bulk_force_publish().await.unwrap();
    server.client().bulk_suspend().await.unwrap();
    // bulk_import tested in functional_ca_import

    server.client().cas_list().await.unwrap();
    server.client().ca_add(surplus.clone()).await.unwrap();
    server.client().ca_details(&surplus).await.unwrap();
    server.client().ca_delete(&surplus).await.unwrap();
    server.client().ca_issues(&child).await.unwrap();
    server.client().ca_history_commands(
        &parent, None, None, None, None
    ).await.unwrap();
    server.client().ca_history_commands(
        &parent, None, None, None, Some(Time::now())
    ).await.unwrap();
    server.client().ca_history_commands(
        &parent, None, None, Some(Time::now()), Some(Time::now())
    ).await.unwrap();
    server.client().ca_history_details(
        &parent, "0"
    ).await.unwrap();
    // ca_init_keyroll and ca_activate_keyroll tested in functional_keyroll
    server.client().ca_update_id(&parent).await.unwrap();
    server.client().ca_sync_parents(&child).await.unwrap();

    server.client().child_connections(&parent).await.unwrap();
    // child_add tested above
    // child_import tested in functional_delegated_ca_import
    server.client().child_details(&parent, &child.convert()).await.unwrap();
    server.client().child_update(
        &parent, &child.convert(), api::admin::UpdateChildRequest::unsuspend()
    ).await.unwrap();
    server.client().child_contact(&parent, &child.convert()).await.unwrap();
    // child_export tested in functional_delegated_ca_import
    // child_delete tested in functional_parent_child
    server.client().child_request(&child).await.unwrap();

    server.client().parent_list(&parent).await.unwrap();
    // parent_add tested above
    server.client().parent_details(&parent, &testbed.convert()).await.unwrap();
    // parent_delete tested in functional_parent_child

    server.client().repo_request(&parent).await.unwrap();
    server.client().repo_details(&parent).await.unwrap();
    server.client().repo_status(&parent).await.unwrap();
    // repo_update tested variously

    let _ = server.client().roas_update(
        &child,
        api::roa::RoaConfigurationUpdates {
            added: vec![common::roa_conf("10.0.0.0/16-16 => 64496")],
            removed: vec![]
        }
    ).await.unwrap();
    server.client().roas_list(&child).await.unwrap();
    let update = api::roa::RoaConfigurationUpdates {
        added: vec![common::roa_conf("10.1.0.0/16-16 => 64496")],
        removed: vec![],
    };
    server.client().roas_dryrun_update(
        &child, update.clone()
    ).await.unwrap();
    server.client().roas_try_update(
        &child, update.clone()
    ).await.unwrap();
    server.client().roas_analyze(&child).await.unwrap();
    server.client().roas_suggest(&child, None).await.unwrap();
    server.client().roas_suggest(&child, Some(ca_res.clone())).await.unwrap();

    server.client().bgpsec_add_single(
        &child, common::asn("AS65000"),
        rpki::ca::csr::BgpsecCsr::decode(
            include_bytes!("../test-resources/bgpsec/router-csr.der").as_ref()
        ).unwrap(),
    ).await.unwrap();
    // bgpsec_delete_single boils down to the same API call, so not tested
    server.client().bgpsec_list(&child).await.unwrap();

    server.client().aspas_add_single(
        &child,
        api::aspa::AspaDefinition {
            customer: common::asn("AS65000"),
            providers: vec![common::asn("AS64496")]
        },
    ).await.unwrap();
    server.client().aspas_list(&child).await.unwrap();
    server.client().aspas_update_single(
        &child, common::asn("AS65000"),
        api::aspa::AspaProvidersUpdate {
            added: vec![common::asn("AS64497")],
            removed: vec![]
        },
    ).await.unwrap();

    server.client().publishers_list().await.unwrap();
    server.client().publishers_stale(30).await.unwrap();
    // publishers_add called above in create_ca_with_repo
    server.client().publisher_details(&child.convert()).await.unwrap();
    server.client().publisher_response(&child.convert()).await.unwrap();
    // publisher_delete tested in testbed

    // pubserver_init tested in functional_ta
    server.client().pubserver_delete_files(
        uri::Rsync::from_str("rsync://localhost/testbed/bla").unwrap()
    ).await.unwrap();
    server.client().pubserver_stats().await.unwrap();
    server.client().pubserver_session_reset().await.unwrap();
    server.client().publisher_delete(&ta.convert()).await.unwrap();
    server.client().publisher_delete(&testbed.convert()).await.unwrap();
    server.client().publisher_delete(&parent.convert()).await.unwrap();
    server.client().publisher_delete(&child.convert()).await.unwrap();
    server.client().pubserver_clear().await.unwrap();

    // testbed commands tested in testbed
    // ta_proxy commands tests in functional_ta
}

#[tokio::test]
async fn http() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed().await;
    client_coverage(server).await;
}

#[tokio::test]
#[cfg(unix)]
async fn unix() {
    use std::collections::HashMap;

    let (mut config, _tempdir) = common::TestConfig::mem_storage()
        .enable_testbed().enable_ca_refresh().finalize();

    // The user that is executing the test gets access to everything
    let uid = nix::unistd::Uid::current();
    let user = nix::unistd::User::from_uid(uid).unwrap().unwrap();
    let file_sock = tempfile::NamedTempFile::new().unwrap();
    config.unix_socket = Some(file_sock.path().into());
    config.unix_users = HashMap::from([(user.name, "admin".to_string())]);
    let server = common::KrillServer::start_with_config_unix(config).await;
    client_coverage(server).await;
}