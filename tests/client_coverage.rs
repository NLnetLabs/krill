//! Tests that all the client commands are working.

use std::str::FromStr;
use rpki::uri;
use rpki::repository::resources::ResourceSet;
use rpki::repository::x509::Time;
use krill::commons::api;

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
#[test]
fn client_coverage() {
    let (server, _tempdir) = common::KrillServer::start_with_testbed();

    let ta = common::ca_handle("ta");
    let testbed = common::ca_handle("testbed");
    let parent = common::ca_handle("parent");
    let child = common::ca_handle("child");
    let surplus = common::ca_handle("surplus");
    let ca_res = common::resources("AS65000", "10.0.0.0/8", "");

    // Wait for the *testbed* CA to get its certificate, then set up two
    // CAs, “parent” directly under “testbed” and “child” under “parent.”
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all())
    );
    server.create_ca_with_repo(&parent);
    server.create_ca_with_repo(&child);
    server.register_ca_with_parent(&parent, &testbed, &ca_res);
    server.register_ca_with_parent(&child, &parent, &ca_res);

    server.client().authorized().unwrap();
    server.client().info().unwrap();
    server.client().bulk_issues().unwrap();
    server.client().bulk_sync_parents().unwrap();
    server.client().bulk_sync_repo().unwrap();
    server.client().bulk_publish().unwrap();
    server.client().bulk_force_publish().unwrap();
    server.client().bulk_suspend().unwrap();
    // bulk_import tested in functional_ca_import

    server.client().cas_list().unwrap();
    server.client().ca_add(surplus.clone()).unwrap();
    server.client().ca_details(&surplus).unwrap();
    server.client().ca_delete(&surplus).unwrap();
    server.client().ca_issues(&child).unwrap();
    server.client().ca_history_commands(
        &parent, None, None, None, None
    ).unwrap();
    server.client().ca_history_commands(
        &parent, None, None, None, Some(Time::now())
    ).unwrap();
    server.client().ca_history_commands(
        &parent, None, None, Some(Time::now()), Some(Time::now())
    ).unwrap();
    server.client().ca_history_details(
        &parent, "0"
    ).unwrap();
    // ca_init_keyroll and ca_activate_keyroll tested in functional_keyroll
    server.client().ca_update_id(&parent).unwrap();
    server.client().ca_sync_parents(&child).unwrap();

    server.client().child_connections(&parent).unwrap();
    // child_add tested above
    // child_import tested in functional_delegated_ca_import
    server.client().child_details(&parent, &child.convert()).unwrap();
    server.client().child_update(
        &parent, &child.convert(), api::UpdateChildRequest::unsuspend()
    ).unwrap();
    server.client().child_contact(&parent, &child.convert()).unwrap();
    // child_export tested in functional_delegated_ca_import
    // child_delete tested in functional_parent_child
    server.client().child_request(&child).unwrap();

    server.client().parent_list(&parent).unwrap();
    // parent_add tested above
    server.client().parent_details(&parent, &testbed.convert()).unwrap();
    // parent_delete tested in functional_parent_child

    server.client().repo_request(&parent).unwrap();
    server.client().repo_details(&parent).unwrap();
    server.client().repo_status(&parent).unwrap();
    // repo_update tested variously

    let _ = server.client().roas_update(
        &child,
        api::RoaConfigurationUpdates::new(
            vec![common::roa_conf("10.0.0.0/16-16 => 64496")],
            vec![]
        )
    ).unwrap();
    server.client().roas_list(&child).unwrap();
    let update = api::RoaConfigurationUpdates::new(
        vec![common::roa_conf("10.1.0.0/16-16 => 64496")],
        vec![]
    );
    server.client().roas_dryrun_update(
        &child, update.clone()
    ).unwrap();
    server.client().roas_try_update(
        &child, update.clone()
    ).unwrap();
    server.client().roas_analyze(&child).unwrap();
    server.client().roas_suggest(&child, None).unwrap();
    server.client().roas_suggest(&child, Some(ca_res.clone())).unwrap();

    server.client().bgpsec_add_single(
        &child, common::asn("AS65000"),
        rpki::ca::csr::BgpsecCsr::decode(
            include_bytes!("../test-resources/bgpsec/router-csr.der").as_ref()
        ).unwrap(),
    ).unwrap();
    // bgpsec_delete_single boils down to the same API call, so not tested
    server.client().bgpsec_list(&child).unwrap();

    server.client().aspas_add_single(
        &child,
        api::AspaDefinition::new(
            common::asn("AS65000"), vec![common::asn("AS64496")]
        )
    ).unwrap();
    server.client().aspas_list(&child).unwrap();
    server.client().aspas_update_single(
        &child, common::asn("AS65000"),
        api::AspaProvidersUpdate::new(vec![common::asn("AS64497")], vec![])
    ).unwrap();

    server.client().publishers_list().unwrap();
    server.client().publishers_stale(30).unwrap();
    // publishers_add called above in create_ca_with_repo
    server.client().publisher_details(&child.convert()).unwrap();
    server.client().publisher_response(&child.convert()).unwrap();
    // publisher_delete tested in testbed

    // pubserver_init tested in functional_ta
    server.client().pubserver_delete_files(
        uri::Rsync::from_str("rsync://localhost/testbed/bla").unwrap()
    ).unwrap();
    server.client().pubserver_stats().unwrap();
    server.client().pubserver_session_reset().unwrap();
    server.client().publisher_delete(&ta.convert()).unwrap();
    server.client().publisher_delete(&testbed.convert()).unwrap();
    server.client().publisher_delete(&parent.convert()).unwrap();
    server.client().publisher_delete(&child.convert()).unwrap();
    server.client().pubserver_clear().unwrap();

    // testbed commands tested in testbed
    // ta_proxy commands tests in functional_ta
}

