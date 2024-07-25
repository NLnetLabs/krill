//! Test migrating a CA to a different repository.

use rpki::rrdp;
use rpki::repository::resources::ResourceSet;
use krill::commons::api;
use krill::commons::util::httpclient;

mod common;


//------------ Test Function -------------------------------------------------

#[tokio::test]
async fn migrate_repository() {
    let testbed = common::ca_handle("testbed");

    let ca1 = common::ca_handle("CA1");
    let ca1_res = common::ipv4_resources("10.0.0.0/16");
    let ca1_roa = common::roa_payload("10.0.0.0/16-16 => 65000");
    let ca1_roa_name = api::ObjectName::from(&ca1_roa).to_string();

    let rcn0 = common::rcn(0);

    eprintln!(">>>> Start Krill.");
    // Use a 5 second RRDP update interval for the Krill server, so that we
    // can also test here that the re-scheduling of delayed RRDP deltas
    // works.
    let (server, _krilltmp) = common::KrillServer::start_with_config_testbed(
        |config| {
            config.rrdp_updates_config.rrdp_delta_interval_min_seconds = 5
        }
    ).await;

    eprintln!(">>>> Start a secondary publication server.");
    let (pubd, _pubtmp) = common::KrillServer::start_pubd(5).await;

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Set up CA1 under testbed.");
    server.create_ca_with_repo(&ca1).await;
    server.register_ca_with_parent(&ca1, &testbed, &ca1_res).await;

    eprintln!(">>>> Create a ROA for CA1.");
    server.client().roas_update(
        &ca1,
        api::RoaConfigurationUpdates::new(
            vec![ca1_roa.clone().into()], vec![]
        )
    ).await.unwrap();

    eprintln!(">>>> Verify that the testbed published the expected objects");
    let mut files = server.expected_objects(&testbed);
    files.push_mft_and_crl(&rcn0).await;
    files.push_cer(&ca1, &rcn0).await;
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Verify that CA1 publishes in the embedded repo.");
    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0).await;
    files.push(ca1_roa_name.clone());
    assert!(files.wait_for_published().await);

    eprintln!(">>>> Sanity check the operation of the RRDP endpoint.");
    // Verify that actual RRDP operation is roughly working as expected
    // (without writing an entire RPKI client into our test suite,
    // integration tests are better suited for testing with a full RPKI
    // client).

    // Verify that requesting rrdp/ on a publishing instance of Krill
    // results in a 404 Not Found error rather than a panic.
    assert!(server.http_get_404("rrdp/").await);

    // Verify that requesting garbage file and directory URLs results in
    // an error rather than a panic.
    assert!(server.http_get_404("rrdp/i/dont/exist").await);
    assert!(server.http_get_404("rrdp/i/dont/exist/").await);

    // Verify that we can fetch the notification XML.
    let notify = rrdp::NotificationFile::parse(
        server.http_get(
            "rrdp/notification.xml"
        ).await.unwrap().as_bytes()
    ).unwrap();

    // Verify that we can fetch the snapshot XML.
    let snapshot = httpclient::get_text(
        notify.snapshot().uri().as_str(), None
    ).await.unwrap();
    let _ = rrdp::Snapshot::parse(snapshot.as_bytes()).unwrap();

    // Verify that attempting to fetch a valid subdirectory results in an
    // error rather than a panic.
    assert!(common::check_not_found(
        httpclient::get_text(
            notify.snapshot().uri().parent().unwrap().as_str(), None
        ).await
    ));
    assert!(common::check_not_found(
        httpclient::get_text(
            notify.snapshot().uri().parent().unwrap()
                .as_str().strip_suffix('/').unwrap(),
            None
        ).await
    ));

    eprintln!(">>>> Migrate a Repository for CA1 (using a keyroll).");
    // CA1 currently uses the embedded publication server. In order
    // to migrate it, we will need to do the following:
    //
    // - get the RFC 8183 publisher request from CA1
    // - add CA1 as a publisher under the dedicated (separate) pubd,
    // - get the response
    // - update the repo config for CA1 using the 8183 response
    //    - this should initiate a key roll
    //    - the new key publishes in the new repo
    // - complete the key roll
    //    - the old key should be cleaned up,
    //    - nothing published for CA1 in the embedded repo

    // Add CA1 to dedicated repo
    let request = server.client().repo_request(&ca1).await.unwrap();
    let response = pubd.client().publishers_add(request).await.unwrap();
    assert_eq!(
        response,
        pubd.client().publisher_response(&ca1.convert()).await.unwrap()
    );

    // Wait a tiny bit.. when we add a new repo we check that it's
    // available or it will be rejected.
    common::sleep_seconds(1).await;

    // Update CA1 to use dedicated repo
    server.client().repo_update(&ca1, response).await.unwrap();

    // This should result in a key roll and content published in both repos
    assert!(server.wait_for_state_new_key(&ca1).await);

    // Expect that CA1 still publishes two current keys in the embedded repo
    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0).await;
    files.push(ca1_roa_name.clone());
    assert!(files.wait_for_published().await);

    // Expect that CA1 publishes two new keys in the dedicated repo
    let mut files = server.expected_objects(&ca1);
    files.push_new_key_mft_and_crl(&rcn0).await;
    assert!(files.wait_for_published_at(&pubd).await);

    // Complete the keyroll, this should remove the content in the
    // embedded repo
    server.client().ca_activate_keyroll(&ca1).await.unwrap();
    assert!(server.wait_for_state_active(&ca1).await);

    // Expect that CA1 publishes two current keys in the dedicated repo
    let mut files = server.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0).await;
    files.push(ca1_roa_name.clone());
    assert!(files.wait_for_published_at(&pubd).await);

    // Expect that CA1 publishes nothing in the embedded repo
    assert!(server.expected_objects(&ca1).wait_for_published().await);
}

