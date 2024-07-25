//! Tests running a CA under a remote parent and repo

use rpki::repository::resources::ResourceSet;
use krill::commons::api::{ObjectName, ParentCaReq, RoaConfigurationUpdates};

mod common;


//------------ Test Function -------------------------------------------------

#[tokio::test]
async fn remote_parent_and_repo() {
    // Start two testbeds
    let (server1, _tmp1) = common::KrillServer::start_with_testbed().await;
    let (server2, _tmp2)
        = common::KrillServer::start_second_with_testbed().await;

    let testbed = common::ca_handle("testbed");
    let ca1 = common::ca_handle("CA1");
    let ca1_res = common::ipv4_resources("10.0.0.0/16");
    let ca1_roa = common::roa_payload("10.0.0.0/16-16 => 65000");
    let ca1_roa_name = ObjectName::from(&ca1_roa).to_string();
    let rcn0 = common::rcn(0);

    // Wait for the *testbed* CA to get its certificate, this means
    // that all CAs which are set up as part of krill_start under the
    // testbed config have been set up.
    assert!(
        server1.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    eprintln!(">>>> Create up CA1 in second server.");
    server2.client().ca_add(ca1.clone()).await.unwrap();

    eprintln!(">>>> Set up CA1 as a child to testbed on first server.");
    let req = server2.client().child_request(&ca1).await.unwrap();
    let id_cert = req.validate().unwrap();
    let response = server1.client().child_add(
        &testbed, ca1.convert(), ca1_res.clone(), id_cert
    ).await.unwrap();
    server2.client().parent_add(
        &ca1,
        ParentCaReq::new(testbed.convert(), response)
    ).await.unwrap();

    eprintln!(">>>> Set up CA1 as a publisher.");
    let req = server2.client().repo_request(&ca1).await.unwrap();
    let response = server1.client().publishers_add(req).await.unwrap();
    server2.client().repo_update(&ca1, response).await.unwrap();

    // Wait a bit so that CA1 can request a certificate from testbed
    assert!(server2.wait_for_ca_resources(&ca1, &ca1_res).await);

    eprintln!(">>>> Create a ROA for CA1.");
    server2.client().roas_update(
        &ca1,
        RoaConfigurationUpdates::new(
            vec![ca1_roa.into()], vec![]
        )
    ).await.unwrap();

    eprintln!(">>>> Verify that CA1 publishes.");
    let mut files = server2.expected_objects(&ca1);
    files.push_mft_and_crl(&rcn0).await;
    files.push(ca1_roa_name.clone());
    assert!(files.wait_for_published_at(&server1).await);
}
