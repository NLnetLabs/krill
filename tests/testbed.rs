//! Test the testbed.

use rpki::ca::idexchange;
use rpki::repository::resources::ResourceSet;
use krill::commons::api::{ParentCaReq, ParentInfo};

mod common;


//------------ Test Function -------------------------------------------------

#[tokio::test]
async fn add_and_remove_certificate_authority() {
    let (config, _tmpdir) = common::TestConfig::mem_storage()
        .enable_testbed().enable_ca_refresh().finalize();
    let server = common::KrillServer::start_with_config(config).await;

    let ca = common::ca_handle("CA");
    let ca_res = common::resources("AS1", "", "");
    let testbed = common::ca_handle("testbed");

    eprintln!(">>>> Establish/verify starting conditions.");
    // Verify that the testbed CA has been created with the expected resources
    assert!(
        server.wait_for_ca_resources(&testbed, &ResourceSet::all()).await
    );

    // Verify that the testbed publisher has been created
    assert_eq!(
        testbed,
        server.client().publisher_details(&testbed.convert()).await.unwrap()
            .handle().convert()
    );

    // verify that the testbed REST API is enabled.
    server.client().testbed_enabled().await.unwrap();

    // Create a CA that we can register with the testbed.
    server.client().ca_add(ca.clone()).await.unwrap();

    eprintln!(">>>> Verify registration of a child CA with the testbed");

    // Verify that the child CA doesn't have a parent.
    assert_eq!(
        server.client().ca_details(&ca).await.unwrap().parents().len(),
        0
    );

    // get the CA's child request details just like testbed web UI would
    // extract these from user provided <child_request/> XML
    let request = server.client().child_request(&ca).await.unwrap();

    // verify that we can register a child CA with the testbed in the same way
    // that an API client (such as the testbed web UI) would do.
    // <child_request/>   --> testbed
    // <parent_response/> <-- testbed
    let id_cert = request.validate().unwrap();
    let response = server.client().testbed_child_add(
        ca.convert(), ca_res.clone(), id_cert
    ).await.unwrap();
        
    // verify that the testbed shows that it now has the expected child CA
    let testbed_ca = server.client().ca_details(&testbed).await.unwrap();
    let testbed_children = testbed_ca.children();
    assert_eq!(testbed_children.len(), 1);
    assert_eq!(testbed_children[0].convert(), ca);

    // verify that the child CA still doesn't have a parent
    assert_eq!(
        server.client().ca_details(&ca).await.unwrap().parents().len(),
        0
    );

    // verify that we can obtain the <parent_response/> XML as the testbed UI
    // would do so that it can present the XML to the end user.
    let response_xml = server.client().testbed_child_response(
        &ca.convert()
    ).await.unwrap();
    let _ = idexchange::ParentResponse::parse(
        response_xml.as_bytes()
    ).unwrap();

    // complete the RFC 8183 child registration process on the "client" side
    server.client().parent_add(
        &ca,
        ParentCaReq::new(testbed.convert(), response.clone())
    ).await.unwrap();

    // verify that the child CA now has the correct parent
    assert_eq!(
        *server.client().ca_details(&ca).await.unwrap().parents(),
        vec![ParentInfo::new(testbed.convert())]
    );

    eprintln!(">>>> Verify registration of child publisher with testbed.");

    // Verify that the child CA isn't configured to publish to a repository
    assert!(
        server.client().ca_details(&ca).await.unwrap().repo_info().is_none()
    );

    // Verify that the testbed doesn't have a publisher for the child CA yet
    let publishers = server.client().publishers_list().await.unwrap();
    let publisher_found = publishers.publishers().iter().any(|ps| {
        ps.handle().as_str() == ca.as_str()
    });
    assert!(!publisher_found);

    // Get the CA's publisher request details just like testbed web UI would
    // extract these from user provided <publisher_request/> XML
    let request = server.client().repo_request(&ca).await.unwrap();
    let id_cert = request.id_cert().clone();

    // Verify that we can register a publisher with the testbed in the same
    // way that an API client (such as the testbed web UI) would do.
    // <publisher_request/>   --> testbed
    // <repository_response/> <-- testbed
    let response = server.client().testbed_publishers_add(
        idexchange::PublisherRequest::new(
            id_cert,
            ca.convert(),
            None, // no tag
        )
    ).await.unwrap();

    // verify that the testbed now has a publisher for the child CA
    let publishers = server.client().publishers_list().await.unwrap();
    let publisher_found = publishers.publishers().iter().any(|ps| {
        ps.handle().as_str() == ca.as_str()
    });
    assert!(publisher_found);

    // Verify that the child CA still isn't configured to publish to a
    // repository
    assert!(
        server.client().ca_details(&ca).await.unwrap().repo_info().is_none()
    );

    // Complete the RFC 8183 publisher registration process on the "client"
    // side
    server.client().repo_update(&ca, response).await.unwrap();

    // verify that the child CA is now configured to publish to a repository
    assert!(
        server.client().ca_details(&ca).await.unwrap().repo_info().is_some()
    );

    eprintln!(">>>> Verify unregistration of the child CA with the testbed.");
    server.client().testbed_publisher_delete(&ca).await.unwrap();

    // Verify that the testbed shows that it no longer has the child publisher
    let publishers = server.client().publishers_list().await.unwrap();
    let publisher_found = publishers.publishers().iter().any(|ps| {
        ps.handle().as_str() == ca.as_str()
    });
    assert!(!publisher_found);

    // Unregister the child CA with the testbed
    server.client().testbed_child_delete(&ca).await.unwrap();

    // Verify that the testbed shows that it no longer has any children
    assert_eq!(
        server.client().ca_details(&testbed).await.unwrap().children().len(),
        0
    );

    eprintln!("Verify that the testbed TAL can be downloaded.");
    // Verify that the testbed TAL can be downloaded at the alternate location
    // that results in a more helpful name on the Relying Party (assuming that
    // the RP, like Routinator, uses the TAL filename by default to identify
    // the RPKI hierarchy being queried).
    assert_eq!(
        server.client().testbed_tal().await.unwrap(),
        server.client().testbed_renamed_tal().await.unwrap()
    );
}
