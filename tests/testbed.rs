#![type_length_limit = "5000000"]

extern crate krill;

#[tokio::test]
async fn add_and_remove_certificate_authority() {
    use std::fs;
    use std::matches;
    use std::str::FromStr;

    use rpki::{
        ca::idexchange::{Handle, PublisherRequest, RepositoryResponse},
        repository::resources::ResourceSet,
    };

    use krill::commons::api::*;
    use krill::commons::util::httpclient::*;
    use krill::daemon::ca::testbed_ca_handle;
    use krill::test::*;

    let dir = start_krill_with_default_test_config(true, true, false, false).await;

    // -------------------------------------------------------------------------
    // establish/verify starting conditions
    // -------------------------------------------------------------------------

    // verify that the testbed CA has been created with the expected resources
    let asns = "0-4294967295";
    let v4 = "0.0.0.0/0";
    let v6 = "::0/0";
    let expected_resources = ResourceSet::from_strs(asns, v4, v6).unwrap();
    let testbed_ca_handle = testbed_ca_handle();
    assert!(ca_contains_resources(&testbed_ca_handle, &expected_resources).await);

    // verify that the testbed publisher has been created
    assert_eq!(
        testbed_ca_handle,
        publisher_details(testbed_ca_handle.convert()).await.handle().convert()
    );

    // verify that the testbed REST API is enabled
    assert!(get_ok(&format!("{}testbed/enabled", KRILL_SERVER_URI), None)
        .await
        .is_ok());

    // create a dummy CA that we can register with the testbed
    let dummy_ca_handle = Handle::from_str("dummy").unwrap();
    init_ca(&dummy_ca_handle).await;

    // -------------------------------------------------------------------------
    // verify registration of a child CA with the testbed
    // -------------------------------------------------------------------------

    // verify that the child CA doesn't have a parent
    assert_eq!(0, ca_details(&dummy_ca_handle).await.parents().len());

    // get the CA's child request details just like testbed web UI would extract
    // these from user provided <child_request/> XML
    let rfc8183_child_request = request(&dummy_ca_handle).await;

    // verify that we can register a child CA with the testbed in the same way
    // that an API client (such as the testbed web UI) would do.
    // <child_request/>   --> testbed
    // <parent_response/> <-- testbed
    let (child_id_cert, _, _) = rfc8183_child_request.unpack();
    let add_child_response: ParentCaContact = post_json_with_response(
        &format!("{}testbed/children", KRILL_SERVER_URI),
        &AddChildRequest::new(
            dummy_ca_handle.convert(),
            ResourceSet::from_strs("AS1", "", "").unwrap(),
            child_id_cert,
        ),
        None, // no token, the testbed API should be open
    )
    .await
    .unwrap();

    assert!(matches!(add_child_response, ParentCaContact::Rfc6492(_)));

    // verify that the testbed shows that it now has the expected child CA
    let testbed_ca = ca_details(&testbed_ca_handle).await;
    let testbed_children = testbed_ca.children();
    assert_eq!(1, testbed_children.len());
    assert_eq!(dummy_ca_handle, testbed_children[0].convert());

    // verify that the child CA still doesn't have a parent
    assert_eq!(0, ca_details(&dummy_ca_handle).await.parents().len());

    // verify that we can obtain the <parent_response/> XML as the testbed UI
    // would do so that it can present the XML to the end user
    let parent_response_xml = get_text(
        &format!(
            "{}testbed/children/{}/parent_response.xml",
            KRILL_SERVER_URI, &dummy_ca_handle
        ),
        None, // no token, the testbed API should be open
    )
    .await
    .unwrap();

    assert!(parent_response_xml.starts_with("\n<parent_response "));
    assert!(xml::reader::EventReader::from_str(&parent_response_xml).next().is_ok());

    // complete the RFC 8183 child registration process on the "client" side
    let parent_ca_req = ParentCaReq::new(testbed_ca_handle.convert(), add_child_response.clone());
    add_parent_to_ca(&dummy_ca_handle, parent_ca_req).await;

    // verify that the child CA now has the correct parent
    let dummy_ca = ca_details(&dummy_ca_handle).await;
    let dummy_ca_parents = dummy_ca.parents();
    let expected_parent_info = ParentInfo::new(testbed_ca_handle.convert(), add_child_response);
    let actual_parent_info = &dummy_ca_parents[0];
    assert_eq!(1, dummy_ca_parents.len());
    assert_eq!(&expected_parent_info, actual_parent_info);

    // -------------------------------------------------------------------------
    // verify registration of a child publisher with the testbed
    // -------------------------------------------------------------------------

    // verify that the child CA isn't configured to publish to a repository
    assert!(ca_details(&dummy_ca_handle).await.repo_info().is_none());

    // verify that the testbed doesn't have a publisher for the child CA yet
    let publishers = list_publishers().await;
    let publisher_found = publishers
        .publishers()
        .iter()
        .any(|ps: &PublisherSummary| ps.handle().as_str() == dummy_ca_handle.as_str());
    assert!(!publisher_found);

    // get the CA's publisher request details just like testbed web UI would
    // extract these from user provided <publisher_request/> XML
    let rfc8183_publisher_request = publisher_request(&dummy_ca_handle).await;
    let id_cert = rfc8183_publisher_request.id_cert().clone();

    // verify that we can register a publisher with the testbed in the same way
    // that an API client (such as the testbed web UI) would do.
    // <publisher_request/>   --> testbed
    // <repository_response/> <-- testbed
    let repository_response: RepositoryResponse = post_json_with_response(
        &format!("{}testbed/publishers", KRILL_SERVER_URI),
        &PublisherRequest::new(
            id_cert,
            dummy_ca_handle.convert(),
            None, // no tag
        ),
        None, // no token, the testbed API should be open
    )
    .await
    .unwrap();

    // verify that the testbed now has a publisher for the child CA
    let publishers = list_publishers().await;
    let publisher_found = publishers
        .publishers()
        .iter()
        .any(|ps: &PublisherSummary| ps.handle().as_str() == dummy_ca_handle.as_str());

    assert!(publisher_found);

    // verify that the child CA still isn't configured to publish to a repository
    assert!(ca_details(&dummy_ca_handle).await.repo_info().is_none());

    // complete the RFC 8183 publisher registration process on the "client" side
    ca_repo_update_rfc8181(&dummy_ca_handle, repository_response).await;

    // verify that the child CA is now configured to publish to a repository
    assert!(ca_details(&dummy_ca_handle).await.repo_info().is_some());

    // -------------------------------------------------------------------------
    // verify unregistration of the child CA with the testbed
    // -------------------------------------------------------------------------

    // unregister the child CA publisher with the testbed
    assert!(delete(
        &format!("{}testbed/publishers/{}", KRILL_SERVER_URI, &dummy_ca_handle),
        None
    )
    .await
    .is_ok());

    // verify that the testbed shows that it no longer has the child publisher
    let publishers = list_publishers().await;
    let publisher_found = publishers
        .publishers()
        .iter()
        .any(|ps: &PublisherSummary| ps.handle().as_str() == dummy_ca_handle.as_str());
    assert!(!publisher_found);

    // unregister the child CA with the testbed
    assert!(delete(
        &format!("{}testbed/children/{}", KRILL_SERVER_URI, &dummy_ca_handle),
        None
    )
    .await
    .is_ok());

    // verify that the testbed shows that it no longer has any children
    assert_eq!(0, ca_details(&testbed_ca_handle).await.children().len());

    // -------------------------------------------------------------------------
    // verify that the testbed TAL can be downloaded at the alternate location
    // that results in a more helpful name on the Relying Party (assuming that
    // the RP, like Routinator, uses the TAL filename by default to identify the
    // RPKI hierarchy being queried).
    // -------------------------------------------------------------------------
    let org_tal = get_text(&format!("{}ta/ta.tal", KRILL_SERVER_URI), None).await.unwrap();
    let renamed_tal = get_text(&format!("{}testbed.tal", KRILL_SERVER_URI), None)
        .await
        .unwrap();
    assert_eq!(org_tal, renamed_tal);

    let _ = fs::remove_dir_all(dir);
}
