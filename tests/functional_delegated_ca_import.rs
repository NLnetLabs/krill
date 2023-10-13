//! Test export and import of a delegated CA child from
//! a parent in one Krill instance into a parent in another
//! Krill instance.

use krill::{
    cli::{
        options::{CaCommand, Command},
        report::ApiResponse,
    },
    commons::api::{
        import::{ExportChild, ImportChild},
        ParentCaReq, ResourceClassNameMapping, UpdateChildRequest,
    },
    test::*,
};
use rpki::{
    ca::{
        idexchange::{CaHandle, ParentResponse},
        provisioning::ResourceClassName,
    },
    repository::resources::ResourceSet,
};

#[tokio::test]
async fn functional_delegated_ca_import() {
    async fn start_testbed(port: u16) -> impl FnOnce() {
        let (data_dir, cleanup) = tmp_dir();
        let storage_uri = mem_storage();
        let mut config = test_config(&storage_uri, Some(&data_dir), true, true, false, false);
        config.port = port;
        start_krill(config).await;

        cleanup
    }

    // Start a testbed
    // Start a second testbed
    // Add child in testbed one
    //   - add child
    //   - override default resource class name for child
    //   - add parent to child
    // Export the child in testbed one
    // Import the child in testbed two
    // Update the child to use testbed two
    // Update the child resources

    let testbed = ca_handle("testbed");
    let child = ca_handle("child");
    let child_res = resources("AS65000", "10.0.0.0/16", "");
    let child_res_2 = resources("AS65000-AS65010", "10.0.0.0/8", "2001:db8::/32");
    let child_rcn = ResourceClassName::from("custom");

    // Start a testbed
    let testbed_1_clean = start_testbed(3000).await;

    // Start a second testbed
    let testbed_2_clean = start_testbed(3002).await;

    // Add child in testbed one
    set_up_ca_with_repo(&child).await;
    set_up_ca_under_parent_main_krill(&child, &testbed, &child_res, child_rcn).await;

    // Export the child
    let exported_child = export_child_main_krill(&testbed, &child).await;

    // Import child into testbed on the other server
    import_child_secondary_krill(&testbed, exported_child).await;

    // Add testbed in other server as parent to child
    let response = parent_contact_secondary_krill(&testbed, &child).await;
    let parent_ca_req = ParentCaReq::new(testbed.convert(), response);
    add_parent_to_ca(&child, parent_ca_req).await;

    // Remove the child from the original parent
    delete_child(&testbed, &child).await;

    // Update the resources for the child in the new
    // parent, then synchronise it, and verify that
    // the resources are received.
    update_child_resources_secondary_krill(&testbed, &child, &child_res_2).await;

    sleep_seconds(5).await; // because CI can be slow
    cas_refresh_single(&child).await;
    assert!(ca_contains_resources(&child, &child_res_2).await);

    testbed_1_clean();
    testbed_2_clean();
}

async fn export_child_main_krill(parent: &CaHandle, child: &CaHandle) -> ExportChild {
    match krill_admin(Command::CertAuth(CaCommand::ChildExport(
        parent.clone(),
        child.convert(),
    )))
    .await
    {
        ApiResponse::ChildExported(child) => child,
        _ => {
            panic!("Expected exported child")
        }
    }
}

async fn import_child_secondary_krill(parent: &CaHandle, child: ImportChild) {
    match krill2_admin(Command::CertAuth(CaCommand::ChildImport(parent.clone(), child))).await {
        ApiResponse::Empty => {}
        _ => {
            panic!("Expected exported child")
        }
    }
}

async fn set_up_ca_under_parent_main_krill(
    ca: &CaHandle,
    parent: &CaHandle,
    resources: &ResourceSet,
    child_rcn: ResourceClassName,
) {
    let child_request = request(ca).await;
    let parent_ca_req = {
        let response = add_child_rfc6492(parent.convert(), ca.convert(), child_request, resources.clone()).await;
        ParentCaReq::new(parent.convert(), response)
    };
    let mapping = ResourceClassNameMapping {
        name_in_parent: rcn(0),
        name_for_child: child_rcn,
    };
    krill_admin(krill::cli::options::Command::CertAuth(CaCommand::ChildUpdate(
        parent.convert(),
        ca.convert(),
        UpdateChildRequest::resource_class_name_mapping(mapping),
    )))
    .await;
    add_parent_to_ca(ca, parent_ca_req).await;
    assert!(ca_contains_resources(ca, resources).await);
}

async fn parent_contact_secondary_krill(ca: &CaHandle, child: &CaHandle) -> ParentResponse {
    match krill2_admin(Command::CertAuth(CaCommand::ParentResponse(
        ca.clone(),
        child.convert(),
    )))
    .await
    {
        ApiResponse::Rfc8183ParentResponse(response) => response,
        _ => panic!("Expected RFC 8183 Parent Response"),
    }
}

async fn update_child_resources_secondary_krill(ca: &CaHandle, child: &CaHandle, resources: &ResourceSet) {
    let child_handle = child.convert();
    let req = UpdateChildRequest::resources(resources.clone());
    match krill2_admin(Command::CertAuth(CaCommand::ChildUpdate(ca.clone(), child_handle, req))).await {
        ApiResponse::Empty => {}
        _ => panic!("Expected empty ok response"),
    }
}
