//! Test export and import of a delegated CA child from
//! a parent in one Krill instance into a parent in another
//! Krill instance.

use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use krill::api;
use rpki::repository::resources::ResourceSet;

mod common;


//------------ Test Function -------------------------------------------------

#[tokio::test]
async fn functional_delegated_ca_import() {
    // Start two testbeds
    let (server1, _tmp1) = common::KrillServer::start_with_testbed().await;
    let (server2, _tmp2)
        = common::KrillServer::start_second_with_testbed().await;

    let testbed = common::ca_handle("testbed");
    let parent_1 = common::ca_handle("parent_1");
    let parent_2 = common::ca_handle("parent_2");

    let parent_res = ResourceSet::all();

    let child = common::ca_handle("child");
    let child_res = common::resources("AS65000", "10.0.0.0/16", "");
    let child_res_2 = common::resources(
        "AS65000-AS65010", "10.0.0.0/8", "2001:db8::/32"
    );
    let child_rcn = ResourceClassName::from("custom");

    eprintln!(">>>> Add parent1 under testbed in server 1.");
    server1.add_ca_under_parent(&parent_1, &testbed, &parent_res, None).await;

    eprintln!(">>>> Add child under parent1 in server 1.");
    server1.add_ca_under_parent(
        &child, &parent_1, &child_res, Some(&child_rcn)
    ).await;

    eprintln!(">>>> Export the child.");
    let exported = server1.client().child_export(
        &parent_1, &child.convert(),
    ).await.unwrap();

    eprintln!(">>>> Add parent2 under testbed in server 2.");
    server2.add_ca_under_parent(&parent_2, &testbed, &parent_res, None).await;

    eprintln!(">>>> Import child under parent2.");
    server2.client().child_import(&parent_2, exported).await.unwrap();

    eprintln!(">>>> Add parent2 as the parent of child.");
    let response = server2.client().child_contact(
        &parent_2, &child.convert()
    ).await.unwrap();
    server1.client().parent_add(
        &child,
        api::admin::ParentCaReq { handle: parent_2.convert(), response }
    ).await.unwrap();

    eprintln!(">>>> Remove the child from the original parent.");
    server1.client().child_delete(&parent_1, &child.convert()).await.unwrap();

    eprintln!(">>>> Update the resources for the child in parent2.");
    server2.client().child_update(
        &parent_2, &child.convert(),
        api::admin::UpdateChildRequest::resources(child_res_2.clone())
    ).await.unwrap();

    eprintln!(">>>> Verify that the resources are received.");
    assert!(server1.wait_for_ca_resources(&child, &child_res_2).await);
}


//------------ Extend KrillServer --------------------------------------------

impl common::KrillServer {
    async fn add_ca_under_parent(
        &self, ca: &CaHandle, parent: &CaHandle, resources: &ResourceSet,
        child_rcn: Option<&ResourceClassName>,
    ) {
        self.create_ca_with_repo(ca).await;
        let request = self.client().child_request(ca).await.unwrap();
        let response = self.add_child(
            parent, ca.convert(), request, resources.clone()
        ).await;

        if let Some(rcn) = child_rcn {
            self.client().child_update(
                &parent.convert(), &ca.convert(),
                api::admin::UpdateChildRequest::resource_class_name_mapping(
                    api::admin::ResourceClassNameMapping {
                        name_in_parent: common::rcn(0),
                        name_for_child: rcn.clone(),
                    }
                )
            ).await.unwrap();
        }

        self.client().parent_add(
            ca, api::admin::ParentCaReq { handle: parent.convert(), response }
        ).await.unwrap();
        assert!(self.wait_for_ca_resources(ca, resources).await);
    }
}

