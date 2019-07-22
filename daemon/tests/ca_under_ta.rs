extern crate krill_daemon;
extern crate krill_client;
extern crate krill_commons;
extern crate krill_pubc;

use krill_client::options::{
    CaCommand,
    Command,
    TrustAnchorCommand,
};
use krill_client::report::ApiResponse;
use krill_commons::api::ca::{ResourceSet, CertAuthInfo, CaParentsInfo};
use krill_commons::api::admin::{AddChildRequest, CertAuthInit, CertAuthPubMode, Handle, ParentCaContact, AddParentRequest, Token, ChildAuthRequest};
use krill_commons::remote::rfc8183;
use krill_daemon::ca::ta_handle;
use krill_daemon::test::{test_with_krill_server, krill_admin, wait_seconds};


fn init_ta() {
    krill_admin(Command::TrustAnchor(TrustAnchorCommand::Init));
}

fn init_child(handle: &Handle, token: &Token) {
    let init = CertAuthInit::new(
        handle.clone(), token.clone(), CertAuthPubMode::Embedded
    );
    krill_admin(Command::CertAuth(CaCommand::Init(init)));
}

fn child_request(handle: &Handle) -> rfc8183::ChildRequest {
    match krill_admin(
        Command::CertAuth(CaCommand::ChildRequest(handle.clone()))
    ) {
        ApiResponse::Rfc8183ChildRequest(req) => req,
        _ => panic!("Expected child request")
    }

}

fn add_child_to_ta_embedded(
    handle: &Handle,
    token: &Token,
    resources: ResourceSet
) -> ParentCaContact {
    let auth = ChildAuthRequest::Embedded(token.clone());
    let req = AddChildRequest::new(handle.clone(), resources, auth);
    let res = krill_admin(
        Command::TrustAnchor(TrustAnchorCommand::AddChild(req))
    );

    match res {
        ApiResponse::ParentCaInfo(info) => info,
        _ => panic!("Expected ParentCaInfo response")
    }
}

fn add_child_to_ta_rfc6492(
    handle: &Handle,
    req: rfc8183::ChildRequest,
    resources: ResourceSet
) -> ParentCaContact {
    let auth = ChildAuthRequest::Rfc8183(req);
    let req = AddChildRequest::new(handle.clone(), resources, auth);
    let res = krill_admin(
        Command::TrustAnchor(TrustAnchorCommand::AddChild(req))
    );

    match res {
        ApiResponse::ParentCaInfo(info) => info,
        _ => panic!("Expected ParentCaInfo response")
    }
}

fn add_parent_to_ca(handle: &Handle, parent: AddParentRequest) {
    krill_admin(
        Command::CertAuth(CaCommand::AddParent(handle.clone(), parent))
    );
}

fn ca_details(handle: &Handle) -> CertAuthInfo {
    match krill_admin(Command::CertAuth(CaCommand::Show(handle.clone()))) {
        ApiResponse::CertAuthInfo(inf) => inf,
        _ => panic!("Expected cert auth info")
    }

}

fn wait_for_resources_on_current_key(handle: &Handle, resources: &ResourceSet) {
    let tries = 30;
    for counter in 1..tries+1 {
        if counter == tries {
            panic!("cms child did not get its resource certificate");
        }

        let cms_ca_info = ca_details(handle.clone());

        if let CaParentsInfo::Parents(parents) = cms_ca_info.parents() {
            if let Some(parent) = parents.get(&ta_handle) {
                if let Some(rc) = parent.resources().get("all") {
                    if let Some(key) = rc.current_key() {
                        assert_eq!(resources, key.resources());
                        break
                    }
                }
            }
        }

        wait_seconds(1);
    }
}


#[test]
fn ca_under_ta() {
    test_with_krill_server(|_d|{

        let ta_handle = ta_handle();
        init_ta();

        let emb_child_handle = Handle::from("child");
        let emb_child_token = Token::from("child");
        let emb_child_resources = ResourceSet::from_strs(
            "",
            "192.168.0.0/16",
            ""
        ).unwrap();

        init_child(&emb_child_handle, &emb_child_token);

        let parent = {
            let parent_contact = add_child_to_ta_embedded(
                &emb_child_handle, &emb_child_token, emb_child_resources
            );
            AddParentRequest::new(ta_handle.clone(), parent_contact)
        };

        add_parent_to_ca(&emb_child_handle, parent);

        let cms_child_handle = Handle::from("rfc6492");
        let cms_child_token = Token::from("rfc6492");
        let cms_child_resources = ResourceSet::from_strs(
            "",
            "10.0.0.0/16",
            ""
        ).unwrap();

        init_child(&cms_child_handle, &cms_child_token);
        let req = child_request(&cms_child_handle);

        let parent = {
            let contact = add_child_to_ta_rfc6492(
                &cms_child_handle, req, cms_child_resources.clone()
            );
            AddParentRequest::new(ta_handle.clone(), contact)
        };

        add_parent_to_ca(&cms_child_handle, parent);

        wait_for_resources_on_current_key(&cms_child_handle, &cms_child_resources);


    });
}
