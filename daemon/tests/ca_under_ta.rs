extern crate krill_daemon;
extern crate krill_client;
extern crate krill_commons;
extern crate krill_pubc;

use krill_daemon::ca::caserver::ta_handle;
use krill_client::options::{
    CaCommand,
    Command,
    TrustAnchorCommand,
};
use krill_client::report::ApiResponse;
use krill_commons::api::ca::ResourceSet;
use krill_commons::api::admin::{AddChildRequest, CertAuthInit, CertAuthPubMode, Handle, ParentCaContact, AddParentRequest, Token, ChildAuthRequest};
use krill_daemon::test::{ test_with_krill_server, execute_krillc_command };
use krill_commons::remote::rfc8183;
use std::thread;
use std::time::Duration;


fn init_ta() {
    execute_krillc_command(Command::TrustAnchor(TrustAnchorCommand::Init));
}

fn init_child(handle: &Handle, token: &Token) {
    let init = CertAuthInit::new(
        handle.clone(), token.clone(), CertAuthPubMode::Embedded
    );
    execute_krillc_command(Command::CertAuth(CaCommand::Init(init)));
}

fn child_request(handle: &Handle) -> rfc8183::ChildRequest {
    match execute_krillc_command(
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
    let res = execute_krillc_command(
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
    let res = execute_krillc_command(
        Command::TrustAnchor(TrustAnchorCommand::AddChild(req))
    );

    match res {
        ApiResponse::ParentCaInfo(info) => info,
        _ => panic!("Expected ParentCaInfo response")
    }
}

fn add_parent_to_ca(handle: &Handle, parent: AddParentRequest) {
    execute_krillc_command(
        Command::CertAuth(CaCommand::AddParent(handle.clone(), parent))
    );
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
                &cms_child_handle, req, cms_child_resources
            );
            AddParentRequest::new(ta_handle.clone(), contact)
        };

        add_parent_to_ca(&cms_child_handle, parent);
    });
}
