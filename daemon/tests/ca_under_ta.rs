extern crate krill_daemon;
extern crate krill_client;
extern crate krill_commons;
extern crate krill_pubc;
extern crate krill_ca;

use krill_ca::ta_handle;
use krill_client::options::{
    CaCommand,
    Command,
    TrustAnchorCommand,
};
use krill_client::report::ApiResponse;
use krill_commons::api::ca::ResourceSet;
use krill_commons::api::admin::{
    AddChildRequest,
    CertAuthInit,
    CertAuthPubMode,
    Handle,
    ParentCaContact,
    ParentCaReq,
    Token,
};
use krill_daemon::test::{ test_with_krill_server, execute_krillc_command };


fn init_ta() {
    execute_krillc_command(Command::TrustAnchor(TrustAnchorCommand::Init));
}

fn init_child(handle: &Handle, token: &Token) {
    let init = CertAuthInit::new(
        handle.clone(), token.clone(), CertAuthPubMode::Embedded
    );
    execute_krillc_command(Command::CertAuth(CaCommand::Init(init)));
}

fn child_request(handle: &Handle) {
    let _res = execute_krillc_command(
        Command::CertAuth(CaCommand::ChildRequest(handle.clone()))
    );
}

fn add_child_to_ta(
    handle: &Handle,
    token: &Token,
    resources: ResourceSet
) -> ParentCaContact {
    let req = AddChildRequest::new(handle.clone(), token.clone(), resources);
    let res = execute_krillc_command(
        Command::TrustAnchor(TrustAnchorCommand::AddChild(req))
    );

    match res {
        ApiResponse::ParentCaInfo(info) => info,
        _ => panic!("Expected ParentCaInfo response")
    }
}

fn add_parent_to_ca(handle: &Handle, parent: ParentCaReq) {
    execute_krillc_command(
        Command::CertAuth(CaCommand::AddParent(handle.clone(), parent))
    );
}

#[test]
fn ca_under_ta() {
    test_with_krill_server(|_d|{

        let ta_handle = ta_handle();

        let child_handle = Handle::from("child");
        let child_token = Token::from("child");
        let child_resources = ResourceSet::from_strs(
            "",
            "192.168.0.0/16",
            ""
        ).unwrap();

        init_ta();

        init_child(&child_handle, &child_token);

        let _child_req = child_request(&child_handle);


        let parent = {
            let parent_contact = add_child_to_ta(
                &child_handle, &child_token, child_resources
            );
            ParentCaReq::new(ta_handle.clone(), parent_contact)
        };

        add_parent_to_ca(&child_handle, parent);
    });
}