//! Support for tests in other modules using a running krill server

use std::path::PathBuf;
use std::{thread, time};

use rpki::uri::Rsync;

use crate::cli::options::{CaCommand, Command, Options, PublishersCommand};
use crate::cli::report::{ApiResponse, ReportFormat};
use crate::cli::{Error, KrillClient};
use crate::commons::api::{
    AddChildRequest, CertAuthInfo, CertAuthInit, CertifiedKeyInfo, ChildAuthRequest, ChildHandle,
    Handle, ParentCaContact, ParentCaReq, ParentHandle, Publish, PublisherDetails, PublisherHandle,
    ResourceClassKeysInfo, ResourceClassName, ResourceSet, RouteAuthorizationUpdates,
    UpdateChildRequest,
};
use crate::commons::remote::rfc8183;
use crate::commons::remote::rfc8183::ChildRequest;
use crate::commons::util::test;
use crate::daemon::ca::ta_handle;
use crate::daemon::config::Config;
use crate::daemon::http::server;

pub fn test_with_krill_server<F>(op: F)
where
    F: FnOnce(PathBuf) -> (),
{
    test::test_under_tmp(|dir| {
        // Set up a test PubServer Config
        let server_conf = {
            // Use a data dir for the storage
            let data_dir = test::sub_dir(&dir);
            Config::test(&data_dir)
        };

        // Start the server
        thread::spawn(move || server::start(&server_conf).unwrap());

        let mut tries = 0;
        loop {
            thread::sleep(time::Duration::from_millis(100));
            if let Ok(_res) = health_check() {
                break;
            }

            tries += 1;
            if tries > 20 {
                panic!("Server is not coming up")
            }
        }

        op(dir)
    })
}

pub fn start_krill_pubd_server() {
    let data_dir = test::sub_dir(&PathBuf::from("work"));
    let server_conf = Config::pubd_test(&data_dir);

    // Start the server
    thread::spawn(move || server::start(&server_conf).unwrap());

    let mut tries = 0;
    loop {
        thread::sleep(time::Duration::from_millis(100));
        if let Ok(_res) = krill_pubd_health() {
            break;
        }

        tries += 1;
        if tries > 20 {
            panic!("Server is not coming up")
        }
    }
}

pub fn wait_seconds(s: u64) {
    thread::sleep(time::Duration::from_secs(s));
}

fn health_check() -> Result<ApiResponse, Error> {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Default,
        Command::Health,
    );

    KrillClient::process(krillc_opts)
}

pub fn krill_admin(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Json,
        command,
    );
    match KrillClient::process(krillc_opts) {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

fn krill_pubd_health() -> Result<ApiResponse, Error> {
    let krillc_opts = Options::new(
        test::https("https://localhost:3001/"),
        "secret",
        ReportFormat::Default,
        Command::Health,
    );

    KrillClient::process(krillc_opts)
}

pub fn krill_pubd_admin(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::https("https://localhost:3001/"),
        "secret",
        ReportFormat::Json,
        command,
    );
    match KrillClient::process(krillc_opts) {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

pub fn krill_admin_expect_error(command: Command) -> Error {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Json,
        command,
    );
    match KrillClient::process(krillc_opts) {
        Ok(_res) => panic!("Expected error"),
        Err(e) => e,
    }
}

fn refresh_all() {
    krill_admin(Command::CertAuth(CaCommand::RefreshAll));
}

pub fn init_child(handle: &Handle) {
    let init = CertAuthInit::new(handle.clone());
    krill_admin(Command::CertAuth(CaCommand::Init(init)));
}

pub fn generate_new_id(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::UpdateId(handle.clone())));
}

pub fn parent_contact(handle: &Handle, child: &ChildHandle) -> ParentCaContact {
    match krill_admin(Command::CertAuth(CaCommand::ParentResponse(
        handle.clone(),
        child.clone(),
    ))) {
        ApiResponse::ParentCaContact(contact) => contact,
        _ => panic!("Expected RFC8183 parent response"),
    }
}

pub fn child_request(handle: &Handle) -> rfc8183::ChildRequest {
    match krill_admin(Command::CertAuth(CaCommand::ChildRequest(handle.clone()))) {
        ApiResponse::Rfc8183ChildRequest(req) => req,
        _ => panic!("Expected child request"),
    }
}

pub fn add_child_to_ta_embedded(handle: &Handle, resources: ResourceSet) -> ParentCaContact {
    let auth = ChildAuthRequest::Embedded;
    let req = AddChildRequest::new(handle.clone(), resources, auth);
    let res = krill_admin(Command::CertAuth(CaCommand::ChildAdd(ta_handle(), req)));

    match res {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub fn add_child_to_ta_rfc6492(
    handle: &Handle,
    req: rfc8183::ChildRequest,
    resources: ResourceSet,
) -> ParentCaContact {
    let auth = ChildAuthRequest::Rfc8183(req);
    let req = AddChildRequest::new(handle.clone(), resources, auth);
    let res = krill_admin(Command::CertAuth(CaCommand::ChildAdd(ta_handle(), req)));

    match res {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub fn add_child_rfc6492(
    parent: &ParentHandle,
    child: &ChildHandle,
    req: rfc8183::ChildRequest,
    resources: ResourceSet,
) -> ParentCaContact {
    let auth = ChildAuthRequest::Rfc8183(req);
    let req = AddChildRequest::new(child.clone(), resources, auth);
    let res = krill_admin(Command::CertAuth(CaCommand::ChildAdd(parent.clone(), req)));

    match res {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub fn update_child(ca: &Handle, child: &ChildHandle, resources: &ResourceSet) {
    let req = UpdateChildRequest::graceful(None, Some(resources.clone()));
    send_child_request(ca, child, req)
}

pub fn update_child_id(ca: &Handle, child: &ChildHandle, req: ChildRequest) {
    let (_, _, id) = req.unwrap();
    let req = UpdateChildRequest::graceful(Some(id), None);
    send_child_request(ca, child, req)
}

pub fn delete_child(ca: &Handle, child: &ChildHandle) {
    krill_admin(Command::CertAuth(CaCommand::ChildDelete(
        ca.clone(),
        child.clone(),
    )));
}

fn send_child_request(ca: &Handle, child: &Handle, req: UpdateChildRequest) {
    match krill_admin(Command::CertAuth(CaCommand::ChildUpdate(
        ca.clone(),
        child.clone(),
        req,
    ))) {
        ApiResponse::Empty => {}
        _ => panic!("Expected empty ok response"),
    }
    refresh_all();
}

pub fn add_parent_to_ca(ca: &Handle, parent: ParentCaReq) {
    krill_admin(Command::CertAuth(CaCommand::AddParent(ca.clone(), parent)));
}

pub fn update_parent_contact(ca: &Handle, parent: &ParentHandle, contact: ParentCaContact) {
    krill_admin(Command::CertAuth(CaCommand::UpdateParentContact(
        ca.clone(),
        parent.clone(),
        contact,
    )));
}

pub fn delete_parent(ca: &Handle, parent: &ParentHandle) {
    krill_admin(Command::CertAuth(CaCommand::RemoveParent(
        ca.clone(),
        parent.clone(),
    )));
}

pub fn ca_roll_init(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollInit(handle.clone())));
}

pub fn ca_roll_activate(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollActivate(
        handle.clone(),
    )));
}

pub fn ca_route_authorizations_update(handle: &Handle, updates: RouteAuthorizationUpdates) {
    krill_admin(Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(
        handle.clone(),
        updates,
    )));
}

pub fn ca_route_authorizations_update_expect_error(
    handle: &Handle,
    updates: RouteAuthorizationUpdates,
) {
    krill_admin_expect_error(Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(
        handle.clone(),
        updates,
    )));
}

pub fn ca_details(handle: &Handle) -> CertAuthInfo {
    match krill_admin(Command::CertAuth(CaCommand::Show(handle.clone()))) {
        ApiResponse::CertAuthInfo(inf) => inf,
        _ => panic!("Expected cert auth info"),
    }
}

pub fn ca_key_for_rcn(handle: &Handle, rcn: &ResourceClassName) -> CertifiedKeyInfo {
    ca_details(handle)
        .resources()
        .get(rcn)
        .unwrap()
        .current_key()
        .unwrap()
        .clone()
}

pub fn wait_for<O>(tries: u64, error_msg: &str, op: O)
where
    O: Copy + FnOnce() -> bool,
{
    for _counter in 1..=tries {
        if op() {
            return;
        }
        wait_seconds(1);
    }
    eprintln!("{}", error_msg);
    panic!();
}

pub fn wait_for_current_resources(handle: &Handle, resources: &ResourceSet) {
    wait_for(
        30,
        "cms child did not get its resource certificate",
        move || &ca_current_resources(handle) == resources,
    )
}

pub fn wait_for_new_key(handle: &Handle) {
    wait_for(30, "No new key received", move || {
        let ca = ca_details(handle);
        if let Some(rc) = ca.resources().get(&ResourceClassName::default()) {
            match rc.keys() {
                ResourceClassKeysInfo::RollNew(_, _) => return true,
                _ => return false,
            }
        }

        false
    })
}

pub fn wait_for_key_roll_complete(handle: &Handle) {
    wait_for(30, "Key roll did not complete", || {
        let ca = ca_details(handle);

        if let Some(rc) = ca.resources().get(&ResourceClassName::default()) {
            match rc.keys() {
                ResourceClassKeysInfo::Active(_) => return true,
                _ => return false,
            }
        }

        false
    })
}

pub fn wait_for_resource_class_to_disappear(handle: &Handle) {
    wait_for(30, "Resource class not removed", || {
        let ca = ca_details(handle);
        ca.resources().get(&ResourceClassName::default()).is_none()
    })
}

pub fn wait_for_ta_to_have_number_of_issued_certs(number: usize) {
    wait_for(30, "TA has wrong amount of issued certs", || {
        ta_issued_certs() == number
    })
}

pub fn ta_issued_certs() -> usize {
    let ta = ca_details(&ta_handle());
    ta.published_objects().len() - 2
}

pub fn ta_issued_resources(child: &Handle) -> ResourceSet {
    let ta = ca_details(&ta_handle());
    let child = ta.children().get(child).unwrap();
    child.issued_resources().clone()
}

pub fn ca_current_resources(handle: &Handle) -> ResourceSet {
    let ca = ca_details(handle);

    let mut res = ResourceSet::default();

    for rc in ca.resources().values() {
        match rc.keys() {
            ResourceClassKeysInfo::Active(current)
            | ResourceClassKeysInfo::RollPending(_, current)
            | ResourceClassKeysInfo::RollNew(_, current)
            | ResourceClassKeysInfo::RollOld(current, _) => {
                res = res.union(current.incoming_cert().resources());
            }
            _ => {}
        }
    }

    res
}

pub fn ca_current_objects(handle: &Handle) -> Vec<Publish> {
    let ca = ca_details(handle);
    ca.published_objects()
}

pub fn publisher_details(publisher: &PublisherHandle) -> PublisherDetails {
    match krill_admin(Command::Publishers(PublishersCommand::ShowPublisher(
        publisher.clone(),
    ))) {
        ApiResponse::PublisherDetails(pub_details) => pub_details,
        _ => panic!("Expected publisher details"),
    }
}

pub fn wait_for_published_objects(publisher: &PublisherHandle, objects: &[&str]) {
    let mut details = publisher_details(publisher);

    for _counter in 1..=30 {
        let current_files = details.current_files();

        if current_files.len() == objects.len() {
            let current_files: Vec<&Rsync> = current_files.iter().map(|p| p.uri()).collect();
            let mut all_matched = true;
            for o in objects {
                if current_files.iter().find(|uri| uri.ends_with(o)).is_none() {
                    all_matched = false;
                }
            }
            if all_matched {
                return;
            }
        }

        wait_seconds(1);

        details = publisher_details(publisher);
    }

    eprintln!("Did not find match for: {}", publisher);
    eprintln!("Found:");
    for file in details.current_files() {
        eprintln!("  {}", file.uri());
    }
    eprintln!("Expected:");
    for file in objects {
        eprintln!("  {}", file);
    }

    panic!("Exiting test");
}
