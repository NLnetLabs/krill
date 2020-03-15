//! Support for tests in other modules using a running krill server

use std::path::PathBuf;
use std::time::Duration;

use hyper::StatusCode;
use tokio::time::{delay_for, timeout};

use rpki::uri::Rsync;

use crate::cli::options::{BulkCaCommand, CaCommand, Command, Options, PublishersCommand};
use crate::cli::report::{ApiResponse, ReportFormat};
use crate::cli::{Error, KrillClient};
use crate::commons::api::{
    AddChildRequest, CertAuthInfo, CertAuthInit, CertifiedKeyInfo, ChildAuthRequest, ChildHandle,
    Handle, ParentCaContact, ParentCaReq, ParentHandle, Publish, PublisherDetails, PublisherHandle,
    RepositoryUpdate, ResourceClassKeysInfo, ResourceClassName, ResourceSet, RoaDefinitionUpdates,
    UpdateChildRequest,
};
use crate::commons::remote::rfc8183;
use crate::commons::remote::rfc8183::ChildRequest;
use crate::commons::util::test::{sub_dir, tmp_dir};
use crate::commons::util::{httpclient, test};
use crate::daemon::ca::ta_handle;
use crate::daemon::config::Config;
use crate::daemon::http::server;

#[derive(Clone, Copy)]
pub enum PubdTestContext {
    Main,
    Secondary,
}

pub async fn primary_server_ready() -> bool {
    server_ready("https://localhost:3000/health").await
}

pub async fn secondary_server_ready() -> bool {
    server_ready("https://localhost:3001/health").await
}

pub async fn server_ready(uri: &str) -> bool {
    for _ in 0..300 {
        match httpclient::client(uri).await {
            Ok(client) => {
                let res = timeout(Duration::from_millis(100), client.get(uri).send()).await;
                if let Ok(Ok(res)) = res {
                    if res.status() == StatusCode::OK {
                        return true;
                    }
                }
            }
            Err(_) => return false,
        }
    }

    false
}

/// Starts krill server for testing, with embedded TA and repo.
/// Creates a random base directory in the 'work' folder, and returns
/// it. Be sure to clean it up when the test is done.
pub async fn start_krill() -> PathBuf {
    let dir = tmp_dir();

    let server_conf = {
        // Use a data dir for the storage
        let data_dir = sub_dir(&dir);
        Config::test(&data_dir)
    };

    tokio::spawn(server::start(server_conf));

    assert!(primary_server_ready().await);
    dir
}

pub async fn start_secondary_krill(base_dir: &PathBuf) {
    let data_dir = test::sub_dir(base_dir);
    let server_conf = Config::pubd_test(&data_dir);

    tokio::spawn(server::start(server_conf));

    assert!(secondary_server_ready().await);
}

pub async fn krill_admin(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Json,
        command,
    );
    match KrillClient::process(krillc_opts).await {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

pub async fn krill_admin_secondary(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(
        test::https("https://localhost:3001/"),
        "secret",
        ReportFormat::Json,
        command,
    );
    match KrillClient::process(krillc_opts).await {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

pub async fn krill_pubd_admin(command: Command, server: PubdTestContext) -> ApiResponse {
    match server {
        PubdTestContext::Main => krill_admin(command).await,
        PubdTestContext::Secondary => krill_admin_secondary(command).await,
    }
}

pub async fn krill_admin_expect_error(command: Command) -> Error {
    let krillc_opts = Options::new(
        test::https("https://localhost:3000/"),
        "secret",
        ReportFormat::Json,
        command,
    );
    match KrillClient::process(krillc_opts).await {
        Ok(_res) => panic!("Expected error"),
        Err(e) => e,
    }
}

async fn refresh_all() {
    krill_admin(Command::Bulk(BulkCaCommand::Refresh)).await;
}

pub async fn init_child_with_embedded_repo(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::Init(CertAuthInit::new(
        handle.clone(),
    ))))
    .await;
    krill_admin(Command::CertAuth(CaCommand::RepoUpdate(
        handle.clone(),
        RepositoryUpdate::Embedded,
    )))
    .await;
}

pub async fn generate_new_id(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::UpdateId(handle.clone()))).await;
}

pub async fn parent_contact(handle: &Handle, child: &ChildHandle) -> ParentCaContact {
    match krill_admin(Command::CertAuth(CaCommand::ParentResponse(
        handle.clone(),
        child.clone(),
    )))
    .await
    {
        ApiResponse::ParentCaContact(contact) => contact,
        _ => panic!("Expected RFC8183 parent response"),
    }
}

pub async fn child_request(handle: &Handle) -> rfc8183::ChildRequest {
    match krill_admin(Command::CertAuth(CaCommand::ChildRequest(handle.clone()))).await {
        ApiResponse::Rfc8183ChildRequest(req) => req,
        _ => panic!("Expected child request"),
    }
}

pub async fn add_child_to_ta_embedded(handle: &Handle, resources: ResourceSet) -> ParentCaContact {
    let auth = ChildAuthRequest::Embedded;
    let req = AddChildRequest::new(handle.clone(), resources, auth);
    let res = krill_admin(Command::CertAuth(CaCommand::ChildAdd(ta_handle(), req))).await;

    match res {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub async fn add_child_to_ta_rfc6492(
    handle: &Handle,
    req: rfc8183::ChildRequest,
    resources: ResourceSet,
) -> ParentCaContact {
    let auth = ChildAuthRequest::Rfc8183(req);
    let req = AddChildRequest::new(handle.clone(), resources, auth);
    let res = krill_admin(Command::CertAuth(CaCommand::ChildAdd(ta_handle(), req))).await;

    match res {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub async fn add_child_rfc6492(
    parent: &ParentHandle,
    child: &ChildHandle,
    req: rfc8183::ChildRequest,
    resources: ResourceSet,
) -> ParentCaContact {
    let auth = ChildAuthRequest::Rfc8183(req);
    let req = AddChildRequest::new(child.clone(), resources, auth);

    match krill_admin(Command::CertAuth(CaCommand::ChildAdd(parent.clone(), req))).await {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub async fn update_child(ca: &Handle, child: &ChildHandle, resources: &ResourceSet) {
    let req = UpdateChildRequest::resources(resources.clone());
    send_child_request(ca, child, req).await
}

pub async fn update_child_id(ca: &Handle, child: &ChildHandle, req: ChildRequest) {
    let (_, _, id) = req.unwrap();
    let req = UpdateChildRequest::id_cert(id);
    send_child_request(ca, child, req).await
}

pub async fn delete_child(ca: &Handle, child: &ChildHandle) {
    krill_admin(Command::CertAuth(CaCommand::ChildDelete(
        ca.clone(),
        child.clone(),
    )))
    .await;
}

async fn send_child_request(ca: &Handle, child: &Handle, req: UpdateChildRequest) {
    match krill_admin(Command::CertAuth(CaCommand::ChildUpdate(
        ca.clone(),
        child.clone(),
        req,
    )))
    .await
    {
        ApiResponse::Empty => {}
        _ => error!("Expected empty ok response"),
    }
    refresh_all().await;
}

pub async fn add_parent_to_ca(ca: &Handle, parent: ParentCaReq) {
    krill_admin(Command::CertAuth(CaCommand::AddParent(ca.clone(), parent))).await;
}

pub async fn update_parent_contact(ca: &Handle, parent: &ParentHandle, contact: ParentCaContact) {
    krill_admin(Command::CertAuth(CaCommand::UpdateParentContact(
        ca.clone(),
        parent.clone(),
        contact,
    )))
    .await;
}

pub async fn delete_parent(ca: &Handle, parent: &ParentHandle) {
    krill_admin(Command::CertAuth(CaCommand::RemoveParent(
        ca.clone(),
        parent.clone(),
    )))
    .await;
}

pub async fn ca_roll_init(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollInit(handle.clone()))).await;
}

pub async fn ca_roll_activate(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollActivate(
        handle.clone(),
    )))
    .await;
}

pub async fn ca_route_authorizations_update(handle: &Handle, updates: RoaDefinitionUpdates) {
    krill_admin(Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(
        handle.clone(),
        updates,
    )))
    .await;
}

pub async fn ca_route_authorizations_update_expect_error(
    handle: &Handle,
    updates: RoaDefinitionUpdates,
) {
    krill_admin_expect_error(Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(
        handle.clone(),
        updates,
    )))
    .await;
}

pub async fn ca_details(handle: &Handle) -> CertAuthInfo {
    match krill_admin(Command::CertAuth(CaCommand::Show(handle.clone()))).await {
        ApiResponse::CertAuthInfo(inf) => inf,
        _ => panic!("Expected cert auth info"),
    }
}

pub async fn ca_key_for_rcn(handle: &Handle, rcn: &ResourceClassName) -> CertifiedKeyInfo {
    ca_details(handle)
        .await
        .resource_classes()
        .get(rcn)
        .unwrap()
        .current_key()
        .unwrap()
        .clone()
}

pub async fn ca_gets_resources(handle: &Handle, resources: &ResourceSet) -> bool {
    for _ in 0..30_u8 {
        if &ca_current_resources(handle).await == resources {
            return true;
        }
        delay_for(Duration::from_secs(1)).await
    }
    false
}

pub async fn rc_state_becomes_new_key(handle: &Handle) -> bool {
    for _ in 0..30_u8 {
        let ca = ca_details(handle).await;
        if let Some(rc) = ca.resource_classes().get(&ResourceClassName::default()) {
            if let ResourceClassKeysInfo::RollNew(_) = rc.keys() {
                return true;
            }
        }
        delay_for(Duration::from_secs(1)).await
    }
    false
}

pub async fn rc_state_becomes_active(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;
        if let Some(rc) = ca.resource_classes().get(&ResourceClassName::default()) {
            if let ResourceClassKeysInfo::Active(_) = rc.keys() {
                return true;
            }
        }
        delay_for(Duration::from_millis(100)).await
    }
    false
}

pub async fn rc_is_removed(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;
        if ca
            .resource_classes()
            .get(&ResourceClassName::default())
            .is_none()
        {
            return true;
        }
        delay_for(Duration::from_millis(100)).await
    }
    false
}

pub async fn ta_will_have_issued_n_certs(number: usize) -> bool {
    for _ in 0..300 {
        let ta = ca_details(&ta_handle()).await;
        if ta.published_objects().len() - 2 == number {
            return true;
        }
        delay_for(Duration::from_millis(100)).await
    }
    false
}

pub async fn ca_current_resources(handle: &Handle) -> ResourceSet {
    let ca = ca_details(handle).await;

    let mut res = ResourceSet::default();

    for rc in ca.resource_classes().values() {
        if let Some(resources) = rc.current_resources() {
            res = res.union(resources)
        }
    }

    res
}

pub async fn ca_current_objects(handle: &Handle) -> Vec<Publish> {
    let ca = ca_details(handle).await;
    ca.published_objects()
}

pub async fn publisher_details(publisher: &PublisherHandle) -> PublisherDetails {
    match krill_admin(Command::Publishers(PublishersCommand::ShowPublisher(
        publisher.clone(),
    )))
    .await
    {
        ApiResponse::PublisherDetails(pub_details) => pub_details,
        _ => panic!("Expected publisher details"),
    }
}

pub async fn will_publish_objects(publisher: &PublisherHandle, objects: &[&str]) -> bool {
    for _ in 0..300 {
        let details = publisher_details(publisher).await;

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
                return true;
            }
        }

        delay_for(Duration::from_millis(100)).await
    }

    let details = publisher_details(publisher).await;

    eprintln!("Did not find match for: {}", publisher);
    eprintln!("Found:");
    for file in details.current_files() {
        eprintln!("  {}", file.uri());
    }
    eprintln!("Expected:");
    for file in objects {
        eprintln!("  {}", file);
    }

    false
}
