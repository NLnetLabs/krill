//! Helper functions for testing Krill.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, path::Path};

use bytes::Bytes;

use hyper::StatusCode;
use tokio::time::{delay_for, timeout};

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::cli::report::{ApiResponse, ReportFormat};
use crate::cli::{Error, KrillClient, KrillPubdClient};
use crate::commons::api::{
    AddChildRequest, CertAuthInfo, CertAuthInit, CertifiedKeyInfo, ChildHandle, Handle, ParentCaContact, ParentCaReq,
    ParentHandle, ParentStatuses, PublicationServerUris, PublisherDetails, PublisherHandle, PublisherList,
    ResourceClassName, ResourceSet, RoaDefinition, RoaDefinitionUpdates, RtaList, RtaName, RtaPrepResponse, Token,
    TypedPrefix, UpdateChildRequest,
};
use crate::commons::bgp::{Announcement, BgpAnalysisReport, BgpAnalysisSuggestion};
use crate::commons::crypto::SignSupport;
use crate::commons::remote::rfc8183;
use crate::commons::remote::rfc8183::{ChildRequest, RepositoryResponse};
use crate::commons::util::httpclient;
use crate::daemon::ca::{ta_handle, ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest};
use crate::daemon::http::server;
use crate::{
    cli::options::{BulkCaCommand, CaCommand, Command, KrillPubcOptions, Options, PublishersCommand},
    commons::api::RepositoryContact,
};

#[cfg(test)]
use crate::commons::crypto::IdCert;
use crate::daemon::config::Config;
use crate::daemon::krillserver::KrillMode;

pub const KRILL_SERVER_URI: &str = "https://localhost:3000/";
pub const KRILL_PUBD_SERVER_URI: &str = "https://localhost:3001/";

pub fn init_logging() {
    // Just creates a test config so we can initialize logging, then forgets about it
    let d = PathBuf::from(".");
    let _ = Config::test(&d, false).init_logging();
}

pub fn info(msg: impl std::fmt::Display) {
    info!("{}", msg); // we can change this to using the logger crate later
}

pub async fn krill_server_ready() -> bool {
    server_ready(KRILL_SERVER_URI).await
}

pub async fn krill_pubd_ready() -> bool {
    server_ready(KRILL_PUBD_SERVER_URI).await
}

pub async fn server_ready(uri: &str) -> bool {
    let health = format!("{}health", uri);

    for _ in 0..300 {
        match httpclient::client(&health).await {
            Ok(client) => {
                let res = timeout(Duration::from_millis(100), client.get(&health).send()).await;

                if let Ok(Ok(res)) = res {
                    if res.status() == StatusCode::OK {
                        return true;
                    } else {
                        eprintln!("Got status: {}", res.status());
                    }
                }
            }
            Err(_) => return false,
        }
        delay_for(Duration::from_millis(100)).await;
    }

    false
}

pub fn test_config(dir: &Path, enable_testbed: bool) -> Config {
    if enable_testbed {
        crate::constants::enable_test_mode();
        crate::constants::enable_test_announcements();
    }
    Config::test(dir, enable_testbed)
}

pub fn init_config(config: &Config) {
    if config.init_logging().is_err() {
        trace!("Logging already initialized");
    }
    config.verify().unwrap();
}

/// Starts krill server for testing using the given configuration. Creates a random base directory in the 'work' folder,
/// adjusts the config to use it and returns it. Be sure to clean it up when the test is done.
pub async fn start_krill_with_custom_config(mut config: Config) -> PathBuf {
    let dir = tmp_dir();
    config.set_data_dir(dir.clone());
    start_krill(config).await;
    dir
}

/// Starts krill server for testing using the default test configuration, and optionally with testbed mode enabled.
/// Creates a random base directory in the 'work' folder, and returns it. Be sure to clean it up when the test is done.
pub async fn start_krill_with_default_test_config(enable_testbed: bool) -> PathBuf {
    let dir = tmp_dir();
    let config = test_config(&dir, enable_testbed);
    start_krill(config).await;
    dir
}

async fn start_krill(config: Config) {
    init_config(&config);
    tokio::spawn(start_krill_with_error_trap(Arc::new(config), KrillMode::Ca));
    assert!(krill_server_ready().await);
}

async fn start_krill_with_error_trap(config: Arc<Config>, mode: KrillMode) {
    if let Err(err) = server::start_krill_daemon(config, mode).await {
        error!("Krill failed to start: {}", err);
    }
}

/// Starts a krill pubd for testing on its own port, and its
/// own temp dir for storage.
pub async fn start_krill_pubd() -> PathBuf {
    let dir = tmp_dir();
    let mut config = test_config(&dir, false);
    init_config(&config);

    config.port = 3001;
    config.service_uri = "https://localhost:3001/".to_string();

    tokio::spawn(start_krill_with_error_trap(Arc::new(config), KrillMode::Pubd));
    assert!(krill_pubd_ready().await);

    // Initialize the repository using separate URIs
    let uris = {
        let rsync_base = uri::Rsync::from_str("rsync://localhost/dedicated-repo/").unwrap();
        let rrdp_base_uri = uri::Https::from_str("https://localhost:3001/test-rrdp/").unwrap();
        PublicationServerUris::new(rrdp_base_uri, rsync_base)
    };
    let command = PublishersCommand::RepositoryInit(uris);
    krill_dedicated_pubd_admin(command).await;

    dir
}

pub async fn krill_admin(command: Command) -> ApiResponse {
    let krillc_opts = Options::new(https(KRILL_SERVER_URI), "secret", ReportFormat::Json, command);
    match KrillClient::process(krillc_opts).await {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

pub async fn krill_embedded_pubd_admin(command: PublishersCommand) -> ApiResponse {
    let options = KrillPubcOptions::new(
        https(KRILL_SERVER_URI),
        Token::from("secret"),
        ReportFormat::Json,
        false,
        command,
    );
    match KrillPubdClient::process(options).await {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

pub async fn krill_dedicated_pubd_admin(command: PublishersCommand) -> ApiResponse {
    let options = KrillPubcOptions::new(
        https(KRILL_PUBD_SERVER_URI),
        Token::from("secret"),
        ReportFormat::Json,
        false,
        command,
    );
    match KrillPubdClient::process(options).await {
        Ok(res) => res, // ok
        Err(e) => panic!("{}", e),
    }
}

pub async fn krill_admin_expect_error(command: Command) -> Error {
    let krillc_opts = Options::new(https(KRILL_SERVER_URI), "secret", ReportFormat::Json, command);
    match KrillClient::process(krillc_opts).await {
        Ok(_res) => panic!("Expected error"),
        Err(e) => e,
    }
}

async fn refresh_all() {
    krill_admin(Command::Bulk(BulkCaCommand::Refresh)).await;
}

pub async fn init_ca(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::Init(CertAuthInit::new(handle.clone())))).await;
}

pub async fn delete_ca(ca: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::Delete(ca.clone()))).await;
}

// // We use embedded when not testing RFC 8181 - so that the CMS signing/verification overhead can be reduced.
// pub async fn init_ca_with_embedded_repo(handle: &Handle) {
//     krill_admin(Command::CertAuth(CaCommand::Init(CertAuthInit::new(handle.clone())))).await;
//     krill_admin(Command::CertAuth(CaCommand::RepoUpdate(
//         handle.clone(),
//         RepositoryUpdate::Embedded,
//     )))
//     .await;
// }

pub async fn ca_repo_update_rfc8181(handle: &Handle, response: RepositoryResponse) {
    krill_admin(Command::CertAuth(CaCommand::RepoUpdate(
        handle.clone(),
        RepositoryContact::new(response),
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

pub async fn request(handle: &Handle) -> rfc8183::ChildRequest {
    match krill_admin(Command::CertAuth(CaCommand::ChildRequest(handle.clone()))).await {
        ApiResponse::Rfc8183ChildRequest(req) => req,
        _ => panic!("Expected child request"),
    }
}

pub async fn add_child_to_ta_rfc6492(
    handle: &Handle,
    child_request: rfc8183::ChildRequest,
    resources: ResourceSet,
) -> ParentCaContact {
    let (_, _, id_cert) = child_request.unpack();
    let req = AddChildRequest::new(handle.clone(), resources, id_cert);
    let res = krill_admin(Command::CertAuth(CaCommand::ChildAdd(ta_handle(), req))).await;

    match res {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub async fn add_child_rfc6492(
    parent: &ParentHandle,
    child: &ChildHandle,
    child_request: rfc8183::ChildRequest,
    resources: ResourceSet,
) -> ParentCaContact {
    let (_, _, id_cert) = child_request.unpack();

    let add_child_request = AddChildRequest::new(child.clone(), resources, id_cert);

    match krill_admin(Command::CertAuth(CaCommand::ChildAdd(
        parent.clone(),
        add_child_request,
    )))
    .await
    {
        ApiResponse::ParentCaContact(info) => info,
        _ => panic!("Expected ParentCaInfo response"),
    }
}

pub async fn update_child(ca: &Handle, child: &ChildHandle, resources: &ResourceSet) {
    let req = UpdateChildRequest::resources(resources.clone());
    send_child_request(ca, child, req).await
}

pub async fn update_child_id(ca: &Handle, child: &ChildHandle, req: ChildRequest) {
    let (_, _, id) = req.unpack();
    let req = UpdateChildRequest::id_cert(id);
    send_child_request(ca, child, req).await
}

pub async fn delete_child(ca: &Handle, child: &ChildHandle) {
    krill_admin(Command::CertAuth(CaCommand::ChildDelete(ca.clone(), child.clone()))).await;
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

pub async fn parent_statuses(ca: &Handle) -> ParentStatuses {
    match krill_admin(Command::CertAuth(CaCommand::ParentStatuses(ca.clone()))).await {
        ApiResponse::ParentStatuses(status) => status,
        _ => panic!("Expected parent statuses"),
    }
}

pub async fn update_parent_contact(ca: &Handle, parent: &ParentHandle, contact: ParentCaContact) {
    let parent_req = ParentCaReq::new(parent.clone(), contact);
    krill_admin(Command::CertAuth(CaCommand::AddParent(ca.clone(), parent_req))).await;
}

pub async fn delete_parent(ca: &Handle, parent: &ParentHandle) {
    krill_admin(Command::CertAuth(CaCommand::RemoveParent(ca.clone(), parent.clone()))).await;
}

pub async fn ca_route_authorizations_update(handle: &Handle, updates: RoaDefinitionUpdates) {
    krill_admin(Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(
        handle.clone(),
        updates,
    )))
    .await;
}

pub async fn ca_route_authorizations_update_expect_error(handle: &Handle, updates: RoaDefinitionUpdates) {
    krill_admin_expect_error(Command::CertAuth(CaCommand::RouteAuthorizationsUpdate(
        handle.clone(),
        updates,
    )))
    .await;
}

pub async fn ca_route_authorizations_suggestions(handle: &Handle) -> BgpAnalysisSuggestion {
    match krill_admin(Command::CertAuth(CaCommand::BgpAnalysisSuggest(handle.clone(), None))).await {
        ApiResponse::BgpAnalysisSuggestions(suggestion) => suggestion,
        _ => panic!("Expected ROA suggestion"),
    }
}

pub async fn ca_route_authorization_dryrun(handle: &Handle, updates: RoaDefinitionUpdates) -> BgpAnalysisReport {
    match krill_admin(Command::CertAuth(CaCommand::RouteAuthorizationsDryRunUpdate(
        handle.clone(),
        updates,
    )))
    .await
    {
        ApiResponse::BgpAnalysisFull(report) => report,
        _ => panic!("Expected BGP analysis report"),
    }
}

pub async fn ca_details(handle: &Handle) -> CertAuthInfo {
    match krill_admin(Command::CertAuth(CaCommand::Show(handle.clone()))).await {
        ApiResponse::CertAuthInfo(inf) => inf,
        _ => panic!("Expected cert auth info"),
    }
}

pub async fn rta_sign_sign(
    ca: Handle,
    name: RtaName,
    resources: ResourceSet,
    keys: Vec<KeyIdentifier>,
    content: Bytes,
) {
    let request = RtaContentRequest::new(resources, SignSupport::sign_validity_days(14), keys, content);
    let command = Command::CertAuth(CaCommand::RtaSign(ca, name, request));
    krill_admin(command).await;
}

pub async fn rta_list(ca: Handle) -> RtaList {
    let command = Command::CertAuth(CaCommand::RtaList(ca));
    match krill_admin(command).await {
        ApiResponse::RtaList(list) => list,
        _ => panic!("Expected RTA list"),
    }
}

pub async fn rta_show(ca: Handle, name: RtaName) -> ResourceTaggedAttestation {
    let command = Command::CertAuth(CaCommand::RtaShow(ca, name, None));
    match krill_admin(command).await {
        ApiResponse::Rta(rta) => rta,
        _ => panic!("Expected RTA"),
    }
}

pub async fn rta_multi_prep(ca: Handle, name: RtaName, resources: ResourceSet) -> RtaPrepResponse {
    let request = RtaPrepareRequest::new(resources, SignSupport::sign_validity_days(14));
    let command = Command::CertAuth(CaCommand::RtaMultiPrep(ca, name, request));
    match krill_admin(command).await {
        ApiResponse::RtaMultiPrep(res) => res,
        _ => panic!("Expected RtaMultiPrep"),
    }
}

pub async fn rta_multi_cosign(ca: Handle, name: RtaName, rta: ResourceTaggedAttestation) {
    let command = Command::CertAuth(CaCommand::RtaMultiCoSign(ca, name, rta));
    krill_admin(command).await;
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

pub async fn ca_new_key_for_rcn(handle: &Handle, rcn: &ResourceClassName) -> CertifiedKeyInfo {
    ca_details(handle)
        .await
        .resource_classes()
        .get(rcn)
        .unwrap()
        .new_key()
        .unwrap()
        .clone()
}

pub async fn ca_contains_resources(handle: &Handle, resources: &ResourceSet) -> bool {
    for _ in 0..30_u8 {
        if ca_current_resources(handle).await.contains(resources) {
            return true;
        }
        delay_for(Duration::from_secs(1)).await
    }
    false
}

pub async fn ca_equals_resources(handle: &Handle, resources: &ResourceSet) -> bool {
    for _ in 0..30_u8 {
        if &ca_current_resources(handle).await == resources {
            return true;
        }
        delay_for(Duration::from_secs(1)).await
    }
    false
}

pub async fn rc_is_removed(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;
        if ca.resource_classes().get(&ResourceClassName::default()).is_none() {
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

pub async fn list_publishers() -> PublisherList {
    match krill_embedded_pubd_admin(PublishersCommand::PublisherList).await {
        ApiResponse::PublisherList(pub_list) => pub_list,
        _ => panic!("Expected publisher list"),
    }
}

pub async fn publisher_details(publisher: &PublisherHandle) -> PublisherDetails {
    match krill_embedded_pubd_admin(PublishersCommand::ShowPublisher(publisher.clone())).await {
        ApiResponse::PublisherDetails(pub_details) => pub_details,
        _ => panic!("Expected publisher details"),
    }
}

pub async fn dedicated_repo_publisher_details(publisher: &PublisherHandle) -> PublisherDetails {
    match krill_dedicated_pubd_admin(PublishersCommand::ShowPublisher(publisher.clone())).await {
        ApiResponse::PublisherDetails(pub_details) => pub_details,
        _ => panic!("Expected publisher details"),
    }
}

pub async fn publisher_request(handle: &Handle) -> rfc8183::PublisherRequest {
    match krill_admin(Command::CertAuth(CaCommand::RepoPublisherRequest(handle.clone()))).await {
        ApiResponse::Rfc8183PublisherRequest(req) => req,
        _ => panic!("Expected publisher request"),
    }
}

/// This method sets up a test directory with a random name (a number)
/// under 'work', relative to where cargo is running. It then runs the
/// test provided in the closure, and finally it cleans up the test
/// directory.
///
/// Note that if your test fails the directory is not cleaned up.
pub fn test_under_tmp<F>(op: F)
where
    F: FnOnce(PathBuf),
{
    let dir = sub_dir(&PathBuf::from("work"));
    let path = PathBuf::from(&dir);

    op(dir);

    let _result = fs::remove_dir_all(path);
}

pub fn tmp_dir() -> PathBuf {
    sub_dir(&PathBuf::from("work"))
}

/// This method sets up a random subdirectory and returns it. It is
/// assumed that the caller will clean this directory themselves.
pub fn sub_dir(base_dir: &Path) -> PathBuf {
    let mut bytes = [0; 8];
    openssl::rand::rand_bytes(&mut bytes).unwrap();

    let mut dir = base_dir.to_path_buf();
    dir.push(hex::encode(bytes));

    let full_path = PathBuf::from(&dir);
    fs::create_dir_all(&full_path).unwrap();

    full_path
}

pub fn rsync(s: &str) -> uri::Rsync {
    uri::Rsync::from_str(s).unwrap()
}

pub fn https(s: &str) -> uri::Https {
    uri::Https::from_str(s).unwrap()
}

pub fn as_bytes(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

pub fn save_file(base_dir: &Path, file_name: &str, content: &[u8]) {
    let mut full_name = base_dir.to_path_buf();
    full_name.push(PathBuf::from(file_name));
    let mut f = File::create(full_name).unwrap();
    f.write_all(content).unwrap();
}

// Support testing announcements and ROAs etc

pub fn announcement(s: &str) -> Announcement {
    let def = definition(s);
    Announcement::from(def)
}

pub fn definition(s: &str) -> RoaDefinition {
    RoaDefinition::from_str(s).unwrap()
}

pub fn typed_prefix(s: &str) -> TypedPrefix {
    TypedPrefix::from_str(s).unwrap()
}

#[cfg(test)]
pub fn test_id_certificate() -> IdCert {
    let data = include_bytes!("../test-resources/oob/id_publisher_ta.cer");
    IdCert::decode(Bytes::from_static(data)).unwrap()
}
