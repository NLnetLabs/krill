//! Helper functions for testing Krill.

use std::{
    fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;

use hyper::StatusCode;
use tokio::time::{sleep, timeout};

use rpki::{repository::crypto::KeyIdentifier, uri};

use crate::{
    cli::{
        options::{BulkCaCommand, CaCommand, Command, Options, PubServerCommand},
        report::{ApiResponse, ReportFormat},
        {Error, KrillClient},
    },
    commons::{
        api::{
            AddChildRequest, AspaCustomer, AspaDefinition, AspaDefinitionList, AspaProvidersUpdate, CertAuthInfo,
            CertAuthInit, CertifiedKeyInfo, ChildHandle, Handle, ObjectName, ParentCaContact, ParentCaReq,
            ParentHandle, ParentStatuses, PublicationServerUris, PublisherDetails, PublisherHandle, PublisherList,
            RepositoryContact, ResourceClassKeysInfo, ResourceClassName, ResourceSet, RoaDefinition,
            RoaDefinitionUpdates, RtaList, RtaName, RtaPrepResponse, TypedPrefix, UpdateChildRequest,
        },
        bgp::{Announcement, BgpAnalysisReport, BgpAnalysisSuggestion},
        crypto::SignSupport,
        remote::rfc8183,
        remote::rfc8183::{ChildRequest, RepositoryResponse},
        util::httpclient,
    },
    daemon::{
        ca::{ta_handle, ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest},
        config::Config,
        http::server,
    },
};

#[cfg(test)]
use crate::commons::crypto::IdCert;

pub const KRILL_SERVER_URI: &str = "https://localhost:3000/";
pub const KRILL_PUBD_SERVER_URI: &str = "https://localhost:3001/";

pub fn init_logging() {
    // Just creates a test config so we can initialize logging, then forgets about it
    let d = PathBuf::from(".");
    let _ = Config::test(&d, false, false, false).init_logging();
}

pub fn info(msg: impl std::fmt::Display) {
    info!("{}", msg); // we can change this to using the logger crate later
}

pub async fn sleep_seconds(secs: u64) {
    sleep(Duration::from_secs(secs)).await
}

pub async fn sleep_millis(millis: u64) {
    sleep(Duration::from_millis(millis)).await
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
        match httpclient::client(&health) {
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
        sleep_millis(100).await;
    }

    false
}

pub fn test_config(dir: &Path, enable_testbed: bool, enable_ca_refresh: bool, enable_suspend: bool) -> Config {
    if enable_testbed {
        crate::constants::enable_test_mode();
        crate::constants::enable_test_announcements();
    }
    Config::test(dir, enable_testbed, enable_ca_refresh, enable_suspend)
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
pub async fn start_krill_with_default_test_config(
    enable_testbed: bool,
    enable_ca_refresh: bool,
    enable_suspend: bool,
) -> PathBuf {
    let dir = tmp_dir();
    let config = test_config(&dir, enable_testbed, enable_ca_refresh, enable_suspend);
    start_krill(config).await;
    dir
}

async fn start_krill(config: Config) {
    init_config(&config);
    tokio::spawn(start_krill_with_error_trap(Arc::new(config)));
    assert!(krill_server_ready().await);
}

async fn start_krill_with_error_trap(config: Arc<Config>) {
    if let Err(err) = server::start_krill_daemon(config).await {
        error!("Krill failed to start: {}", err);
    }
}

/// Starts a krill pubd for testing on its own port, and its
/// own temp dir for storage.
pub async fn start_krill_pubd() -> PathBuf {
    let dir = tmp_dir();
    let mut config = test_config(&dir, false, false, false);
    init_config(&config);
    config.port = 3001;

    tokio::spawn(start_krill_with_error_trap(Arc::new(config)));
    assert!(krill_pubd_ready().await);

    // Initialize the repository using separate URIs
    let uris = {
        let rsync_base = uri::Rsync::from_str("rsync://localhost/dedicated-repo/").unwrap();
        let rrdp_base_uri = uri::Https::from_str("https://localhost:3001/test-rrdp/").unwrap();
        PublicationServerUris::new(rrdp_base_uri, rsync_base)
    };
    let command = PubServerCommand::RepositoryInit(uris);
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

pub async fn krill_embedded_pubd_admin(command: PubServerCommand) -> ApiResponse {
    krill_admin(Command::PubServer(command)).await
}

pub async fn krill_dedicated_pubd_admin(command: PubServerCommand) -> ApiResponse {
    let options = Options::new(
        https(KRILL_PUBD_SERVER_URI),
        "secret",
        ReportFormat::Json,
        Command::PubServer(command),
    );
    match KrillClient::process(options).await {
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

pub async fn cas_refresh_all() {
    krill_admin(Command::Bulk(BulkCaCommand::Refresh)).await;
}

pub async fn cas_refresh_single(ca: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::Refresh(ca.clone()))).await;
}

pub async fn ca_suspend_child(ca: &Handle, child: &ChildHandle) {
    krill_admin(Command::CertAuth(CaCommand::ChildUpdate(
        ca.clone(),
        child.clone(),
        UpdateChildRequest::suspend(),
    )))
    .await;
}

pub async fn ca_unsuspend_child(ca: &Handle, child: &ChildHandle) {
    krill_admin(Command::CertAuth(CaCommand::ChildUpdate(
        ca.clone(),
        child.clone(),
        UpdateChildRequest::unsuspend(),
    )))
    .await;
}

pub async fn init_ca(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::Init(CertAuthInit::new(handle.clone())))).await;
}

pub async fn delete_ca(ca: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::Delete(ca.clone()))).await;
}

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

pub async fn suspend_inactive_child(ca: &Handle, child: &ChildHandle) {
    let update = UpdateChildRequest::suspend();

    krill_admin(Command::CertAuth(CaCommand::ChildUpdate(
        ca.clone(),
        child.clone(),
        update,
    )))
    .await;
}

pub async fn unsuspend_child(ca: &Handle, child: &ChildHandle) {
    let update = UpdateChildRequest::unsuspend();

    krill_admin(Command::CertAuth(CaCommand::ChildUpdate(
        ca.clone(),
        child.clone(),
        update,
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
    cas_refresh_all().await;
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

pub async fn ca_aspas_add(handle: &Handle, aspa: AspaDefinition) {
    krill_admin(Command::CertAuth(CaCommand::AspasAddOrReplace(handle.clone(), aspa))).await;
}

pub async fn ca_aspas_expect(handle: &Handle, expected_aspas: AspaDefinitionList) {
    let res = krill_admin(Command::CertAuth(CaCommand::AspasList(handle.clone()))).await;

    if let ApiResponse::AspaDefinitions(found_aspas) = res {
        if expected_aspas != found_aspas {
            panic!("Expected ASPAs:\n{}, Got ASPAs:\n{}", expected_aspas, found_aspas)
        }
    } else {
        panic!("Expected AspaDefinitionsList")
    }
}

pub async fn ca_aspas_update(handle: &Handle, customer: AspaCustomer, update: AspaProvidersUpdate) {
    krill_admin(Command::CertAuth(CaCommand::AspasUpdate(
        handle.clone(),
        customer,
        update,
    )))
    .await;
}

pub async fn ca_aspas_remove(handle: &Handle, customer: AspaCustomer) {
    krill_admin(Command::CertAuth(CaCommand::AspasRemove(handle.clone(), customer))).await;
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
        cas_refresh_all().await;
        sleep_seconds(1).await
    }
    false
}

pub async fn ca_equals_resources(handle: &Handle, resources: &ResourceSet) -> bool {
    for _ in 0..30_u8 {
        if &ca_current_resources(handle).await == resources {
            return true;
        }
        cas_refresh_all().await;
        sleep_seconds(1).await
    }
    false
}

pub async fn rc_is_removed(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;
        if ca.resource_classes().get(&ResourceClassName::default()).is_none() {
            return true;
        }
        cas_refresh_all().await;
        sleep_seconds(100).await
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
    match krill_embedded_pubd_admin(PubServerCommand::PublisherList).await {
        ApiResponse::PublisherList(pub_list) => pub_list,
        _ => panic!("Expected publisher list"),
    }
}

pub async fn publisher_details(publisher: &PublisherHandle) -> PublisherDetails {
    match krill_embedded_pubd_admin(PubServerCommand::ShowPublisher(publisher.clone())).await {
        ApiResponse::PublisherDetails(pub_details) => pub_details,
        _ => panic!("Expected publisher details"),
    }
}

pub async fn dedicated_repo_publisher_details(publisher: &PublisherHandle) -> PublisherDetails {
    match krill_dedicated_pubd_admin(PubServerCommand::ShowPublisher(publisher.clone())).await {
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

pub fn handle(s: &str) -> Handle {
    Handle::from_str(s).unwrap()
}

pub fn ipv4_resources(v4: &str) -> ResourceSet {
    ResourceSet::from_strs("", v4, "").unwrap()
}

pub fn resources(asn: &str, v4: &str, v6: &str) -> ResourceSet {
    ResourceSet::from_strs(asn, v4, v6).unwrap()
}

pub fn rcn(nr: u32) -> ResourceClassName {
    ResourceClassName::from(nr)
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

pub async fn repo_update(ca: &Handle, contact: RepositoryContact) {
    let command = Command::CertAuth(CaCommand::RepoUpdate(ca.clone(), contact));
    krill_admin(command).await;
}

pub async fn embedded_repository_response(publisher: &PublisherHandle) -> rfc8183::RepositoryResponse {
    let command = PubServerCommand::RepositoryResponse(publisher.clone());
    match krill_embedded_pubd_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

pub async fn embedded_repo_add_publisher(req: rfc8183::PublisherRequest) {
    let command = PubServerCommand::AddPublisher(req);
    krill_embedded_pubd_admin(command).await;
}

pub async fn dedicated_repository_response(publisher: &PublisherHandle) -> rfc8183::RepositoryResponse {
    let command = PubServerCommand::RepositoryResponse(publisher.clone());
    match krill_dedicated_pubd_admin(command).await {
        ApiResponse::Rfc8183RepositoryResponse(response) => response,
        _ => panic!("Expected repository response."),
    }
}

pub async fn dedicated_repo_add_publisher(req: rfc8183::PublisherRequest) {
    let command = PubServerCommand::AddPublisher(req);
    krill_dedicated_pubd_admin(command).await;
}

pub async fn set_up_ca_with_repo(ca: &Handle) {
    init_ca(ca).await;

    // Add the CA as a publisher
    let publisher_request = publisher_request(ca).await;
    embedded_repo_add_publisher(publisher_request).await;

    // Get a Repository Response for the CA
    let response = embedded_repository_response(ca).await;

    // Update the repo for the child
    let contact = RepositoryContact::new(response);
    repo_update(ca, contact).await;
}

pub async fn expected_mft_and_crl(ca: &Handle, rcn: &ResourceClassName) -> Vec<String> {
    let rc_key = ca_key_for_rcn(ca, rcn).await;
    let mft_file = rc_key.incoming_cert().mft_name().to_string();
    let crl_file = rc_key.incoming_cert().crl_name().to_string();
    vec![mft_file, crl_file]
}

pub async fn expected_new_key_mft_and_crl(ca: &Handle, rcn: &ResourceClassName) -> Vec<String> {
    let rc_key = ca_new_key_for_rcn(ca, rcn).await;
    let mft_file = rc_key.incoming_cert().mft_name().to_string();
    let crl_file = rc_key.incoming_cert().crl_name().to_string();
    vec![mft_file, crl_file]
}

pub async fn expected_issued_cer(ca: &Handle, rcn: &ResourceClassName) -> String {
    let rc_key = ca_key_for_rcn(ca, rcn).await;
    ObjectName::from(rc_key.incoming_cert().cert()).to_string()
}

pub async fn will_publish_embedded(test_msg: &str, publisher: &PublisherHandle, files: &[String]) -> bool {
    will_publish(test_msg, publisher, files, PubServer::Embedded).await
}

pub async fn will_publish_dedicated(test_msg: &str, publisher: &PublisherHandle, files: &[String]) -> bool {
    will_publish(test_msg, publisher, files, PubServer::Dedicated).await
}

enum PubServer {
    Embedded,
    Dedicated,
}

async fn will_publish(test_msg: &str, publisher: &PublisherHandle, files: &[String], server: PubServer) -> bool {
    let objects: Vec<_> = files.iter().map(|s| s.as_str()).collect();
    for _ in 0..6000 {
        let details = {
            match &server {
                PubServer::Dedicated => dedicated_repo_publisher_details(publisher).await,
                PubServer::Embedded => publisher_details(publisher).await,
            }
        };

        let current_files = details.current_files();

        if current_files.len() == objects.len() {
            let current_files: Vec<&uri::Rsync> = current_files.iter().map(|p| p.uri()).collect();
            let mut all_matched = true;
            for o in &objects {
                if !current_files.iter().any(|uri| uri.ends_with(o)) {
                    all_matched = false;
                }
            }
            if all_matched {
                return true;
            }
        }

        sleep_millis(100).await;
    }

    let details = publisher_details(publisher).await;

    eprintln!(
        "Did not find match for test: {}, for publisher: {}",
        test_msg, publisher
    );
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

pub async fn set_up_ca_under_parent_with_resources(ca: &Handle, parent: &ParentHandle, resources: &ResourceSet) {
    let child_request = request(ca).await;
    let parent = {
        let contact = add_child_rfc6492(parent, ca, child_request, resources.clone()).await;
        ParentCaReq::new(parent.clone(), contact)
    };
    add_parent_to_ca(ca, parent).await;
    assert!(ca_contains_resources(ca, resources).await);
}

pub async fn ca_roll_init(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollInit(handle.clone()))).await;
}

pub async fn ca_roll_activate(handle: &Handle) {
    krill_admin(Command::CertAuth(CaCommand::KeyRollActivate(handle.clone()))).await;
}

pub async fn state_becomes_new_key(handle: &Handle) -> bool {
    for _ in 0..30_u8 {
        let ca = ca_details(handle).await;

        // wait for ALL RCs to become state new key
        let rc_map = ca.resource_classes();

        let expected = rc_map.len();
        let mut found = 0;

        for rc in rc_map.values() {
            if let ResourceClassKeysInfo::RollNew(_) = rc.keys() {
                found += 1;
            }
        }

        if found == expected {
            return true;
        }

        sleep_seconds(1).await
    }
    false
}

pub async fn state_becomes_active(handle: &Handle) -> bool {
    for _ in 0..300 {
        let ca = ca_details(handle).await;

        // wait for ALL RCs to become state active key
        let rc_map = ca.resource_classes();

        let expected = rc_map.len();
        let mut found = 0;

        for rc in rc_map.values() {
            if let ResourceClassKeysInfo::Active(_) = rc.keys() {
                found += 1;
            }
        }

        if found == expected {
            return true;
        }

        sleep_millis(100).await
    }
    false
}

#[cfg(test)]
pub fn test_id_certificate() -> IdCert {
    let data = include_bytes!("../test-resources/oob/id_publisher_ta.cer");
    IdCert::decode(Bytes::from_static(data)).unwrap()
}
