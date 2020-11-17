//! An RPKI publication protocol server.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Duration;

use rpki::cert::Cert;
use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::{
    AddChildRequest, AllCertAuthIssues, CaCommandDetails, CaRepoDetails, CertAuthInfo, CertAuthInit, CertAuthIssues,
    CertAuthList, CertAuthStats, ChildAuthRequest, ChildCaInfo, ChildHandle, CommandHistory, CommandHistoryCriteria,
    Handle, ListReply, ParentCaContact, ParentCaReq, ParentHandle, ParentStatuses, PublishDelta, PublisherDetails,
    PublisherHandle, RepoInfo, RepoStatus, RepositoryContact, RepositoryUpdate, ResourceSet, RoaDefinition,
    RoaDefinitionUpdates, RtaList, RtaName, RtaPrepResponse, ServerInfo, TaCertDetails, UpdateChildRequest,
};
use crate::commons::bgp::{BgpAnalyser, BgpAnalysisReport, BgpAnalysisSuggestion};
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error;
use crate::commons::eventsourcing::CommandKey;
use crate::commons::remote::rfc8183;
use crate::commons::{KrillEmptyResult, KrillResult};
use crate::constants::*;
use crate::daemon::auth::{Auth, Authorizer};
use crate::daemon::ca::{
    self, ta_handle, testbed_ca_handle, ResourceTaggedAttestation, RouteAuthorizationUpdates, RtaContentRequest,
    RtaPrepareRequest,
};
use crate::daemon::config::Config;
use crate::daemon::mq::EventQueueListener;
use crate::daemon::scheduler::Scheduler;
use crate::pubd::{PubServer, RepoStats};
use crate::publish::CaPublisher;

//------------ KrillServer ---------------------------------------------------

/// This is the master krill server that is doing all the orchestration
/// for all the components.
pub struct KrillServer {
    // The base URI for this service
    service_uri: uri::Https,

    // The base working directory, used for various storage
    work_dir: PathBuf,

    // Component responsible for API authorization checks
    authorizer: Authorizer,

    // Publication server, with CONFIGured publishers
    pubserver: Option<Arc<PubServer>>,

    // Handles the internal TA and/or CAs
    caserver: Arc<ca::CaServer>,

    // Handles the internal TA and/or CAs
    bgp_analyser: Arc<BgpAnalyser>,

    // Responsible for background tasks, e.g. re-publishing
    #[allow(dead_code)] // just need to keep this in scope
    scheduler: Scheduler,

    // Time this server was started
    started: Time,

    // Global size constraints on things which can be posted
    post_limits: PostLimits,
}

pub struct PostLimits {
    api: u64,
    rfc6492: u64,
    rfc8181: u64,
}

impl PostLimits {
    fn new(api: u64, rfc6492: u64, rfc8181: u64) -> Self {
        PostLimits { api, rfc8181, rfc6492 }
    }

    pub fn api(&self) -> u64 {
        self.api
    }
    pub fn rfc6492(&self) -> u64 {
        self.rfc6492
    }
    pub fn rfc8181(&self) -> u64 {
        self.rfc8181
    }
}

/// # Set up and initialisation
impl KrillServer {
    /// Creates a new publication server. Note that state is preserved
    /// on disk in the work_dir provided.
    pub async fn build(config: Arc<Config>) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let service_uri = config.service_uri();
        let token = &config.auth_token;

        info!("Starting {} v{}", KRILL_SERVER_APP, KRILL_VERSION);
        info!("{} uses service uri: {}", KRILL_SERVER_APP, service_uri);

        let mut repo_dir = work_dir.clone();
        repo_dir.push("repo");

        let signer = Arc::new(KrillSigner::build(work_dir)?);
        let authorizer = Authorizer::new(token);

        let pubserver = {
            if config.repo_enabled {
                Some(PubServer::build(config.clone(), signer.clone())?)
            } else {
                PubServer::remove_if_empty(config.clone(), signer.clone())?
            }
        };
        let pubserver: Option<Arc<PubServer>> = pubserver.map(Arc::new);

        let event_queue = Arc::new(EventQueueListener::default());
        let caserver = Arc::new(ca::CaServer::build(config.clone(), event_queue.clone(), signer).await?);

        if config.use_ta() {
            let ta_handle = ta_handle();
            if !caserver.has_ca(&ta_handle)? {
                info!("Creating embedded Trust Anchor");

                let pubserver = pubserver.as_ref().ok_or_else(|| Error::PublisherNoEmbeddedRepo)?;
                let repo_info: RepoInfo = pubserver.repo_info_for(&ta_handle)?;

                let ta_uri = config.ta_cert_uri();

                let ta_aia = format!("{}ta/ta.cer", config.rsync_base.to_string());
                let ta_aia = uri::Rsync::from_string(ta_aia).unwrap();

                // Add TA
                caserver.init_ta(repo_info, ta_aia, vec![ta_uri]).await?;

                let ta = caserver.get_trust_anchor().await?;

                // Add publisher
                let req = rfc8183::PublisherRequest::new(None, ta_handle.clone(), ta.id_cert().clone());

                pubserver.create_publisher(req)?;

                // Force initial publication
                caserver.republish(&ta_handle).await?;
            }
        }

        if config.testbed_enabled {
            let ta_handle = ta_handle();
            if caserver.has_ca(&ta_handle)? {
                let testbed_ca_handle = testbed_ca_handle();
                if !caserver.has_ca(&testbed_ca_handle)? {
                    info!("Creating embedded Testbed CA");

                    // Add the new testbed CA
                    caserver.init_ca(&testbed_ca_handle)?;
                    let testbed_ca = caserver.get_ca(&testbed_ca_handle).await?;

                    // Add the new testbed publisher
                    let pubserver = pubserver.as_ref().ok_or_else(|| Error::PublisherNoEmbeddedRepo)?;
                    let pub_req =
                        rfc8183::PublisherRequest::new(None, testbed_ca_handle.clone(), testbed_ca.id_cert().clone());
                    pubserver.create_publisher(pub_req)?;
                    let rfc8181_uri =
                        uri::Https::from_string(format!("{}rfc8181/{}", service_uri, testbed_ca_handle)).unwrap();
                    let repo_response = pubserver.repository_response(rfc8181_uri, &testbed_ca_handle)?;
                    let repo_contact = RepositoryContact::Rfc8181(repo_response);
                    caserver.update_repo(testbed_ca_handle.clone(), repo_contact).await?;
                    caserver.republish(&testbed_ca_handle).await?;

                    // Establish the TA (parent) <-> testbed CA (child) relationship
                    let testbed_ca_resources = ResourceSet::all_resources();
                    let auth = ChildAuthRequest::Rfc8183(testbed_ca.child_request());
                    let child_req = AddChildRequest::new(testbed_ca_handle.clone(), testbed_ca_resources, auth);
                    let parent_ca_contact = caserver.ca_add_child(&ta_handle, child_req, &service_uri).await?;
                    let parent_req = ParentCaReq::new(ta_handle.clone(), parent_ca_contact);
                    caserver.ca_parent_add(testbed_ca_handle, parent_req).await?;
                }
            }
        }

        let bgp_analyser = Arc::new(BgpAnalyser::new(
            config.bgp_risdumps_enabled,
            &config.bgp_risdumps_v4_uri,
            &config.bgp_risdumps_v6_uri,
        ));

        let scheduler = Scheduler::build(
            event_queue,
            caserver.clone(),
            pubserver.clone(),
            bgp_analyser.clone(),
            &config,
        );

        let post_limits = PostLimits::new(
            config.post_limit_api,
            config.post_limit_rfc6492,
            config.post_limit_rfc8181,
        );

        Ok(KrillServer {
            service_uri,
            work_dir: work_dir.clone(),
            authorizer,
            pubserver,
            caserver,
            bgp_analyser,
            scheduler,
            started: Time::now(),
            post_limits,
        })
    }

    pub fn service_base_uri(&self) -> &uri::Https {
        &self.service_uri
    }

    pub fn server_info(&self) -> ServerInfo {
        ServerInfo::new(KRILL_VERSION, self.started)
    }
}

/// # Authentication and Access
impl KrillServer {
    pub fn is_api_allowed(&self, auth: &Auth) -> bool {
        self.authorizer.is_api_allowed(auth)
    }

    pub fn limit_api(&self) -> u64 {
        self.post_limits.api()
    }

    pub fn limit_rfc8181(&self) -> u64 {
        self.post_limits.rfc8181()
    }

    pub fn limit_rfc6492(&self) -> u64 {
        self.post_limits.rfc6492()
    }

    pub fn testbed_enabled(&self) -> bool {
        self.caserver.testbed_enabled()
    }
}

/// # Configure publishers
impl KrillServer {
    fn get_embedded(&self) -> KrillResult<&Arc<PubServer>> {
        self.pubserver.as_ref().ok_or_else(|| Error::PublisherNoEmbeddedRepo)
    }

    /// Returns the repository server stats
    pub fn repo_stats(&self) -> KrillResult<RepoStats> {
        self.get_embedded()?.repo_stats()
    }

    /// Returns all currently CONFIGured publishers. (excludes deactivated)
    pub fn publishers(&self) -> KrillResult<Vec<Handle>> {
        self.get_embedded()?.publishers()
    }

    /// Adds the publishers, blows up if it already existed.
    pub fn add_publisher(&self, req: rfc8183::PublisherRequest) -> KrillResult<rfc8183::RepositoryResponse> {
        let publisher_handle = req.publisher_handle().clone();

        self.get_embedded()?.create_publisher(req)?;

        self.repository_response(&publisher_handle)
    }

    /// Removes a publisher, blows up if it didn't exist.
    pub fn remove_publisher(&mut self, publisher: PublisherHandle) -> KrillEmptyResult {
        self.get_embedded()?.remove_publisher(publisher)
    }

    /// Returns a publisher.
    pub fn get_publisher(&self, publisher: &PublisherHandle) -> KrillResult<PublisherDetails> {
        self.get_embedded()?.get_publisher_details(publisher)
    }

    pub fn rrdp_base_path(&self) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push("repo/rrdp");
        path
    }
}

/// # Manage RFC8181 clients
///
impl KrillServer {
    pub fn repository_response(&self, publisher: &PublisherHandle) -> KrillResult<rfc8183::RepositoryResponse> {
        let rfc8181_uri = uri::Https::from_string(format!("{}rfc8181/{}", self.service_uri, publisher)).unwrap();
        self.get_embedded()?.repository_response(rfc8181_uri, publisher)
    }

    pub fn rfc8181(&self, publisher: PublisherHandle, msg_bytes: Bytes) -> KrillResult<Bytes> {
        self.get_embedded()?.rfc8181(publisher, msg_bytes)
    }
}

/// # Being a parent
///
impl KrillServer {
    pub async fn ta(&self) -> KrillResult<TaCertDetails> {
        let ta = self.caserver.get_ca(&ta_handle()).await?;
        if let ParentCaContact::Ta(ta) = ta.parent(&ta_handle()).unwrap() {
            Ok(ta.clone())
        } else {
            panic!("Found TA which was not initialized as TA.")
        }
    }

    pub async fn trust_anchor_cert(&self) -> Option<Cert> {
        self.ta().await.ok().map(|details| details.cert().clone())
    }

    /// Adds a child to a CA and returns the ParentCaInfo that the child
    /// will need to contact this CA for resource requests.
    pub async fn ca_add_child(&self, parent: &ParentHandle, req: AddChildRequest) -> KrillResult<ParentCaContact> {
        let contact = self.caserver.ca_add_child(parent, req, &self.service_uri).await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_contact(&self, parent: &ParentHandle, child: ChildHandle) -> KrillResult<ParentCaContact> {
        let contact = self
            .caserver
            .ca_parent_contact(parent, child, None, &self.service_uri)
            .await?;
        Ok(contact)
    }

    /// Shows the parent contact for a child.
    pub async fn ca_parent_response(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
    ) -> KrillResult<rfc8183::ParentResponse> {
        let contact = self
            .caserver
            .ca_parent_response(parent, child, None, &self.service_uri)
            .await?;
        Ok(contact)
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_update(
        &self,
        parent: &ParentHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
    ) -> KrillEmptyResult {
        self.caserver.ca_child_update(parent, child, req).await?;
        Ok(())
    }

    /// Update IdCert or resources of a child.
    pub async fn ca_child_remove(&self, handle: &Handle, child: ChildHandle) -> KrillEmptyResult {
        self.caserver.ca_child_remove(handle, child).await?;
        Ok(())
    }

    /// Show details for a child under the TA.
    pub async fn ca_child_show(&self, parent: &ParentHandle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        let child = self.caserver.ca_show_child(parent, child).await?;
        Ok(child)
    }
}

/// # Being a child
///
impl KrillServer {
    /// Returns the child request for a CA, or NONE if the CA cannot be found.
    pub async fn ca_child_req(&self, handle: &Handle) -> KrillResult<rfc8183::ChildRequest> {
        self.caserver.get_ca(handle).await.map(|ca| ca.child_request())
    }

    /// Adds a parent to a CA, will check first if the parent can be reached.
    pub async fn ca_parent_add(&self, handle: Handle, parent: ParentCaReq) -> KrillEmptyResult {
        self.ca_parent_reachable(&handle, parent.handle(), parent.contact())
            .await
            .map_err(|_| Error::CaParentAddNotResponsive(handle.clone(), parent.handle().clone()))?;
        Ok(self.caserver.ca_parent_add(handle, parent).await?)
    }

    /// Updates a parent contact for a CA
    pub async fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> KrillEmptyResult {
        self.ca_parent_reachable(&handle, &parent, &contact).await?;
        Ok(self.caserver.ca_parent_update(handle, parent, contact).await?)
    }

    async fn ca_parent_reachable(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
    ) -> KrillEmptyResult {
        self.caserver
            .get_entitlements_from_parent_and_contact(handle, parent, contact)
            .await?;
        Ok(())
    }

    pub async fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle) -> KrillEmptyResult {
        Ok(self.caserver.ca_parent_remove(handle, parent).await?)
    }
}

/// # Stats and status of CAS
///
impl KrillServer {
    pub async fn cas_stats(&self) -> HashMap<Handle, CertAuthStats> {
        let mut res = HashMap::new();

        if let Ok(list) = self.ca_list() {
            for ca in list.cas() {
                // can't fail really, but to be sure
                if let Ok(ca) = self.caserver.get_ca(ca.handle()).await {
                    let roas = ca.roa_definitions();
                    let roa_count = roas.len();
                    let child_count = ca.children().count();

                    let bgp_report = if ca.handle().as_str() == "ta" || ca.handle().as_str() == "testbed" {
                        BgpAnalysisReport::new(vec![])
                    } else {
                        self.bgp_analyser.analyse(roas.as_slice(), &ca.all_resources()).await
                    };

                    res.insert(
                        ca.handle().clone(),
                        CertAuthStats::new(roa_count, child_count, bgp_report.into()),
                    );
                }
            }
        }

        res
    }

    pub async fn all_ca_issues(&self) -> KrillResult<AllCertAuthIssues> {
        let mut all_issues = AllCertAuthIssues::default();
        for ca in self.ca_list()?.cas() {
            let issues = self.ca_issues(ca.handle()).await?;
            if !issues.is_empty() {
                all_issues.add(ca.handle().clone(), issues);
            }
        }

        Ok(all_issues)
    }

    pub async fn ca_issues(&self, ca_handle: &Handle) -> KrillResult<CertAuthIssues> {
        let mut issues = CertAuthIssues::default();

        let status = self.ca_repo_status(ca_handle).await?;

        if let Some(error) = status.into_failure_opt() {
            issues.add_repo_issue(error)
        }

        let parent_statuses = self.caserver.ca_parent_statuses(ca_handle).await?;
        for (parent, status) in parent_statuses.into_iter() {
            if let Some(error) = status.into_failure_opt() {
                issues.add_parent_issue(parent, error)
            }
        }

        Ok(issues)
    }
}

/// # Bulk background operations CAS
///
impl KrillServer {
    /// Republish all CAs that need it.
    pub async fn republish_all(&self) -> KrillEmptyResult {
        self.caserver.republish_all().await?;
        Ok(())
    }

    /// Re-sync all CAs with their repositories
    pub async fn resync_all(&self) -> KrillEmptyResult {
        let publisher = CaPublisher::new(self.caserver.clone(), self.pubserver.clone());

        for ca in self.ca_list()?.cas() {
            if let Err(e) = publisher.publish(ca.handle()).await {
                error!("Failed to sync ca: {}. Got error: {}", ca.handle(), e)
            }
        }

        Ok(())
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub async fn refresh_all(&self) -> KrillEmptyResult {
        self.caserver.resync_all().await;
        Ok(())
    }

    /// Archive old commands
    pub async fn archive_old_commands(&self, days: i64) -> KrillEmptyResult {
        self.caserver.archive_old_commands(days).await?;
        if let Some(pubserver) = self.pubserver.as_ref() {
            pubserver.archive_old_commands(days)?;
        }
        Ok(())
    }
}

/// # Admin CAS
///
impl KrillServer {
    pub fn ca_list(&self) -> KrillResult<CertAuthList> {
        self.caserver.ca_list()
    }

    /// Returns the public CA info for a CA, or NONE if the CA cannot be found.
    pub async fn ca_info(&self, handle: &Handle) -> KrillResult<CertAuthInfo> {
        self.caserver.get_ca(handle).await.map(|ca| ca.as_ca_info())
    }

    /// Returns the parent contact for a CA and parent, or NONE if either the CA or the parent cannot be found.
    pub async fn ca_my_parent_contact(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<ParentCaContact> {
        let ca = self.caserver.get_ca(handle).await?;
        ca.parent(parent).map(|p| p.clone())
    }

    pub async fn ca_my_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> {
        self.caserver.ca_parent_statuses(ca).await
    }

    /// Returns the history for a CA, or NONE in case of issues (i.e. it does not exist).
    pub async fn ca_history(&self, handle: &Handle, crit: CommandHistoryCriteria) -> Option<CommandHistory> {
        self.caserver.get_ca_history(handle, crit).await.ok()
    }

    pub fn ca_command_details(&self, handle: &Handle, command: CommandKey) -> KrillResult<CaCommandDetails> {
        self.caserver.get_ca_command_details(handle, command)
    }

    /// Returns the publisher request for a CA, or NONE of the CA cannot be found.
    pub async fn ca_publisher_req(&self, handle: &Handle) -> Option<rfc8183::PublisherRequest> {
        self.caserver.get_ca(handle).await.map(|ca| ca.publisher_request()).ok()
    }

    pub async fn ca_init(&mut self, init: CertAuthInit) -> KrillEmptyResult {
        let handle = init.unpack();

        // Create CA
        self.caserver.init_ca(&handle)?;

        Ok(())
    }

    /// Return the info about the CONFIGured repository server for a given Ca.
    /// and the actual objects published there, as reported by a list reply.
    pub async fn ca_repo_details(&self, handle: &Handle) -> KrillResult<CaRepoDetails> {
        let ca = self.caserver.get_ca(handle).await?;
        let contact = ca.get_repository_contact()?;
        Ok(CaRepoDetails::new(contact.clone()))
    }

    pub async fn ca_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> {
        self.caserver.ca_repo_status(ca).await
    }

    /// Update the repository for a CA, or return an error. (see `CertAuth::repo_update`)
    pub async fn ca_update_repo(&self, handle: Handle, update: RepositoryUpdate) -> KrillEmptyResult {
        let contact = match update {
            RepositoryUpdate::Embedded => {
                // Add to embedded publication server if not present
                if self.get_embedded()?.get_publisher_details(&handle).is_err() {
                    let id_cert = {
                        let ca = self.caserver.get_ca(&handle).await?;
                        ca.id_cert().clone()
                    };

                    // Add publisher
                    let req = rfc8183::PublisherRequest::new(None, handle.clone(), id_cert);
                    self.add_publisher(req)?;
                }

                RepositoryContact::embedded(self.get_embedded()?.repo_info_for(&handle)?)
            }
            RepositoryUpdate::Rfc8181(response) => {
                // first check that the new repo can be contacted
                if let Err(error) = self.caserver.send_rfc8181_list(&handle, &response, false).await {
                    return Err(Error::CaRepoIssue(handle, error.to_error_response().msg().to_string()));
                }

                RepositoryContact::Rfc8181(response)
            }
        };

        Ok(self.caserver.update_repo(handle, contact).await?)
    }

    pub async fn ca_update_id(&self, handle: Handle) -> KrillEmptyResult {
        Ok(self.caserver.ca_update_id(handle).await?)
    }

    pub async fn ca_keyroll_init(&self, handle: Handle) -> KrillEmptyResult {
        Ok(self.caserver.ca_keyroll_init(handle, Duration::seconds(0)).await?)
    }

    pub async fn ca_keyroll_activate(&self, handle: Handle) -> KrillEmptyResult {
        Ok(self.caserver.ca_keyroll_activate(handle, Duration::seconds(0)).await?)
    }

    pub async fn rfc6492(&self, handle: Handle, msg_bytes: Bytes) -> KrillResult<Bytes> {
        Ok(self.caserver.rfc6492(&handle, msg_bytes).await?)
    }
}

/// # Handle route authorization requests
///
impl KrillServer {
    pub async fn ca_routes_update(&self, handle: Handle, updates: RoaDefinitionUpdates) -> KrillEmptyResult {
        Ok(self.caserver.ca_routes_update(handle, updates.into()).await?)
    }

    pub async fn ca_routes_show(&self, handle: &Handle) -> KrillResult<Vec<RoaDefinition>> {
        let ca = self.caserver.get_ca(handle).await?;
        Ok(ca.roa_definitions())
    }

    pub async fn ca_routes_bgp_analysis(&self, handle: &Handle) -> KrillResult<BgpAnalysisReport> {
        let ca = self.caserver.get_ca(handle).await?;
        let definitions = ca.roa_definitions();
        let resources = ca.all_resources();
        Ok(self.bgp_analyser.analyse(definitions.as_slice(), &resources).await)
    }

    pub async fn ca_routes_bgp_dry_run(
        &self,
        handle: &Handle,
        updates: RoaDefinitionUpdates,
    ) -> KrillResult<BgpAnalysisReport> {
        let ca = self.caserver.get_ca(handle).await?;

        let updates: RouteAuthorizationUpdates = updates.into();
        let updates = updates.into_explicit();
        let resources = updates.affected_prefixes();

        let (would_be_routes, _) = ca.update_authorizations(&updates)?;
        let roas: Vec<RoaDefinition> = would_be_routes
            .into_authorizations()
            .into_iter()
            .map(|a| a.into())
            .collect();

        Ok(self.bgp_analyser.analyse(roas.as_slice(), &resources).await)
    }

    pub async fn ca_routes_bgp_suggest(
        &self,
        handle: &Handle,
        scope: Option<ResourceSet>,
    ) -> KrillResult<BgpAnalysisSuggestion> {
        let ca = self.caserver.get_ca(handle).await?;
        let definitions = ca.roa_definitions();
        let mut resources = ca.all_resources();

        if let Some(scope) = scope {
            resources = resources.intersection(&scope);
        }

        Ok(self.bgp_analyser.suggest(definitions.as_slice(), &resources).await)
    }
}

/// # Handle publication requests
///
impl KrillServer {
    /// Handles a publish delta request sent to the API, or.. through
    /// the CmsProxy.
    pub fn handle_delta(&self, publisher: PublisherHandle, delta: PublishDelta) -> KrillEmptyResult {
        self.get_embedded()?.publish(publisher, delta)
    }

    /// Handles a list request sent to the API, or.. through the CmsProxy.
    pub fn handle_list(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.get_embedded()?.list(publisher)
    }
}

/// # Handle Resource Tagged Attestation requests
///
impl KrillServer {
    /// List all known RTAs
    pub async fn rta_list(&self, ca: Handle) -> KrillResult<RtaList> {
        let ca = self.caserver.get_ca(&ca).await?;
        Ok(ca.rta_list())
    }

    /// Show RTA
    pub async fn rta_show(&self, ca: Handle, name: RtaName) -> KrillResult<ResourceTaggedAttestation> {
        let ca = self.caserver.get_ca(&ca).await?;
        ca.rta_show(&name)
    }

    /// Sign an RTA - either a new, or a prepared RTA
    pub async fn rta_sign(&self, ca: Handle, name: RtaName, request: RtaContentRequest) -> KrillResult<()> {
        self.caserver.rta_sign(ca, name, request).await
    }

    /// Prepare a multi
    pub async fn rta_multi_prep(
        &self,
        ca: Handle,
        name: RtaName,
        request: RtaPrepareRequest,
    ) -> KrillResult<RtaPrepResponse> {
        self.caserver.rta_multi_prep(&ca, name.clone(), request).await?;
        let ca = self.caserver.get_ca(&ca).await?;
        ca.rta_prep_response(&name)
    }

    /// Co-sign an existing RTA
    pub async fn rta_multi_cosign(&self, ca: Handle, name: RtaName, rta: ResourceTaggedAttestation) -> KrillResult<()> {
        self.caserver.rta_multi_cosign(ca, name, rta).await
    }
}

// Tested through integration tests
