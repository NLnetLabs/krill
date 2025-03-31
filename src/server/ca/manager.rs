//! A manager for all CAs.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use chrono::Duration;
use log::{debug, error, info, trace, warn};
use rpki::uri;
use rpki::ca::{provisioning, publication};
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, ParentResponse, PublisherRequest,
    ServiceUri
};
use rpki::ca::provisioning::{
    IssuanceRequest, ProvisioningCms, ResourceClassListResponse,
    ResourceClassName, RevocationRequest, RevocationResponse,
};
use rpki::ca::publication::{
    ListReply, Publish, PublishDelta, Update, Withdraw
};
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use crate::api::admin::{
    AddChildRequest, ParentCaContact, ParentCaReq, ParentServerInfo,
    PublicationServerInfo, PublishedFile, RepositoryContact,
    UpdateChildRequest,
};
use crate::api::aspa::{
    AspaDefinitionList, AspaDefinitionUpdates, AspaProvidersUpdate,
    CustomerAsn,
};
use crate::api::bgpsec::{BgpSecCsrInfoList, BgpSecDefinitionUpdates};
use crate::api::ca::{
    CertAuthIssues, CertAuthList, CertAuthSummary, ChildCaInfo, IdCertInfo,
    ParentStatuses, ReceivedCert, RepoStatus, RtaName, Timestamp,
};
use crate::api::history::{
    CommandDetails, CommandHistory, CommandHistoryCriteria
};
use crate::api::import::ImportChild;
use crate::api::roa::RoaConfigurationUpdates;
use crate::api::rta::{
    ResourceTaggedAttestation, RtaContentRequest, RtaPrepareRequest,
};
use crate::api::ta::{
    ProvisioningRequest, TrustAnchorSignedRequest, TrustAnchorSignedResponse,
    TrustAnchorSignerInfo,
};
use crate::commons::httpclient;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::cmslogger::CmsLogger;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::{Error, Error as KrillError};
use crate::commons::eventsourcing::{Aggregate, AggregateStore, SentCommand};
use crate::constants::{
    CASERVER_NS, STATUS_NS, TA_PROXY_SERVER_NS, TA_SIGNER_SERVER_NS, TA_NAME,
    ta_handle,
};
use crate::server::http::auth::{AuthInfo, Permission}; // XXX remove
use crate::config::Config;
use crate::server::mq::{now, Task, TaskQueue};
use crate::server::pubd::RepositoryManager;
use crate::server::taproxy::{
    TrustAnchorProxy, TrustAnchorProxyCommand, TrustAnchorProxyInitCommand,
};
use crate::tasigner::{
    TrustAnchorSigner, TrustAnchorSignerCommand,
    TrustAnchorSignerInitCommand, TrustAnchorSignerInitCommandDetails,
};
use super::certauth::CertAuth;
use super::commands::{
    CertAuthCommandDetails, CertAuthInitCommand, CertAuthInitCommandDetails,
};
use super::publishing::{CaObjectsStore, DeprecatedRepository};
use super::status::{CaStatus, CaStatusStore};


//------------ testbed_ca_handle ---------------------------------------------

/// The handle of the CA used by the testbed.
pub const TESTBED_CA_NAME: &str = "testbed";

/// Returns the CA handle for the testbed.
pub fn testbed_ca_handle() -> CaHandle {
    use std::str::FromStr;
    CaHandle::from_str(TESTBED_CA_NAME).unwrap()
}


//------------ CaManager -----------------------------------------------------

/// Manages access to all CAs.
pub struct CaManager {
    /// The aggregate store of all CAs.
    ca_store: AggregateStore<CertAuth>,

    /// The objects store for both CAs and TA.
    ///
    /// Used to manage objects for CAs. Also shared with the ca_store as well
    /// as a listener so that it can create manifests and CRLs as needed.
    /// Accessed here for publishing.
    ca_objects_store: Arc<CaObjectsStore>,

    /// A store with the status of all CAs.
    ///
    /// Keeps track of CA parent and CA repository interaction status.
    status_store: CaStatusStore,

    /// The aggregate store of the TA proxy.
    ///
    /// We may have a TA Proxy that we need to manage. Many functions are
    /// similar to CA operations, so it makes sense to manage this as a
    /// special kind of CA here.
    ta_proxy_store: Option<AggregateStore<TrustAnchorProxy>>,

    /// The aggreagte store of the TA signer.
    ///
    /// We may also have a local TA signer - in case we are running in
    /// testbed or benchmarking mode - so that we can do all TA signing
    /// without the need for user interactions through the API and
    /// TA signer CLI.
    ta_signer_store: Option<AggregateStore<TrustAnchorSigner>>,

    /// The task queue.
    ///
    /// This queue:
    /// - listens for events in the ca_store,
    /// - is processed by the Scheduler,
    /// - can be used here to schedule tasks through the API.
    tasks: Arc<TaskQueue>,

    /// The server configuration.
    config: Arc<Config>,

    /// The signer.
    signer: Arc<KrillSigner>,

    /// The actor used for all thing Krill does itself.
    ///
    /// This actor is used for (scheduled or triggered) system actions where
    /// we have no operator actor context.
    system_actor: Actor,
}

impl CaManager {
    /// Builds a new CA manager.
    ///
    /// Return an error if any of the various stores cannot be initialized.
    pub async fn build(
        config: Arc<Config>,
        tasks: Arc<TaskQueue>,
        signer: Arc<KrillSigner>,
        system_actor: Actor,
    ) -> KrillResult<Self> {
        // Create the AggregateStore for the event-sourced `CertAuth`
        // structures that handle most CA functions.
        let mut ca_store = AggregateStore::<CertAuth>::create(
            &config.storage_uri,
            CASERVER_NS,
            config.use_history_cache,
        )?;

        if let Err(e) = ca_store.warm() {
            // Start to 'warm' the cache. This serves two purposes:
            // 1. this ensures that all `CertAuth` structs are available in
            //    memory
            // 2. this ensures that there are no apparent data issues
            //
            // If there are issues, then we need to bail out. Krill 0.14.0+
            // uses single files for all change sets, and files
            // are first completely written to disk, and only then
            // renamed.
            //
            // In other words, if we fail to warm the cache then this points
            // at:
            // - data corruption
            // - user started
            error!(
                "Could not warm up cache, data seems corrupt. \
                 You may need to restore a backup. Error was: {e}"
            );
        }

        // Create the `CaObjectStore` that is responsible for maintaining CA
        // objects: the `CaObjects` for a CA gets copies of all objects
        // and issued certificates from the `CertAuth` and is responsible
        // for manifests and CRL generation.
        let ca_objects_store = Arc::new(CaObjectsStore::create(
            &config.storage_uri,
            config.issuance_timing.clone(),
            signer.clone(),
        )?);

        // Register the `CaObjectsStore` as a pre-save listener to the
        // 'ca_store' so that it can update its ROAs and issued
        // certificates and/or generate manifests and CRLs when relevant
        // changes occur in a `CertAuth`.
        ca_store.add_pre_save_listener(ca_objects_store.clone());

        // Register the `MessageQueue` as a pre-save listener to 'ca_store' so
        // that relevant changes in a `CertAuth` can trigger follow-up
        // actions. This is done as pre-save listener, because commands
        // that would result in a follow-up should fail, if the task cannot be
        // planned.
        //
        // Tasks will typically be picked up after the CA changes are
        // committed, but they may also be picked up sooner by another
        // thread. Because of that the tasks will remember which minimal
        // version of the CA they are intended for, so that they can
        // be rescheduled should they have been picked up too soon.
        //
        // An example of a triggered task: schedule a synchronisation with the
        // repository (publication server) in case ROAs have been
        // updated.
        ca_store.add_pre_save_listener(tasks.clone());

        // Now also register the `MessageQueue` as a post-save listener. We
        // use this to send best-effort post-save signals to children
        // in case a certificate was updated or a child key was revoked.
        // This is a no-op for remote children (we cannot send a signal over
        // RFC 6492).
        ca_store.add_post_save_listener(tasks.clone());

        // Create TA proxy store if we need it.
        let ta_proxy_store = if config.ta_proxy_enabled() {
            let mut store = AggregateStore::<TrustAnchorProxy>::create(
                &config.storage_uri,
                TA_PROXY_SERVER_NS,
                config.use_history_cache,
            )?;

            // We need a pre-save listener so that we can schedule:
            // - publication on updates
            // - signing by the Trust Anchor Signer when there are requests
            //   [in testbed mode]
            store.add_pre_save_listener(tasks.clone());

            // We need a post-save listener so that we can schedule:
            // - re-sync for local children when the proxy has new responses
            //   AND is saved
            store.add_post_save_listener(tasks.clone());

            Some(store)
        }
        else {
            None
        };

        let ta_signer_store = if config.ta_signer_enabled() {
            Some(AggregateStore::create(
                &config.storage_uri,
                TA_SIGNER_SERVER_NS,
                config.use_history_cache,
            )?)
        }
        else {
            None
        };

        // Create the status store which will maintain the last known
        // connection status between each CA and their parent(s) and
        // repository.
        let status_store = CaStatusStore::create(
            &config.storage_uri, STATUS_NS
        )?;

        Ok(CaManager {
            ca_store,
            ca_objects_store,
            status_store,
            ta_proxy_store,
            ta_signer_store,
            tasks,
            config,
            signer,
            system_actor,
        })
    }

    /// Returns whether testbed mode is enabled.
    pub fn testbed_enabled(&self) -> bool {
        self.config.testbed().is_some()
    }

    /// Processes a command for a CA.
    ///
    /// The command will be processed on the latest version of the CA.
    ///
    /// Upon success, returns the new state of the CA.
    fn process_ca_command(
        &self,
        handle: CaHandle,
        actor: &Actor,
        command: CertAuthCommandDetails,
    ) -> Result<Arc<CertAuth>, KrillError> {
        self.ca_store.command(SentCommand::new(handle, None, command, actor))
    }

    /// Republish the embedded TA and CAs if needed.
    ///
    /// If `force` is `true`, everything will be republished, otherwise only
    /// those objects that are close to expiring.
    ///
    /// Returns all CAs for which objects were republished.
    pub async fn republish_all(
        &self,
        force: bool,
    ) -> KrillResult<Vec<CaHandle>> {
        let mut res = vec![];
        for ca in self.ca_store.list()? {
            match self.ca_objects_store.reissue_if_needed(force, &ca) {
                Err(e) => {
                    error!(
                        "Could not reissue manifest and crl for {ca}.\
                        Error: {e}"
                    );
                }
                Ok(false) => {
                    trace!(
                        "No re-issuance of manifest and crl needed for {ca}"
                    );
                }
                Ok(true) => {
                    debug!("Re-issued manifest(s) and CRL(s) for {ca}");
                    res.push(ca.clone())
                }
            }
        }
        Ok(res)
    }
}

/// # Trust Anchor Support
///
impl CaManager {
    /// Sends a command to the TA proxy.
    ///
    /// Errors if TA support is not enabled.
    fn send_ta_proxy_command(
        &self,
        cmd: TrustAnchorProxyCommand,
    ) -> KrillResult<Arc<TrustAnchorProxy>> {
        self.ta_proxy_store.as_ref().ok_or_else(|| {
            Error::custom("ta_support_enabled is false")
        })?.command(cmd)
    }

    /// Sends a command to the TA signer.
    ///
    /// Errors if TA signer support is not enabled.
    fn send_ta_signer_command(
        &self,
        cmd: TrustAnchorSignerCommand,
    ) -> KrillResult<Arc<TrustAnchorSigner>> {
        self.ta_signer_store.as_ref().ok_or_else(|| {
            Error::custom("ta_signer_enabled is false")
        })?.command(cmd)
    }

    /// Returns the TA proxy.
    ///
    /// Returns an error if the TA proxy support is not nabled or the
    /// TA proxy is uninitialized.
    pub fn get_trust_anchor_proxy(
        &self,
    ) -> KrillResult<Arc<TrustAnchorProxy>> {
        self.ta_proxy_store.as_ref().ok_or_else(|| {
            Error::custom("TA proxy not enabled")
        })?.get_latest(&ta_handle())
    }

    /// Returns the TA signer.
    ///
    /// Returns an error if the TA signer support is not nabled or the
    /// TA signer is uninitialized.
    pub fn get_trust_anchor_signer(
        &self,
    ) -> KrillResult<Arc<TrustAnchorSigner>> {
        self.ta_signer_store.as_ref().ok_or_else(|| {
            Error::custom("TA signer not enabled")
        })?.get_latest(&ta_handle())
    }

    /// Initialises the Trust Anchor proxy.
    ///
    /// Returns an error if TA proxy support is not enabled or the proxy is
    /// alreay initialized.
    pub fn ta_proxy_init(&self) -> KrillResult<()> {
        let ta_handle = ta_handle();

        let ta_proxy_store = self.ta_proxy_store.as_ref().ok_or_else(|| {
            Error::custom("ta_support_enabled must be true in config")
        })?;

        if ta_proxy_store.has(&ta_handle)? {
            return Err(Error::TaAlreadyInitialized)
        }

        ta_proxy_store.add(
            TrustAnchorProxyInitCommand::make(
                ta_handle,
                self.signer.clone(),
                &self.system_actor,
            )
        )?;
        Ok(())
    }

    /// Initialises the embedded TA signer (for testbed).
    ///
    /// This assumes that the local TA proxy exists and is to be associated
    /// with this signer.
    pub fn ta_signer_init(
        &self,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        private_key_pem: Option<String>,
    ) -> KrillResult<()> {
        let handle = ta_handle();

        let ta_signer_store = self.ta_signer_store.as_ref().ok_or_else(|| {
            Error::custom("ta_signer_enabled must be true in config")
        })?;

        if ta_signer_store.has(&handle)? {
            return Err(Error::TaAlreadyInitialized)
        }

        // Create Signer
        let repo_contact = self.ta_proxy_repository_contact()?;
        let proxy_id = self.ta_proxy_id()?;

        let details = TrustAnchorSignerInitCommandDetails {
            proxy_id,
            repo_info: repo_contact.repo_info,
            tal_https,
            tal_rsync,
            private_key_pem,
            ta_mft_nr_override: None,
            timing: self.config.ta_timing,
            signer: self.signer.clone(),
        };
        let cmd = TrustAnchorSignerInitCommand::new(
            handle,
            details,
            &self.system_actor,
        );

        ta_signer_store.add(cmd)?;

        Ok(())
    }

    /// Returns the ID certificate used by the TA proxy.
    pub fn ta_proxy_id(&self) -> KrillResult<IdCertInfo> {
        self.get_trust_anchor_proxy().map(|proxy| proxy.id().clone())
    }

    /// Returns the publisher request for the TA proxy.
    ///
    /// Returns an error if the proxy is not initialised.
    pub fn ta_proxy_publisher_request(
        &self,
    ) -> KrillResult<PublisherRequest> {
        self.get_trust_anchor_proxy().map(|proxy| proxy.publisher_request())
    }

    /// Adds a repository to Trust Anchor proxy.
    ///
    /// Returns an error if the proxy is not enabled or already has a
    /// repository.
    pub fn ta_proxy_repository_update(
        &self,
        contact: RepositoryContact,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::add_repo(
                &ta_handle(),
                contact,
                actor,
            )
        )?;
        Ok(())
    }

    /// Returns the repository contact for the proxy.
    ///
    /// Returns an error if there is no proxy, or no repository configured for
    /// it.
    pub fn ta_proxy_repository_contact(
        &self,
    ) -> KrillResult<RepositoryContact> {
        self.get_trust_anchor_proxy()?.repository().cloned().ok_or(
            Error::TaProxyHasNoRepository
        )
    }

    /// Adds the associated signer to the proxy.
    ///
    /// Errors if there is no proxy or the proxy already has a signer.
    pub fn ta_proxy_signer_add(
        &self,
        info: TrustAnchorSignerInfo,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::add_signer(&ta_handle(), info, actor)
        )?;
        Ok(())
    }

    /// Updates the associated signer to the proxy.
    ///
    /// Errors if there is no proxy or the proxy has no or a different signer
    pub fn ta_proxy_signer_update(
        &self,
        info: TrustAnchorSignerInfo,
        actor: &Actor,
    ) -> KrillResult<()> {            
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::update_signer(&ta_handle(), info, actor)
        )?;
        Ok(())
    }

    /// Creates a new request for the signer.
    ///
    /// Errors if there is no proxy or the proxy already has a request.
    pub fn ta_proxy_signer_make_request(
        &self,
        actor: &Actor,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::make_signer_request(&ta_handle(), actor)
        )?.get_signer_request(self.config.ta_timing, &self.signer)
    }

    /// Returns the current request for the signer.
    pub fn ta_proxy_signer_get_request(
        &self,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        self.get_trust_anchor_proxy()?.get_signer_request(
            self.config.ta_timing, &self.signer
        )
    }

    /// Processes a sign response from the signer.
    pub fn ta_proxy_signer_process_response(
        &self,
        response: TrustAnchorSignedResponse,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::process_signer_response(
                &ta_handle(),
                response,
                actor,
            )
        )?;
        Ok(())
    }

    /// Initializes an embedded trust anchor with all resources.
    pub async fn ta_init_fully_embedded(
        &self,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,
        ta_key_pem: Option<String>,
        repo_manager: &Arc<RepositoryManager>,
        actor: &Actor,
    ) -> KrillResult<()> {
        let ta_handle = ta_handle();

        // Initialise proxy
        self.ta_proxy_init()?;

        // Add repository
        let pub_req = self.ta_proxy_publisher_request()?;

        // Create publisher
        repo_manager.create_publisher(pub_req, actor)?;
        let repository_response =
            repo_manager.repository_response(&ta_handle.convert())?;

        // Add repository to proxy
        let contact = RepositoryContact::try_from_response(
            repository_response
        ).map_err(Error::rfc8183)?;
        self.ta_proxy_repository_update(contact, &self.system_actor)?;

        // Initialise signer
        self.ta_signer_init(ta_uris, ta_aia, ta_key_pem)?;

        // Add signer to proxy
        let signer_info = self.get_trust_anchor_signer()?.get_signer_info();
        self.ta_proxy_signer_add(signer_info, &self.system_actor)?;

        self.sync_ta_proxy_signer_if_possible()?;
        self.cas_repo_sync_single(repo_manager, &ta_handle, 0).await?;

        Ok(())
    }

    /// Renews the embedded testbed TA;
    pub fn ta_renew_testbed_ta(&self) -> KrillResult<()> {
        if self.testbed_enabled() {
            let proxy = self.get_trust_anchor_proxy()?;
            if !proxy.has_open_request() {
                info!("Renew the testbed TA");
                self.sync_ta_proxy_signer_if_possible()?;
            }
        }
        Ok(())
    }
}

/// # CA instances and identity
///
impl CaManager {
    /// Initializes a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(&self, handle: CaHandle) -> KrillResult<()> {
        if handle == ta_handle() || handle.as_str() == "version" {
            return Err(Error::TaNameReserved)
        }
        if self.ca_store.has(&handle)? {
            return Err(Error::CaDuplicate(handle))
        }

        // Initialize the CA in self.ca_store, but note that there is no
        // need to create a new CA entry in
        // self.ca_objects_store or self.status_store, because they will
        // generate empty default entries if needed.
        self.ca_store.add(
            CertAuthInitCommand::new(
                handle,
                CertAuthInitCommandDetails { signer: self.signer.clone() },
                &self.system_actor,
            )
        )?;
        Ok(())
    }

    /// Updates the self-signed ID certificate for a CA.
    ///
    /// Use this with care as RFC 8183 only talks about initial ID exchanges
    /// in the form of XML files. It does not talk about updating identity
    /// certificates and keys. Krill supports that a new ID key pair and
    /// certificate is generated, and has functions to update this for a
    /// parent, a child, a repo and a publisher, but other implementations
    /// may not support that identities are updated after initialization.
    pub fn ca_update_id(
        &self,
        handle: CaHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            handle.clone(), actor,
            CertAuthCommandDetails::GenerateNewIdKey(
                self.signer.clone(),
            )
        )?;
        Ok(())
    }

    /// Returns all known CA handles.
    pub fn ca_handles(&self) -> KrillResult<Vec<CaHandle>> {
        Ok(self.ca_store.list()?)
    }

    /// Returns the CAs that the given policy allows read access to.
    //
    //  XXX This should probably not live here but in krillserver.
    pub fn ca_list(
        &self, auth: &AuthInfo,
    ) -> KrillResult<CertAuthList> {
        Ok(CertAuthList {
            cas: self.ca_store
                .list()?
                .into_iter()
                .filter(|handle| {
                    auth.check_permission(
                        Permission::CaRead, Some(handle)
                    ).is_ok()
                })
                .map(|handle| CertAuthSummary { handle })
                .collect(),
        })
    }

    /// Returns the CA by the given handle.
    ///
    /// Returns an error if the CA does not exist.
    pub fn get_ca(&self, handle: &CaHandle) -> KrillResult<Arc<CertAuth>> {
        self.ca_store.get_latest(handle).map_err(|_| {
            Error::CaUnknown(handle.clone())
        })
    }

    /// Returns whether a CA by the given handle exists.
    pub fn has_ca(&self, handle: &CaHandle) -> KrillResult<bool> {
        self.ca_store
            .has(handle)
            .map_err(Error::AggregateStoreError)
    }

    /// Returns the status of the given CA.
    pub fn get_ca_status(
        &self, ca: &CaHandle
    ) -> KrillResult<CaStatus> {
        if self.has_ca(ca)? {
            Ok(self.status_store.get_ca_status(ca))
        }
        else {
            Err(Error::CaUnknown(ca.clone()))
        }
    }

    /// Returns the repository status of the given CA.
    pub fn get_repo_status(
        &self,
        ca: &CaHandle
    ) -> KrillResult<RepoStatus> {
        Ok(self.get_ca_status(ca)?.repo().clone())
    }

    /// Returns the parent statuses of the given CA.
    pub fn get_parent_statuses(
        &self,
        ca: &CaHandle
    ) -> KrillResult<ParentStatuses> {
        Ok(self.get_ca_status(ca)?.parents().clone())
    }

    /// Returns the issues detected for the given CA.
    pub fn get_ca_issues(
        &self, ca: &CaHandle
    ) -> KrillResult<CertAuthIssues> {
        let ca_status = self.get_ca_status(ca)?;
        let mut issues = CertAuthIssues::default();

        if let Some(error) = ca_status.repo().opt_failure() {
            issues.repo_issue = Some(error)
        }

        for (parent, status) in ca_status.parents().iter() {
            if let Some(error) = status.opt_failure() {
                issues.add_parent_issue(parent.clone(), error)
            }
        }

        Ok(issues)
    }

    /// Deletes a CA.
    ///
    /// Does best effort revocation requests and withdraws all its objects
    /// first. Note that any children of this CA will be left orphaned, and
    /// they will only learn of this sad fact when they choose to call home.
    pub async fn delete_ca(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        warn!("Deleting CA '{}' as requested by: {}", ca_handle, actor);

        let ca = self.get_ca(ca_handle)?;

        // Request revocations from all parents - best effort
        info!(
            "Will try to request revocations from all parents CA '{}' \
             before removing it.",
            ca_handle
        );
        for parent in ca.parents() {
            if let Err(e) = self.ca_parent_revoke(ca_handle, parent).await {
                warn!(
                    "Removing CA '{}', but could not send revoke request \
                     to parent '{}': {}",
                    ca_handle, parent, e
                );
            }
        }

        // Clean all repos - again best effort
        info!(
            "Will try to clean up all repositories for CA '{}' before \
             removing it.",
            ca_handle
        );

        // XXX This is quite wasteful. Maybe have a dedicated method to
        //     collect the repository contacts?
        let mut repos: Vec<_> = self.ca_repo_elements(
            ca_handle
        )?.into_keys().collect();

        for deprecated in self.ca_deprecated_repos(ca_handle)? {
            repos.push(deprecated.into_contact());
        }

        for repo_contact in repos {
            if self.ca_repo_sync(
                    repo_manager,
                    ca_handle,
                    ca.id_cert(),
                    &repo_contact,
                    vec![],
            ).await.is_err() {
                info!(
                    "Could not clean up deprecated repository. This is \
                     fine - objects there are no longer referenced."
                );
            }
        }

        self.ca_store.drop_aggregate(ca_handle)?;
        self.ca_objects_store.remove_ca(ca_handle)?;
        self.status_store.remove_ca(ca_handle)?;

        Ok(())
    }
}

/// # CA History
impl CaManager {
    /// Returns the history for a CA.
    pub fn ca_history(
        &self,
        handle: &CaHandle,
        crit: CommandHistoryCriteria,
    ) -> KrillResult<CommandHistory> {
        Ok(self.ca_store.command_history(handle, crit)?)
    }

    /// Returns the details for a CA command.
    pub fn ca_command_details(
        &self,
        handle: &CaHandle,
        version: u64,
    ) -> KrillResult<CommandDetails> {
        self.ca_store.get_command(handle, version).map(|cmd| {
            cmd.to_history_details()
        }).map_err(Error::AggregateStoreError)
    }
}

/// # CAs as parents
impl CaManager {
    /// Adds a child under a CA.
    ///
    /// Returns the response to be sent back to the child.
    ///
    /// If the add child request contains resources not held by this CA,
    /// an error is returned.
    pub fn ca_add_child(
        &self,
        ca: &CaHandle,
        req: AddChildRequest,
        service_uri: &uri::Https,
        actor: &Actor,
    ) -> KrillResult<ParentResponse> {
        info!("CA '{}' process add child request: {}", &ca, &req);
        if ca.as_str() != TA_NAME {
            self.process_ca_command(ca.clone(), actor,
                CertAuthCommandDetails::ChildAdd(
                    req.handle.clone(),
                    req.id_cert.into(),
                    req.resources
                )
            )?;
            self.ca_parent_response(ca, req.handle, service_uri)
        }
        else {
            let child_handle = req.handle.clone();
            let add_child_cmd =
                TrustAnchorProxyCommand::add_child(ca, req, actor);
            self.send_ta_proxy_command(add_child_cmd)?;
            self.ca_parent_response(ca, child_handle, service_uri)
        }
    }

    /// Returns details for a child under the CA.
    pub fn ca_show_child(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<ChildCaInfo> {
        trace!("Finding details for CA: {} under parent: {}", child, ca);
        self.get_ca(ca)?.get_child(child).map(|details| details.to_info())
    }

    /// Exports a child.
    ///
    /// Returns all information to import the child again elsewhere.
    ///
    /// Fails if:
    /// * the child does not exist,
    /// * the child has no received certificate, or
    /// * the child has more than one received certificate or resource class
    ///
    /// This is primarily meant for testing that the child import function
    /// works.
    pub fn ca_child_export(
        &self,
        ca: &CaHandle,
        child_handle: &ChildHandle,
    ) -> KrillResult<ImportChild> {
        trace!("Exporting CA: {} under parent: {}", child_handle, ca);
        self.get_ca(ca)?.child_export(child_handle)
    }

    /// Imports a child under the given CA.
    ///
    /// Fails if:
    /// * the ca does not exist,
    /// * the ca has less than, or more than one resource class,
    /// * the ca does not hold the resources for the child, or
    /// * the child already exists
    pub fn ca_child_import(
        &self,
        ca: &CaHandle,
        import_child: ImportChild,
        actor: &Actor,
    ) -> KrillResult<()> {
        trace!("Importing CA: {} under parent: {}", import_child.name, ca);
        self.process_ca_command(ca.clone(), actor,
            CertAuthCommandDetails::ChildImport(
                import_child,
                self.config.clone(),
                self.signer.clone(),
            )
        )?;
        Ok(())
    }

    /// Returns the contact information for a child.
    pub fn ca_parent_contact(
        &self,
        ca_handle: &CaHandle,
        child_handle: ChildHandle,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentCaContact> {
        let service_uri = Self::service_uri_for_ca(service_uri, ca_handle);
        let ca = self.get_ca(ca_handle)?;

        let server_info = ParentServerInfo {
            service_uri,
            parent_handle: ca_handle.convert(),
            child_handle,
            id_cert: ca.id_cert().clone(),
        };
        Ok(ParentCaContact::Rfc6492(server_info))
    }

    /// Returns an RFC8183 Parent Response for the child.
    pub fn ca_parent_response(
        &self,
        ca_handle: &CaHandle,
        child_handle: ChildHandle,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentResponse> {
        let service_uri = Self::service_uri_for_ca(service_uri, ca_handle);
        let id_cert: publication::Base64 = if ca_handle.as_str() != TA_NAME {
            let ca = self.get_ca(ca_handle)?;
            ca.get_child(&child_handle)?; // ensure the child is known
            ca.id_cert().base64.clone()
        } else {
            let proxy = self.get_trust_anchor_proxy()?;
            proxy.get_child(&child_handle)?;
            proxy.id().base64.clone()
        };

        Ok(ParentResponse::new(
            id_cert,
            ca_handle.convert(),
            child_handle,
            service_uri,
            None,
        ))
    }

    /// Returns the service URI for the CA at a given base URI.
    fn service_uri_for_ca(
        base_uri: &uri::Https,
        ca_handle: &CaHandle,
    ) -> ServiceUri {
        let service_uri = format!("{}rfc6492/{}", base_uri, ca_handle);
        let service_uri = uri::Https::from_string(service_uri).unwrap();
        ServiceUri::Https(service_uri)
    }

    /// Updates a child under this CA.
    ///
    /// The submitted update child request can contain a new ID certificate
    /// or resource set, or both. When resources are updated, the existing
    /// resource entitlements are replaced by the new value - i.e. this is
    /// not a delta and it affects all resource types (IPv4, IPV6, ASN).
    /// Setting resource entitlements beyond the resources held by the parent
    /// CA will return an error.
    pub fn ca_child_update(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        if let Some(id) = req.id_cert {
            self.process_ca_command(ca.clone(), actor,
                CertAuthCommandDetails::ChildUpdateId(
                    child.clone(),
                    id.into(),
                )
            )?;
        }
        if let Some(resources) = req.resources {
            self.process_ca_command(ca.clone(), actor,
                CertAuthCommandDetails::ChildUpdateResources(
                    child.clone(),
                    resources,
                ),
            )?;
        }
        if let Some(suspend) = req.suspend {
            if suspend {
                self.process_ca_command(
                    ca.clone(), actor,
                    CertAuthCommandDetails::ChildSuspendInactive(
                        child.clone()
                    )
                )?;
            } else {
                self.process_ca_command(
                    ca.clone(), actor,
                    CertAuthCommandDetails::ChildUnsuspend(
                        child.clone(),
                    )
                )?;
            }
        }
        if let Some(mapping) = req.resource_class_name_mapping {
            self.process_ca_command(ca.clone(), actor,
                CertAuthCommandDetails::ChildUpdateResourceClassNameMapping(
                    child, mapping,
                )
            )?;
        }
        Ok(())
    }

    /// Removes a child from this CA.
    ///
    /// This will also ensure that certificates issued to the child are
    /// revoked and withdrawn.
    pub fn ca_child_remove(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.status_store.remove_child(ca, &child)?;
        self.process_ca_command(ca.clone(), actor,
            CertAuthCommandDetails::ChildRemove(child)
        )?;
        Ok(())
    }

    /// Processes an provisioning protocol request sent by a child CA.
    ///
    /// Parses, validates, and processes the request and creates, signs, and
    /// returns a response to be sent back to the client.
    pub fn rfc6492(
        &self,
        ca_handle: &CaHandle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        if ca_handle.as_str() == TA_NAME {
            return Err(Error::custom(
                "Remote RFC 6492 to TA is not supported",
            ));
        }

        let ca = self.get_ca(ca_handle)?;

        let req_msg = self.rfc6492_validate_request(&ca, &msg_bytes)?;

        // Create a logger for CMS (avoid cloning recipient)
        let cms_logger = CmsLogger::for_rfc6492_rcvd(
            self.config.rfc6492_log_dir.as_ref(),
            req_msg.recipient(),
            req_msg.sender(),
        );

        match self.rfc6492_process_request(
            ca_handle, req_msg, user_agent, actor
        ) {
            Ok(msg) => {
                let should_log_cms = !msg.is_list_response();
                let reply_bytes = ca.sign_rfc6492_response(
                    msg, &self.signer
                )?;

                if should_log_cms {
                    cms_logger.received(&msg_bytes)?;
                    cms_logger.reply(&reply_bytes)?;
                }

                Ok(reply_bytes)
            }
            Err(e) => {
                cms_logger.received(&msg_bytes)?;
                cms_logger.err(&e)?;

                Err(e)
            }
        }
    }

    /// Processes a provisioning request and returns an unsigned response.
    fn rfc6492_process_request(
        &self,
        ca_handle: &CaHandle,
        req_msg: provisioning::Message,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<provisioning::Message> {
        let (sender, _recipient, payload) = req_msg.unpack();

        let child_handle = sender.convert();

        // If the child was suspended, because it was inactive, then we can
        // now conclude that it's become active again. So unsuspend it
        // first, before processing the request further.
        //
        // The TA will never suspend children, and does not support it.
        if ca_handle.as_str() != TA_NAME {
            let ca = self.get_ca(ca_handle)?;

            let child_ca = ca.get_child(&child_handle)?;
            if child_ca.state.is_suspended() {
                info!(
                    "Child '{}' under CA '{}' became active again, \
                     will unsuspend it.",
                    child_handle,
                    ca.handle()
                );
                self.ca_child_update(
                    ca.handle(),
                    child_handle.clone(),
                    UpdateChildRequest::unsuspend(),
                    actor,
                )?;
            }
        }

        let res_msg = match payload {
            provisioning::Payload::Revoke(req) => {
                self.rfc6492_revoke(
                    ca_handle, child_handle.clone(), req, actor
                )
            }
            provisioning::Payload::List => {
                self.rfc6492_list(ca_handle, &child_handle)
            }
            provisioning::Payload::Issue(req) => {
                self.rfc6492_issue(
                    ca_handle, child_handle.clone(), req, actor
                )
            }
            _ => Err(Error::custom("Unsupported RFC6492 message")),
        };

        // Set child status
        match &res_msg {
            Ok(_) => {
                self.status_store.set_child_success(
                    ca_handle,
                    &child_handle,
                    user_agent,
                )?;
            }
            Err(e) => {
                self.status_store.set_child_failure(
                    ca_handle,
                    &child_handle,
                    user_agent,
                    e,
                )?;
            }
        }

        res_msg
    }

    /// Unpacks and validates a provisioning protocol request.
    fn rfc6492_validate_request(
        &self,
        ca: &CertAuth,
        msg_bytes: &Bytes,
    ) -> KrillResult<provisioning::Message> {
        match ProvisioningCms::decode(msg_bytes.as_ref()) {
            Ok(msg) => ca.verify_rfc6492(msg),
            Err(e) => Err(Error::custom(format!(
                "Could not decode RFC6492 message for: {}, err: {}",
                ca.handle(),
                e
            ))),
        }
    }

    /// Processes a provisioning protocol list request.
    ///
    /// Returns a response listing the entitlements for the child.
    fn rfc6492_list(
        &self,
        ca_handle: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<provisioning::Message> {
        let list_response = if ca_handle.as_str() != TA_NAME {
            self.get_ca(ca_handle)?.list(child, &self.config.issuance_timing)
        }
        else {
            self.get_trust_anchor_proxy()?.entitlements(
                child, &self.config.ta_timing
            ).map(|entitlements| {
                ResourceClassListResponse::new(vec![entitlements])
            })
        }?;

        Ok(provisioning::Message::list_response(
            ca_handle.convert(),
            child.convert(),
            list_response,
        ))
    }

    /// Processes a provisioning protocol issuance request.
    ///
    /// Issues a certificate and returns an unsigned response message.
    fn rfc6492_issue(
        &self,
        ca_handle: &CaHandle,
        child_handle: ChildHandle,
        issue_req: IssuanceRequest,
        actor: &Actor,
    ) -> KrillResult<provisioning::Message> {
        if ca_handle.as_str() == TA_NAME {
            let request = ProvisioningRequest::Issuance(issue_req);
            self.ta_slow_rfc6492_request(
                ca_handle,
                child_handle,
                request,
                actor,
            )
        }
        else {
            let child_rcn = issue_req.class_name();
            let pub_key = issue_req.csr().public_key();

            let ca = self.process_ca_command(
                ca_handle.clone(), actor,
                CertAuthCommandDetails::ChildCertify(
                    child_handle.clone(),
                    issue_req.clone(),
                    self.config.clone(),
                    self.signer.clone(),
                )
            )?;

            // The updated CA will now include the newly issued certificate.
            let child = ca.get_child(&child_handle)?;
            let my_rcn = child.parent_name_for_rcn(child_rcn);

            let response = ca.issuance_response(
                &child_handle,
                &my_rcn,
                pub_key,
                &self.config.issuance_timing,
            )?;

            Ok(provisioning::Message::issue_response(
                ca_handle.convert(),
                child_handle.into_converted(),
                response,
            ))
        }
    }

    /// Processes a provisioning protocol revocation request.
    fn rfc6492_revoke(
        &self,
        ca_handle: &CaHandle,
        child: ChildHandle,
        revoke_request: RevocationRequest,
        actor: &Actor,
    ) -> KrillResult<provisioning::Message> {
        if ca_handle.as_str() == TA_NAME {
            let request = ProvisioningRequest::Revocation(revoke_request);
            self.ta_slow_rfc6492_request(ca_handle, child, request, actor)
        }
        else {
            let res = RevocationResponse::from(&revoke_request);
            let msg = provisioning::Message::revoke_response(
                ca_handle.convert(),
                child.convert(),
                res,
            );
            self.process_ca_command(ca_handle.clone(), actor,
                CertAuthCommandDetails::ChildRevokeKey(child, revoke_request)
            )?;
            Ok(msg)
        }
    }

    /// Processes a 'slow' provisioning protocol request to the TA.
    ///
    /// Because processing will require the TA signer, processing may be
    /// delayed and the correct error response returned.
    fn ta_slow_rfc6492_request(
        &self,
        ta_handle: &CaHandle,
        child: ChildHandle,
        request: ProvisioningRequest,
        actor: &Actor,
    ) -> KrillResult<provisioning::Message> {
        let proxy = self.get_trust_anchor_proxy()?;
        if let Some(response) = proxy.response_for_child(&child, &request)? {
            // Great, we have a pending response. We can give the response to
            // the child and remove it from the proxy.
            let response = response.clone().to_provisioning_message(
                ta_handle.convert(),
                child.convert(),
            );

            self.send_ta_proxy_command(
                TrustAnchorProxyCommand::give_child_response(
                    ta_handle,
                    child,
                    request.key_identifier(),
                    actor,
                )
            )?;

            Ok(response)
        }
        else if proxy.matching_open_request(&child, &request)? {
            // Already scheduled. This should not happen with Krill children
            // but return 1101 just in case.
            provisioning::Message::not_performed_response(
                ta_handle.convert(),
                child.convert(),
                provisioning::NotPerformedResponse::err_1101(),
            )
            .map_err(|_| {
                Error::custom(
                    "creation of not performed response should never fail",
                )
            })
        }
        else {
            // We will need schedule this one and return a 1104 not performed
            // response
            self.send_ta_proxy_command(
                TrustAnchorProxyCommand::add_child_request(
                    ta_handle,
                    child.clone(),
                    request,
                    actor,
                )
            )?;

            provisioning::Message::not_performed_response(
                ta_handle.convert(),
                child.into_converted(),
                provisioning::NotPerformedResponse::err_1104(),
            )
            .map_err(|_| {
                Error::custom(
                    "creation of not performed response should never fail",
                )
            })
        }
    }
}

/// # CAs as children
///
impl CaManager {
    /// Adds a new parent, or updates an existing parent of a CA.
    ///
    /// Adding a parent will trigger that the CA connects to this new parent
    /// in order to learn its resource entitlements and set up the resource
    /// class(es) under it, and request certificate(s).
    pub fn ca_parent_add_or_update(
        &self,
        handle: CaHandle,
        parent_req: ParentCaReq,
        actor: &Actor,
    ) -> KrillResult<()> {
        let ca = self.get_ca(&handle)?;

        let contact = ParentCaContact::try_from_rfc8183_parent_response(
            parent_req.response
        ).map_err(|e| {
            Error::CaParentResponseInvalid(handle.clone(), e.to_string())
        })?;

        let cmd = if !ca.has_parent(&parent_req.handle) {
            CertAuthCommandDetails::AddParent(
                parent_req.handle, contact,
            )
        } else {
            CertAuthCommandDetails::UpdateParentContact(
                parent_req.handle, contact,
            )
        };
        self.process_ca_command(handle.clone(), actor, cmd)?;
        Ok(())
    }

    /// Removes a parent from a CA.
    ///
    /// This will trigger that best effort revocations of existing keys under
    /// this parent are requested. Any resource classes under the parent will
    /// be removed and all relevant content will be withdrawn from the
    /// repository.
    pub async fn ca_parent_remove(
        &self,
        handle: CaHandle,
        parent: ParentHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        // Best effort, request revocations for any remaining keys under this
        // parent.
        if let Err(e) = self.ca_parent_revoke(&handle, &parent).await {
            warn!(
                "Removing parent '{}' from CA '{}', but could not send \
                 revoke requests: {}",
                parent, handle, e
            );
        }

        self.status_store.remove_parent(&handle, &parent)?;
        self.process_ca_command(
            handle.clone(), actor,
            CertAuthCommandDetails::RemoveParent(parent),
        )?;
        Ok(())
    }

    /// Sends revocation requests for a parent of a CA.
    async fn ca_parent_revoke(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
    ) -> KrillResult<()> {
        let ca = self.get_ca(handle)?;
        let revoke_requests = ca.revoke_under_parent(parent, &self.signer)?;
        self.send_revoke_requests(handle, parent, revoke_requests)
            .await?;
        Ok(())
    }

    /// Schedules refreshing all CAs as soon as possible:
    ///
    /// Note: this function can be called manually through the API, but
    /// normally the CA refresh process is replanned on the task
    /// queue automatically.
    pub fn cas_schedule_refresh_all(&self) -> KrillResult<()> {
        if let Ok(cas) = self.ca_store.list() {
            for ca_handle in cas {
                self.cas_schedule_refresh_single(ca_handle)?;
            }
        }
        Ok(())
    }

    /// Refresh a single CA with its parents.
    ///
    /// This possibly also suspend inactive children.
    pub fn cas_schedule_refresh_single(
        &self,
        ca_handle: CaHandle,
    ) -> KrillResult<()> {
        self.ca_schedule_sync_parents(&ca_handle)
    }

    /// Schedules an immediate check suspending all inactive children.
    ///
    /// This check will suspend all children of all CAs that have not been
    /// contacting the CA for a certain time if suspension is enabled.
    ///
    /// While this function can be called manually through the API, it is
    /// normally replanned on the task queue automatically if suspension is
    /// enabled.
    pub fn cas_schedule_suspend_all(&self) -> KrillResult<()> {
        if self.config.suspend_child_after_inactive_seconds().is_some() {
            if let Ok(cas) = self.ca_store.list() {
                for ca in cas {
                    self.tasks.schedule(
                        Task::SuspendChildrenIfNeeded { ca_handle: ca },
                        now(),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Suspends inactive child CAs of the given CA.
    ///
    /// This method is called by the scheduler in response to the scheduled
    /// event.
    //
    //  XXX PANICS
    pub fn ca_suspend_inactive_children(
        &self, ca_handle: &CaHandle, started: Timestamp, actor: &Actor
    ) {
        // Set threshold hours if it was configured AND this server has been
        // started longer ago than the hours specified. Otherwise we
        // risk that *all* children without prior recorded status are
        // suspended on upgrade, or that *all* children are suspended
        // if the server had been down for more than the threshold hours.
        let threshold_seconds =
            self.config.suspend_child_after_inactive_seconds()
            .filter(|secs| started < Timestamp::now_minus_seconds(*secs));

        // suspend inactive children, if so configured
        if let Some(threshold_seconds) = threshold_seconds {
            if let Ok(ca_status) = self.get_ca_status(ca_handle) {
                let connections = ca_status.get_children_connection_stats();

                for child in connections.suspension_candidates(
                    threshold_seconds
                ) {
                    if log::log_enabled!(log::Level::Info) {
                        let threshold_string = if threshold_seconds >= 3600 {
                            format!("{} hours", threshold_seconds / 3600)
                        } else {
                            format!("{} seconds", threshold_seconds)
                        };

                        info!(
                            "Child '{}' under CA '{}' was inactive for more \
                             than {}. Will suspend it.",
                            child, ca_handle, threshold_string
                        );
                    }
                    if let Err(e) =
                        self.status_store.set_child_suspended(
                            ca_handle, &child
                        )
                    {
                        panic!(
                            "System level error encountered while updating \
                             ca status: {e}"
                        );
                    }

                    let req = UpdateChildRequest::suspend();
                    if let Err(e) = self.ca_child_update(
                        ca_handle, child, req, actor
                    ) {
                        error!(
                            "Could not suspend inactive child, error: {}",
                            e
                        );
                    }
                }
            }
        }
    }

    /// Synchronizes a CA with its parents up to the configured batch size.
    ///
    /// The remaining parents will be done in a future run.
    fn ca_schedule_sync_parents(
        &self,
        ca_handle: &CaHandle,
    ) -> KrillResult<()> {
        let Ok(ca) = self.get_ca(ca_handle) else {
            return Ok(())
        };

        if ca.nr_parents() <= self.config.ca_refresh_parents_batch_size {
            // Nr of parents is below batch size, so just process all
            // of them
            for parent in ca.parents() {
                self.tasks.schedule(
                    Task::SyncParent {
                        ca_handle: ca_handle.clone(),
                        ca_version: 0,
                        parent: parent.clone(),
                    },
                    now(),
                )?;
            }
        }
        else {
            // more parents than the batch size exist, so get
            // candidates based on
            // the known parent statuses for this CA.
            let status = self.status_store.get_ca_status(ca_handle);

            for parent in status.parents().sync_candidates(
                ca.parents().collect(),
                self.config.ca_refresh_parents_batch_size,
            ) {
                self.tasks.schedule(
                    Task::SyncParent {
                        ca_handle: ca_handle.clone(),
                        ca_version: 0,
                        parent,
                    },
                    now(),
                )?;
            }
        }
        Ok(())
    }

    /// Synchronizes a CA with one of its parents.
    ///
    /// Send pending requests if present; otherwise gets and processes
    /// updated entitlements.
    ///
    /// The `min_ca_version` argument allows syncing only if the CA has
    /// reached this version yet. If it hasn’t, the method returns
    /// `Ok(false)`. To sync in any case, request version 0.
    ///
    /// If a sync has successfully happened, returns `Ok(true)`.
    ///
    /// Note that if new request events are generated as a result of
    /// processing updated entitlements they will trigger that this
    /// synchronization is called again so that the pending requests
    /// can be sent.
    ///
    /// This method is called by the scheduler in response to the scheduled
    /// sync as well as `KrillServer` when importing a CA.
    pub async fn ca_sync_parent(
        &self,
        handle: &CaHandle,
        min_ca_version: u64, // set this 0 if it does not matter
        parent: &ParentHandle,
        actor: &Actor,
    ) -> KrillResult<bool> {
        let ca = self.get_ca(handle)?;

        trace!(
            "CA version: {}, asked to wait until: {}",
            ca.version(), min_ca_version
        );

        if ca.version() < min_ca_version {
            Ok(false)
        }
        else {
            if ca.has_pending_requests(parent) {
                self.send_requests(handle, parent, actor).await?;
            }
            else {
                self.get_updates_from_parent(handle, parent, actor).await?;
            }
            Ok(true)
        }
    }

    /// Synchronizes the TA proxy with a local TA signer.
    ///
    /// If the TA signer is remote, logs a warning suggesting doing a
    /// manual synchronization, assuming that this method is only ever called
    /// if the TA proxy requires synchronization.
    pub fn sync_ta_proxy_signer_if_possible(&self) -> KrillResult<()> {
        let ta_handle = ta_handle();

        if self.get_trust_anchor_proxy().is_err() {
            debug!(
                "Sync TA proxy signer was called without a TA proxy. \
                 This is rather odd ..."
            );
            return Ok(())
        };

        if self.get_trust_anchor_signer().is_err() {
            warn!(
                "There is at least one pending request for the TA signer. \
                 Plan a signing session!"
            );
            return Ok(())
        };

        // Make sign request in proxy.
        let proxy = self.send_ta_proxy_command(
            TrustAnchorProxyCommand::make_signer_request(
                &ta_handle,
                &self.system_actor,
            )
        )?;

        // Get sign request for signer.
        let signed_request = proxy.get_signer_request(
            self.config.ta_timing,
            &self.signer,
        )?;

        // Remember the noce of the request so we can retrieve it.
        let request_nonce = signed_request.content().nonce.clone();

        // Let signer process request.
        let signer = self.send_ta_signer_command(
            TrustAnchorSignerCommand::make_process_request_command(
                &ta_handle,
                signed_request,
                self.config.ta_timing,
                None, // do not override next manifest number
                self.signer.clone(),
                &self.system_actor,
            )
        )?;

        // Get the response from the signer and give it to the proxy.
        let exchange = signer.get_exchange(&request_nonce).unwrap();
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::process_signer_response(
                &ta_handle,
                exchange.clone().response,
                &self.system_actor,
            )
        )?;
        Ok(())
    }

    /// Tries to get updates from a specific parent of a CA.
    ///
    /// Quietly does nothing for the TA CA.
    async fn get_updates_from_parent(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        if handle == &ta_handle() {
            return Ok(())
        }

        let ca = self.get_ca(handle)?;

        // Return an error if the repository was not configured yet.
        ca.repository_contact()?;

        // XXX Any reason we get this twice?
        let ca = self.get_ca(handle)?;
        let parent_contact = ca.parent(parent)?;
        let entitlements = self.get_entitlements_from_contact(
            handle, parent, parent_contact, true,
        ).await?;

        self.update_entitlements(
            handle, parent.clone(), entitlements, actor,
        )?;

        Ok(())
    }

    /// Sends requests to a specific parent for the CA matching handle.
    ///
    /// First sends all open revoke requests, then sends all open
    /// certificate requests.
    async fn send_requests(
        &self, handle: &CaHandle, parent: &ParentHandle, actor: &Actor,
    ) -> KrillResult<()> {
        self.send_revoke_requests_handle_responses(
            handle, parent, actor
        ).await?;
        self.send_cert_requests_handle_responses(
            handle, parent, actor
        ).await
    }

    /// Sends all open revocation requests and handles the responses.
    async fn send_revoke_requests_handle_responses(
        &self, handle: &CaHandle, parent: &ParentHandle, actor: &Actor,
    ) -> KrillResult<()> {
        let child = self.get_ca(handle)?;
        let requests = child.revoke_requests(parent);

        let revoke_responses = self.send_revoke_requests(
            handle, parent, requests
        ).await?;

        for (rcn, revoke_responses) in revoke_responses {
            for response in revoke_responses {
                self.process_ca_command(
                    handle.clone(), actor,
                    CertAuthCommandDetails::KeyRollFinish(
                        rcn.clone(),
                        response,
                    )
                )?;
            }
        }

        Ok(())
    }

    /// Sends the given revoke requests to a parent.
    ///
    /// Returns the responses for the requests.
    pub async fn send_revoke_requests(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let child = self.get_ca(handle)?;
        let server_info = child.parent(parent)?.parent_server_info();

        match self.send_revoke_requests_rfc6492(
            revoke_requests,
            &child.id_cert().public_key.key_identifier(),
            server_info,
        ) .await {
            Err(e) => {
                self.status_store.set_parent_failure(
                    handle, parent, &server_info.service_uri, &e
                )?;
                Err(e)
            }
            Ok(res) => {
                self.status_store.set_parent_last_updated(
                    handle, parent, &server_info.service_uri
                )?;
                Ok(res)
            }
        }
    }

    /// Sends a revoke request for an unexpected key.
    pub async fn send_revoke_unexpected_key(
        &self,
        handle: &CaHandle,
        rcn: ResourceClassName,
        revocation: RevocationRequest,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>>
    {
        let child = self.ca_store.get_latest(handle)?;
        let parent = child.parent_for_rc(&rcn)?;
        let mut requests = HashMap::new();
        requests.insert(rcn, vec![revocation]);

        self.send_revoke_requests(handle, parent, requests).await
    }

    /// Sends revoke requests using the provisioning protocol.
    async fn send_revoke_requests_rfc6492(
        &self,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        signing_key: &KeyIdentifier,
        server_info: &ParentServerInfo,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let mut revoke_map = HashMap::new();

        for (rcn, revoke_requests) in revoke_requests {
            let mut revocations = Vec::new();
            for req in revoke_requests {
                let sender = server_info.child_handle.convert();
                let recipient = server_info.parent_handle.convert();

                let revoke = provisioning::Message::revoke(
                    sender, recipient, req.clone(),
                );

                let response = self.send_rfc6492_and_validate_response(
                    revoke, server_info, signing_key
                ) .await?;

                let payload = response.into_payload();
                let payload_type = payload.payload_type();

                match payload {
                    provisioning::Payload::RevokeResponse(
                        revoke_response,
                    ) => {
                        revocations.push(revoke_response)
                    }
                    provisioning::Payload::ErrorResponse(e) => {
                        if e.status() == 1101 || e.status() == 1104 {
                            // If we get one of the following responses:
                            //    1101         already processing request
                            //    1104         request scheduled for
                            // processing
                            //
                            // Then we asked the parent, but don't have a
                            // revocation response yet.
                            //
                            // This is okay. There is nothing to do but ask
                            // again later. This should really only happen
                            // for a CA that operates under the *local* Trust
                            // Anchor. The Krill TA uses a 'proxy' part for
                            // online functions, such as talking to children,
                            // and a 'signer' part for signing, which may
                            // happen offline - and much later.
                            //
                            // By not adding any response to the returned hash
                            // we ensure that the old key
                            // remains in use (for a manifest and CRL only)
                            // until we get the revocation response
                            // when we ask later.
                            //
                            // When the local TA 'proxy' receives new signed
                            // responses from the 'signer' then it
                            // will trigger all local children to sync again.
                            // That time, they should see a response.
                        }
                        else if e.status() == 1301 || e.status() == 1302 {
                            // If we get one of the following responses:
                            //    1301         revoke - no such resource class
                            //    1302         revoke - no such key
                            //
                            // Then we can consider this revocation redundant
                            // from the parent side, so just add it
                            // as revoked to this CA and move on. While this
                            // may be unexpected this is unlikely to
                            // be a problem. If we would keep insisting that
                            // the parent revokes a key they already
                            // revoked, then we can end up in a stuck loop.
                            //
                            // More importantly we should re-sync things if we
                            // get 12** errors to certificate sign
                            // requests, but that is done in another function.
                            let revoke_response = (&req).into();
                            revocations.push(revoke_response)
                        }
                        else {
                            return Err(Error::Rfc6492NotPerformed(e));
                        }
                    }
                    _ => {
                        return Err(Error::custom(format!(
                            "Got unexpected response '{}' to revoke query",
                            payload_type
                        )))
                    }
                }
            }

            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
    }

    /// Sends certification requests to a parent CA and proceses the response.
    async fn send_cert_requests_handle_responses(
        &self, ca_handle: &CaHandle, parent: &ParentHandle, actor: &Actor,
    ) -> KrillResult<()> {
        let ca = self.get_ca(ca_handle)?;
        let requests = ca.cert_requests(parent);
        let signing_key = ca.id_cert().public_key.key_identifier();
        let server_info = ca.parent(parent)?.parent_server_info();

        // We may need to do work for multiple resource class and there may
        // therefore be multiple errors. We want to keep track of
        // those, rather than bailing out on the first error, because
        // an issue in one resource class does not necessarily mean
        // that there should be an issue in the the others.
        //
        // Of course for most CAs there will only be one resource class under
        // a parent, but we need to be prepared to deal with N
        // classes.
        let mut errors = vec![];

        for (rcn, requests) in requests {
            // We could have multiple requests in a single resource class
            // (multiple keys during rollover)
            for req in requests {
                let sender = server_info.child_handle.convert();
                let recipient = server_info.parent_handle.convert();

                match self.send_rfc6492_and_validate_response(
                    provisioning::Message::issue(
                        sender, recipient, req
                    ),
                    server_info,
                    &signing_key,
                ).await {
                    Err(e) => {
                        // If any of the requests for an RC results in an
                        // error, then record the
                        // error and break the loop. We will sync again.
                        errors.push(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            e.to_string(),
                        ));
                        break;
                    }
                    Ok(response) => {
                        if let Err(err) = self.handle_cert_response(
                            ca_handle, parent, &rcn, actor, response
                        ) {
                            errors.push(err);
                            break;
                        }
                    }
                }
            }
        }

        let uri = &server_info.service_uri;
        if errors.is_empty() {
            self.status_store
                .set_parent_last_updated(ca_handle, parent, uri)?;

            Ok(())
        } else {
            let e = if errors.len() == 1 {
                errors.pop().unwrap()
            } else {
                Error::Multiple(errors)
            };

            self.status_store
                .set_parent_failure(ca_handle, parent, uri, &e)?;

            Err(e)
        }
    }

    /// Processes a response to a certification request.
    fn handle_cert_response(
        &self,
        ca_handle: &CaHandle,
        parent: &ParentHandle,
        rcn: &ResourceClassName,
        actor: &Actor,
        response: provisioning::Message,
    ) -> KrillResult<()> {
        let payload = response.into_payload();
        let payload_type = payload.payload_type();

        match payload {
            provisioning::Payload::IssueResponse(response) => {
                // Update the received certificate.
                //
                // In a typical exchange we will only have one
                // key under an RC under a
                // parent. During a key roll there may be
                // multiple keys and requests. It
                // is still fine to update the received
                // certificate for key "A" even if we
                // would get an error for the request for key
                // "B". The reason is such an
                // *unlikely* failure would still trigger an
                // appropriate response at
                // the resource class level in the next loop
                // iteration below.
                let issued = response.into_issued();
                let (uri, limit, cert) = issued.unpack();

                let resources = match ResourceSet::try_from(&cert) {
                    Ok(resources) => resources,
                    Err(e) => {
                        // Cannot get resources from the
                        // issued certificate. This should
                        // never happen, but it would occur if
                        // the parent gave us a certificate
                        // with 'inherited' resources. This
                        // may be allowed under RFC 6492 –
                        // or rather it's not strictly
                        // disallowed as perhaps it should be?
                        //
                        // In any case, report the error –
                        // but we do not expect that this
                        // will happen in the wild.
                        return Err(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            format!(
                                "cannot parse resources on received \
                                certificate, error: {e}"
                            ),
                        ));
                    }
                };

                let rcvd_cert = match ReceivedCert::create(
                    cert, uri, resources, limit,
                ) {
                    Ok(cert) => cert,
                    Err(e) => {
                        return Err(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            format!(
                                "cannot use issued certificate, \
                                error: {e}"
                            ),
                        ));
                    }
                };

                if let Err(e) = self.process_ca_command(
                    ca_handle.clone(), actor,
                    CertAuthCommandDetails::UpdateRcvdCert(
                        rcn.clone(),
                        rcvd_cert,
                        self.config.clone(),
                        self.signer.clone(),
                    )
                ) {
                    // Note that sending the command to update a received
                    // certificate cannot fail unless there are bigger issues
                    // like this being the wrong response for this resource
                    // class. This would be extremely odd because
                    // we only just asked the resource class which request to
                    // send. Still, in order to handle this the most graceful
                    // way we can, we should just drop this resource class
                    // and report an error. If there are are still resource
                    // entitlements under the parent for this resource class,
                    // then a new class will be automatically created when we
                    // synchronize the entitlements again.

                    let reason = format!(
                        "cannot process received certificate! error: {e}"
                    );

                    self.process_ca_command(
                        ca_handle.clone(), actor,
                        CertAuthCommandDetails::DropResourceClass(
                            rcn.clone(),
                            reason.clone(),
                            self.signer.clone(),
                        )
                    )?;

                    return Err(Error::CaParentSyncError(
                        ca_handle.clone(),
                        parent.clone(),
                        rcn.clone(),
                        reason,
                    ));
                }
            }
            provisioning::Payload::ErrorResponse(
                not_performed,
            ) => {
                match not_performed.status() {
                    1101 | 1104 => {
                        // If we get one of the following
                        // responses:
                        //    1101         already processing request
                        //    1104         request scheduled for processing
                        //
                        // Then we asked the parent, but don't have a signed
                        // certificate yet.
                        //
                        // This is okay, there is nothing to do but ask again
                        // later. This should really only happen for a CA
                        // that operates under the *local* Trust Anchor. The
                        // Krill TA uses a 'proxy' part for online functions, 
                        // such as talking to children, and a 'signer' part
                        // for signing, which may happen offline - and much
                        // later.
                        //
                        // If the local TA 'proxy' receives new signed
                        // responses from the 'signer' then it will trigger
                        // all local children to sync again. That time, they
                        // should see a response.
                    }
                    1201 | 1202 => {
                        // Okay, so it looks like the parent *just* told the
                        // CA that it was entitled to certain resources in a
                        // resource class and now in response to certificate
                        // sign request they say the resource class is gone
                        // (1201), or there are no resources in it (1202).
                        // This can happen as a result of a race condition if
                        // the child CA was asking the entitlements just
                        // moments before the parent removed them.

                        let reason =
                            "parent removed entitlement to resource class";

                        self.process_ca_command(
                            ca_handle.clone(), actor,
                            CertAuthCommandDetails::DropResourceClass(
                                rcn.clone(),
                                reason.to_string(),
                                self.signer.clone(),
                            )
                        )?;

                        // Push the error for reporting, this will also
                        // trigger that the CA will sync with its parent
                        // again - and then it will just find revocation
                        // requests for this RC - which are sent on a best
                        // effort basis
                        return Err(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            reason.to_string(),
                        ));
                    }
                    1204 => {
                        // The parent says that the CA is re-using a key
                        // across RCs. Krill CAs never re-use keys - so this
                        // is extremely unlikely. Still there seems to be a
                        // disagreement and in this case the parent has the
                        // last word. Recovering by dropping all keys in the
                        // RC and making a new pending key should be possible,
                        // but it's complicated with regards to corner cases:
                        // e.g. what if we were in the middle of key roll.
                        //
                        // So, the most straightforward way to deal with this
                        // is by dropping this current RC altogether. Then the
                        // CA will find its resource entitlements in a future
                        // synchronization with the parent and just create a
                        // new RC - and issue all eligible certificates and
                        // ROAs under it.

                        let reason = "parent claims we are re-using keys";
                        self.process_ca_command(
                            ca_handle.clone(), actor,
                            CertAuthCommandDetails::DropResourceClass(
                                rcn.clone(),
                                reason.to_string(),
                                self.signer.clone(),
                            )
                        )?;

                        // Push the error for reporting, this will also
                        // trigger that the CA will sync with its parent
                        // again - and then it will just find revocation
                        // requests for this RC - which are sent on a best
                        // effort basis
                        return Err(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            reason.to_string(),
                        ));
                    }
                    _ => {
                        // Other not performed responses can be due to
                        // temporary issues at the parent (e.g. it had an
                        // internal error of some kind), or because of
                        // protocol version mismatches and such (in future
                        // maybe?).
                        //
                        // In any event we cannot take any action to recover,
                        // so just report them and let the schedular try to
                        // sync with the parent again.
                        let issue = format!(
                            "parent returned not performed response to \
                             certificate request: {not_performed}",
                        );
                        return Err(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            issue,
                        ));
                    }
                }
            }
            _ => {
                let issue = format!(
                    "unexpected response type '{payload_type}' to a \
                     certificate request"
                );
                return Err(Error::CaParentSyncError(
                    ca_handle.clone(),
                    parent.clone(),
                    rcn.clone(),
                    issue,
                ));
            }
        }
        Ok(())
    }

    /// Updates the CA resource classes with new entitlements.
    ///
    /// Returns `Ok(true)` in case there were any updates, implying that
    /// there will be open requests for the parent CA.
    fn update_entitlements(
        &self,
        ca: &CaHandle,
        parent: ParentHandle,
        entitlements: ResourceClassListResponse,
        actor: &Actor,
    ) -> KrillResult<bool> {
        let current_version = self.get_ca(ca)?.version();
        let new_version = self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::UpdateEntitlements(
                parent,
                entitlements,
                self.signer.clone(),
            ),
        )?.version();
        Ok(new_version > current_version)
    }

    /// Requests the entitlements from the parent.
    pub async fn get_entitlements_from_contact(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
        existing_parent: bool,
    ) -> KrillResult<ResourceClassListResponse> {
        let server_info = contact.parent_server_info();
        let uri = &server_info.service_uri;

        let result = self.get_entitlements_rfc6492(ca, server_info).await;

        match &result {
            Err(error) => {
                if existing_parent {
                    // only update the status store with errors for existing
                    // parents otherwise we end up with
                    // entries if a new parent is rejected because
                    // of the error.
                    self.status_store.set_parent_failure(
                        ca, parent, uri, error
                    )?;
                }
            }
            Ok(entitlements) => {
                self.status_store.set_parent_entitlements(
                    ca,
                    parent,
                    uri,
                    entitlements,
                )?;
            }
        }
        result
    }

    /// Performs the provisioning protocol exchange for entitlements.
    async fn get_entitlements_rfc6492(
        &self,
        handle: &CaHandle,
        server_info: &ParentServerInfo,
    ) -> KrillResult<ResourceClassListResponse> {
        debug!(
            "Getting entitlements for CA '{}' from parent '{}'",
            handle,
            server_info.parent_handle
        );

        let child = self.ca_store.get_latest(handle)?;

        // create a list request
        let list = provisioning::Message::list(
            server_info.child_handle.convert(),
            server_info.parent_handle.convert(),
        );

        let response = self.send_rfc6492_and_validate_response(
            list,
            server_info,
            &child.id_cert().public_key.key_identifier(),
        ).await?;

        let payload = response.into_payload();
        let payload_type = payload.payload_type();

        match payload {
            provisioning::Payload::ListResponse(response) => Ok(response),
            provisioning::Payload::ErrorResponse(np) => {
                Err(Error::Custom(format!("Not performed: {}", np)))
            }
            _ => {
                Err(Error::custom(format!(
                    "Got unexpected response type '{}' to list query",
                    payload_type
                )))
            }
        }
    }

    /// Sends a provisioning message and validates the response.
    async fn send_rfc6492_and_validate_response(
        &self,
        message: provisioning::Message,
        server_info: &ParentServerInfo,
        signing_key: &KeyIdentifier,
    ) -> KrillResult<provisioning::Message> {
        let service_uri = &server_info.service_uri;
        if let Some(parent) = Self::local_parent(
            service_uri, &self.config.service_uri()
        ) {
            let ca_handle = parent.into_converted();
            let user_agent = Some("local-child".to_string());

            self.rfc6492_process_request(
                &ca_handle,
                message,
                user_agent,
                &self.system_actor,
            )
        }
        else {
            // Set up a logger for CMS exchanges. Note that this logger is
            // always set up and used, but.. it will only actually
            // save files in case the given rfc6492_log_dir is
            // Some.
            let sender = message.sender().clone();
            let recipient = message.recipient().clone();

            let cms_logger = CmsLogger::for_rfc6492_sent(
                self.config.rfc6492_log_dir.as_ref(),
                &sender,
                &recipient,
            );

            let cms = self.signer.create_rfc6492_cms(
                message, signing_key
            )?.to_bytes();

            let res_bytes = self.post_protocol_cms_binary(
                &cms,
                service_uri,
                provisioning::CONTENT_TYPE,
                &cms_logger,
            ).await?;

            match ProvisioningCms::decode(&res_bytes) {
                Err(e) => {
                    error!(
                        "Could not decode response from parent (handle): \
                         {}, for ca (handle): {}, at URI: {}. Error: {}",
                        recipient, sender, service_uri, e
                    );
                    cms_logger.err(format!("Could not decode CMS: {}", e))?;
                    Err(Error::Rfc6492(e))
                }
                Ok(cms) => {
                    match cms.validate(&server_info.id_cert.public_key)
                    {
                        Ok(()) => Ok(cms.into_message()),
                        Err(e) => {
                            error!(
                                "Could not validate response from parent \
                                (handle): {}, for ca (handle): {}, \
                                at URI: {}. Error: {}",
                                recipient, sender, service_uri, e
                            );
                            cms_logger.err(
                                format!("Response invalid: {}", e)
                            )?;
                            Err(Error::Rfc6492(e))
                        }
                    }
                }
            }
        }
    }

    /// Posts a protocol message via HTTP and receives a response.
    async fn post_protocol_cms_binary(
        &self,
        msg: &Bytes,
        service_uri: &ServiceUri,
        content_type: &str,
        cms_logger: &CmsLogger,
    ) -> KrillResult<Bytes> {
        cms_logger.sent(msg)?;

        let timeout = self.config.post_protocol_msg_timeout_seconds;

        match httpclient::post_binary_with_full_ua(
            service_uri.as_str(),
            msg,
            content_type,
            timeout,
        ).await {
            Err(e) => {
                cms_logger.err(format!(
                    "Error posting CMS to {}: {}", service_uri, e
                ))?;
                Err(Error::HttpClientError(e))
            }
            Ok(bytes) => {
                cms_logger.reply(&bytes)?;
                Ok(bytes)
            }
        }
    }

    /// Returns the handle for the parent if it is local.
    ///
    /// A parent is local if its `service_uri` is under `base_uri` and
    /// follows the format Krill is using.
    pub fn local_parent(
        service_uri: &ServiceUri,
        base_uri: &uri::Https,
    ) -> Option<ParentHandle> {
        match &service_uri {
            ServiceUri::Http(_) => None,
            ServiceUri::Https(service_uri) => {
                let service_uri = service_uri.as_str();
                let base_uri = base_uri.as_str();

                if let Some(path) = service_uri.strip_prefix(base_uri) {
                    if let Some(ca_name) = path.strip_prefix("rfc6492/") {
                        return ParentHandle::from_str(ca_name).ok();
                    }
                }

                None
            }
        }
    }
}

/// # Publishing
///
impl CaManager {
    /// Schedules synchronizing all CAs with their repositories.
    pub fn cas_schedule_repo_sync_all(
        &self, auth: &AuthInfo,
    ) -> KrillResult<()> {
        for ca in &self.ca_list(auth)?.cas {
            self.cas_schedule_repo_sync(ca.handle.clone())?;
        }
        Ok(())
    }

    /// Schedules synchronizing a CA with its repositories.
    pub fn cas_schedule_repo_sync(
        &self,
        ca_handle: CaHandle,
    ) -> KrillResult<()> {
        // no need to wait for an updated CA to be committed. 
        let ca_version = 0;
        self.tasks.schedule(
            Task::SyncRepo {
                ca_handle,
                ca_version,
            },
            now(),
        )
    }

    /// Synchronizes a CA with its repositories.
    ///
    /// Returns `Ok(true)` in case the synchronization was successful,
    /// `Ok(false)` in case it was premature wrt to given CA version, and
    /// an error in case of any issues.
    ///
    /// Note typically a CA will have only one active repository, but in case
    /// there are multiple during a migration, this function will ensure that
    /// they are all synchronized.
    ///
    /// In case the CA had deprecated repositories, then a clean up will be
    /// attempted. I.e. the CA will try to withdraw all objects from the
    /// deprecated repository. If this clean up fails then the number of
    /// clean-up attempts for the repository in question is incremented,
    /// and this function will fail. When there have been 5 failed
    /// attempts, then the old repository is assumed to be unreachable and
    /// it will be dropped - i.e. the CA will no longer try to clean up
    /// objects.
    pub async fn cas_repo_sync_single(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        ca_version: u64,
    ) -> KrillResult<bool> {
        // Note that this is a no-op for new CAs which do not yet have any
        // repository configured.
        if ca_handle.as_str() == TA_NAME {
            let proxy = self.get_trust_anchor_proxy()?;
            if proxy.version() < ca_version {
                Ok(false)
            }
            else {
                let id = proxy.id();
                let repo = proxy.repository().ok_or(
                    Error::TaProxyHasNoRepository
                )?;
                let objects = proxy.get_trust_anchor_objects()?
                                .publish_elements()?;
                self.ca_repo_sync(
                    repo_manager, ca_handle, id, repo, objects
                ).await?;
                Ok(true)
            }
        }
        else if !self.has_ca(ca_handle)? {
            debug!(
                "Dropping task to sync removed CA '{ca_handle}' with \
                its repository."
            );
            Ok(true)
        }
        else {
            let ca = self.get_ca(ca_handle)?;

            if ca.version() < ca_version {
                Ok(false)
            }
            else {
                for (repo_contact, objects) in
                    self.ca_repo_elements(ca_handle)?
                {
                    self.ca_repo_sync(
                        repo_manager,
                        ca_handle,
                        ca.id_cert(),
                        &repo_contact,
                        objects,
                    ).await?;
                }

                // Clean-up of old repos
                for deprecated in self.ca_deprecated_repos(ca_handle)? {
                    info!(
                        "Will try to clean up deprecated repository '{}' \
                        for CA '{}'",
                        deprecated.contact(),
                        ca_handle
                    );

                    if let Err(e) = self.ca_repo_sync(
                        repo_manager,
                        ca_handle,
                        ca.id_cert(),
                        deprecated.contact(),
                        vec![],
                    ).await {
                        warn!(
                            "Could not clean up deprecated repository: {}",
                            e
                        );

                        if deprecated.clean_attempts() < 5 {
                            self.ca_deprecated_repo_increment_clean_attempts(
                                ca_handle,
                                deprecated.contact(),
                            )?;
                            return Err(e);
                        }
                    }

                    self.ca_deprecated_repo_remove(
                        ca_handle,
                        deprecated.contact(),
                    )?;
                }

                Ok(true)
            }
        }
    }

    /// Synchronizes with the repository.
    async fn ca_repo_sync(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        id_cert: &IdCertInfo,
        repo_contact: &RepositoryContact,
        publish_elements: Vec<PublishedFile>,
    ) -> KrillResult<()> {
        debug!("CA '{}' sends list query to repo", ca_handle);
        let list_reply = self.send_rfc8181_list(
            repo_manager,
            ca_handle,
            id_cert,
            &repo_contact.server_info,
        ).await?;

        // XXX Do we really need hash maps here? In particular, this will
        //     quietly overwrite double URLs which we should probably catch?
        let elements: HashMap<_, _> = list_reply
            .into_elements()
            .into_iter()
            .map(|el| el.unpack())
            .collect();

        let mut all_objects: HashMap<_, _> =
            publish_elements.into_iter()
                .map(|el| (el.uri, el.base64)).collect();

        let mut delta = PublishDelta::empty();

        for (uri, hash) in elements {
            match all_objects.remove(&uri) {
                Some(base64) => {
                    if base64.to_hash() != hash {
                        delta.add_update(Update::new(None, uri, base64, hash))
                    }
                }
                None => delta.add_withdraw(Withdraw::new(None, uri, hash)),
            }
        }

        for (uri, base64) in all_objects {
            delta.add_publish(Publish::new(None, uri, base64));
        }

        if !delta.is_empty() {
            debug!("CA '{}' sends delta", ca_handle);
            self.send_rfc8181_delta(
                repo_manager,
                ca_handle,
                id_cert,
                &repo_contact.server_info,
                delta,
            ).await?;
            debug!("CA '{}' sent delta", ca_handle);
        }
        else {
            debug!("CA '{}' has nothing to publish", ca_handle);
        }

        Ok(())
    }

    /// Returns the current objects for a CA for each repository.
    ///
    /// Typically a CA will use only one repository, but during
    /// migrations there may be multiple.
    ///
    /// The object may not have been published (yet) - check via
    /// `ca_repo_status`.
    fn ca_repo_elements(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<HashMap<RepositoryContact, Vec<PublishedFile>>> {
        Ok(self.ca_objects_store.ca_objects(ca)?.repo_elements_map())
    }

    /// Returns the deprecated repositories so that they can be cleaned.
    fn ca_deprecated_repos(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<Vec<DeprecatedRepository>> {
        Ok(self
            .ca_objects_store
            .ca_objects(ca)?
            .deprecated_repos()
            .cloned()
            .collect()
        )
    }

    /// Removes a deprecated repo
    pub fn ca_deprecated_repo_remove(
        &self,
        ca: &CaHandle,
        to_remove: &RepositoryContact,
    ) -> KrillResult<()> {
        self.ca_objects_store.with_ca_objects(ca, |objects| {
            objects.deprecated_repo_remove(to_remove);
            Ok(())
        })
    }

    /// Increases the clean attempt counter for a deprecated repository
    pub fn ca_deprecated_repo_increment_clean_attempts(
        &self,
        ca: &CaHandle,
        contact: &RepositoryContact,
    ) -> KrillResult<()> {
        self.ca_objects_store.with_ca_objects(ca, |objects| {
            objects.deprecated_repo_inc_clean_attempts(contact);
            Ok(())
        })
    }

    /// Updates the repository where a CA publishes.
    ///
    /// If `check_repo` is `true`, checks that the repository can be reached
    /// and returns an error if not.
    pub async fn update_repo(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: CaHandle,
        new_contact: RepositoryContact,
        check_repo: bool,
        actor: &Actor,
    ) -> KrillResult<()> {
        let ca = self.get_ca(&ca_handle)?;
        if check_repo {
            // First verify that this repository can be reached and responds
            // to a list request.
            self.send_rfc8181_list(
                repo_manager,
                &ca_handle,
                ca.id_cert(),
                &new_contact.server_info,
            ).await.map_err(|e| {
                Error::CaRepoIssue(ca_handle.clone(), e.to_string())
            })?;
        }
        self.process_ca_command(
            ca_handle, actor,
            CertAuthCommandDetails::RepoUpdate(
                new_contact,
                self.signer.clone(),
            )
        )?;
        Ok(())
    }

    /// Sends a publication protocol list request and returns the reply.
    async fn send_rfc8181_list(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        id_cert: &IdCertInfo,
        server_info: &PublicationServerInfo,
    ) -> KrillResult<ListReply> {
        let signing_key = id_cert.public_key.key_identifier();

        let message = publication::Message::list_query();

        let reply = match self.send_rfc8181_and_validate_response(
            repo_manager,
            message,
            server_info,
            ca_handle,
            &signing_key,
        ).await {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &e,
                )?;
                return Err(e);
            }
        };

        match reply {
            publication::Reply::List(list_reply) => {
                self.status_store.set_status_repo_success(
                    ca_handle, server_info.service_uri.clone()
                )?;
                Ok(list_reply)
            }
            publication::Reply::Success => {
                let err = Error::custom("Got success reply to list query?!");
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
            publication::Reply::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
        }
    }

    /// Sends a publication protocol delta request.
    async fn send_rfc8181_delta(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        id_cert: &IdCertInfo,
        server_info: &PublicationServerInfo,
        delta: PublishDelta,
    ) -> KrillResult<()> {
        let signing_key = id_cert.public_key.key_identifier();

        let message = publication::Message::delta(delta.clone());

        let reply = match self.send_rfc8181_and_validate_response(
            repo_manager,
            message,
            server_info,
            ca_handle,
            &signing_key,
        ).await {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &e,
                )?;
                return Err(e);
            }
        };

        match reply {
            publication::Reply::Success => {
                self.status_store.set_status_repo_published(
                    ca_handle,
                    server_info.service_uri.clone(),
                    delta,
                )?;
                Ok(())
            }
            publication::Reply::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
            publication::Reply::List(_) => {
                let err = Error::custom("Got list reply to delta query?!");
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
        }
    }

    /// Sends a publication protocol request and validates the response.
    async fn send_rfc8181_and_validate_response(
        &self,
        repo_manager: &RepositoryManager,
        message: publication::Message,
        server_info: &PublicationServerInfo,
        ca_handle: &CaHandle,
        signing_key: &KeyIdentifier,
    ) -> KrillResult<publication::Reply> {
        let repo_service_uri = &server_info.service_uri;

        if repo_service_uri.as_str().starts_with(
            self.config.service_uri().as_str()
        ) {
            // this maps back to *this* Krill instance
            let query = message.as_query()?;
            let publisher_handle = ca_handle.convert();
            let response = repo_manager.rfc8181_message(
                &publisher_handle, query
            )?;
            response.as_reply().map_err(Error::Rfc8181)
        }
        else {
            // Set up a logger for CMS exchanges.
            let cms_logger = CmsLogger::for_rfc8181_sent(
                self.config.rfc8181_log_dir.as_ref(),
                ca_handle,
            );

            let cms = self.signer.create_rfc8181_cms(
                message, signing_key
            )?.to_bytes();

            let res_bytes = self.post_protocol_cms_binary(
                &cms,
                repo_service_uri,
                publication::CONTENT_TYPE,
                &cms_logger,
            ).await?;

            match publication::PublicationCms::decode(&res_bytes) {
                Err(e) => {
                    error!(
                        "Could not decode response from publication server \
                         at: {}, for ca: {}. Error: {}",
                        repo_service_uri, ca_handle, e
                    );
                    cms_logger.err(format!("Could not decode CMS: {}", e))?;
                    Err(Error::Rfc8181(e))
                }
                Ok(cms) => match cms.validate(&server_info.public_key) {
                    Err(e) => {
                        error!(
                            "Could not validate response from publication \
                            server at: {}, for ca: {}. Error: {}",
                            repo_service_uri, ca_handle, e
                        );
                        cms_logger.err(format!("Response invalid: {}", e))?;
                        Err(Error::Rfc8181(e))
                    }
                    Ok(()) => {
                        cms.into_message().as_reply().map_err(Error::Rfc8181)
                    }
                },
            }
        }
    }
}

/// # ASPA
///
impl CaManager {
    /// Returns the current ASPA definitions for this CA.
    pub fn ca_aspas_definitions_show(
        &self,
        ca: CaHandle,
    ) -> KrillResult<AspaDefinitionList> {
        Ok(self.get_ca(&ca)?.aspas_definitions_show())
    }

    /// Adds a new ASPA definition for this CA.
    pub fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::AspasUpdate(
                updates,
                self.config.clone(),
                self.signer.clone(),
            ),
        )?;
        Ok(())
    }

    /// Updates the ASPA providers for a given customer ASN in a CA.
    pub fn ca_aspas_update_aspa_providers(
        &self,
        ca: CaHandle,
        customer: CustomerAsn,
        update: AspaProvidersUpdate,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::AspasUpdateExisting(
                customer,
                update,
                self.config.clone(),
                self.signer.clone(),
            )
        )?;
        Ok(())
    }
}

/// # BGPSec functions
impl CaManager {
    /// Returns the BGPsec definitions for a CA.
    pub fn ca_bgpsec_definitions_show(
        &self,
        ca: CaHandle,
    ) -> KrillResult<BgpSecCsrInfoList> {
        Ok(self.get_ca(&ca)?.bgpsec_definitions_show())
    }

    /// Updates the BGPsec definitions for a CA.
    pub fn ca_bgpsec_definitions_update(
        &self,
        ca: CaHandle,
        updates: BgpSecDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::BgpSecUpdateDefinitions(
                updates,
                self.config.clone(),
                self.signer.clone(),
            ),
        )?;
        Ok(())
    }
}

/// # ROAs
///
impl CaManager {
    /// Updates the ROA configuratoin for a CA.
    ///
    /// This will trigger that ROAs are made in the resource classes that
    /// contain the prefixes. If the update is rejected, e.g. because the CA
    /// does not have the necessary prefixes then an error will be returned.
    /// If the update is successful, new manifest(s) and CRL(s) will be
    /// created, and resynchronization between the CA and its repository
    /// will be triggered. Finally note that ROAs may be issues on a per
    /// prefix basis, or aggregated by ASN based on the defaults or values
    /// configured.
    pub fn ca_routes_update(
        &self,
        ca: CaHandle,
        updates: RoaConfigurationUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RouteAuthorizationsUpdate(
                updates,
                self.config.clone(),
                self.signer.clone(),
            ),
        )?;
        Ok(())
    }

    /// Re-issues objects of all CAs that are about to expire.
    ///
    /// This is a no-op in case no object needs re-issuance. If new objects
    /// are created they will also be published. An event will trigger that
    /// manifests and CRL are also made and the CA in question
    /// synchronizes with its repository.
    ///
    /// Note that this does not re-issue issued CA certificates, because child
    /// CAs are expected to note extended validity eligibility and request
    /// updated certificates themselves.
    pub fn renew_objects_all(
        &self, actor: &Actor
    ) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::RouteAuthorizationsRenew(
                    self.config.clone(),
                    self.signer.clone(),
                )
            ) {
                error!(
                    "Renewing ROAs for CA '{}' failed with error: {}",
                    ca, e
                );
            }

            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::AspasRenew(
                    self.config.clone(),
                    self.signer.clone(),
                ),
            ) {
                error!(
                    "Renewing ASPAs for CA '{}' failed with error: {}",
                    ca, e
                );
            }

            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::BgpSecRenew(
                    self.config.clone(),
                    self.signer.clone(),
                ),
            ) {
                error!(
                    "Renewing BGPsec certificates for CA '{ca}' \
                     failed with error: {e}"
                );
            }
        }
        Ok(())
    }

    /// Forces the re-issuance of all ROAs in all CAs.
    ///
    /// This function was added because we need to re-issue ROAs in Krill
    /// 0.9.3 to force that a short subject CN is used for the EE
    /// certificate: i.e. the SKI rather than the full public key. But there
    /// may also be other cases in future where forcing to re-issue ROAs may
    /// be useful.
    pub fn force_renew_roas_all(
        &self,
        actor: &Actor,
    ) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::RouteAuthorizationsForceRenew(
                    self.config.clone(),
                    self.signer.clone(),
                ),
            ) {
                error!(
                    "Renewing ROAs for CA '{}' failed with error: {}",
                    ca, e
                );
            }
        }
        Ok(())
    }
}

/// # RTA
///
impl CaManager {
    /// Sign a one-off single-signed RTA
    pub fn rta_sign(
        &self,
        ca: CaHandle,
        name: RtaName,
        request: RtaContentRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RtaSign(
                name,
                request,
                self.signer.clone(),
            )
        )?;
        Ok(())
    }

    /// Prepare a multi-singed RTA
    pub fn rta_multi_prep(
        &self,
        ca: &CaHandle,
        name: RtaName,
        request: RtaPrepareRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RtaMultiPrepare(
                name,
                request,
                self.signer.clone(),
            )
        )?;
        Ok(())
    }

    /// Co-sign an existing RTA
    pub fn rta_multi_cosign(
        &self,
        ca: CaHandle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RtaCoSign(
                name,
                rta,
                self.signer.clone(),
            )
        )?;
        Ok(())
    }
}

/// CA Key Roll
impl CaManager {
    /// Initiates an key roll for all old active keys in a CA.
    ///
    /// A key roll is started for all keys in the given CA that are older
    /// than `max_age`.
    pub fn ca_keyroll_init(
        &self,
        handle: CaHandle,
        max_age: Duration,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            handle.clone(), actor,
            CertAuthCommandDetails::KeyRollInitiate(
                max_age,
                self.signer.clone(),
            )
        )?;
        Ok(())
    }

    /// Activates a new key, as part of the key roll process.
    ///
    /// Only new keys that have an age equal to or greater than the staging
    /// period are promoted. The RFC mandates a staging period of 24
    /// hours, but we may use a shorter period for testing and/or emergency
    /// manual key rolls.
    pub fn ca_keyroll_activate(
        &self,
        handle: CaHandle,
        staging: Duration,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.process_ca_command(
            handle.clone(), actor,
            CertAuthCommandDetails::KeyRollActivate(
                staging,
                self.config.clone(),
                self.signer.clone(),
            )
        )?;
        Ok(())
    }
}

