//! A manager for all CAs.


//------------ Sub-modules ---------------------------------------------------
//
// Some functionality of `CaManager` has been moved into sub-modules for
// manageability. 

mod child;
mod http;
mod rfc8181;
mod parent;


//------------ Actual content ------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use chrono::Duration;
use log::{debug, error, info, trace, warn};
use rpki::uri;
use rpki::ca::publication;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, ParentResponse, PublisherRequest,
    ServiceUri
};
use crate::api::admin::{
    AddChildRequest, ParentCaContact, ParentCaReq, ParentServerInfo,
    PublishedFile, RepositoryContact,
    UpdateChildRequest,
};
use crate::api::aspa::{
    AspaDefinitionList, AspaDefinitionUpdates, AspaProvidersUpdate,
    CustomerAsn,
};
use crate::api::bgpsec::{BgpSecCsrInfoList, BgpSecDefinitionUpdates};
use crate::api::ca::{
    CertAuthIssues, CertAuthList, CertAuthSummary, ChildCaInfo, IdCertInfo,
    ParentStatuses, RepoStatus, RtaName, Timestamp,
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
    ApiTrustAnchorSignedRequest,
    TrustAnchorSignedResponse, TrustAnchorSignerInfo,
};
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::error::{Error, Error as KrillError};
use crate::commons::eventsourcing::{Aggregate, AggregateStore, SentCommand};
use crate::config::Config;
use crate::constants::{
    CASERVER_NS, STATUS_NS, TA_PROXY_SERVER_NS, TA_SIGNER_SERVER_NS, TA_NAME,
    ta_handle,
};
use crate::daemon::http::auth::{AuthInfo, Permission}; // XXX remove
use crate::server::manager::KrillContext;
use crate::server::mq::{now, Task, TaskQueue};
use crate::server::runtime;
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

    /// A Tokio runtime handle to spawn tasks onto.
    runtime: runtime::Handle,
}

impl CaManager {
    /// Builds a new CA manager.
    ///
    /// Return an error if any of the various stores cannot be initialized.
    pub fn build(
        config: &Config,
        tasks: &Arc<TaskQueue>,
        runtime: runtime::Handle,
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
            &config.storage_uri
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
            runtime,
        })
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
    pub fn republish_all(
        &self,
        force: bool,
        krill: &KrillContext,
    ) -> KrillResult<Vec<CaHandle>> {
        let mut res = vec![];
        for ca in self.ca_store.list()? {
            match self.ca_objects_store.reissue_if_needed(
                force, &ca, &krill.config().issuance_timing, krill.signer(),
            ) {
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
    pub fn ta_proxy_init(
        &self,
        krill: &KrillContext,
    ) -> KrillResult<()> {
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
                krill.signer(),
                krill.system_actor(),
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
        krill: &KrillContext,
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
            timing: krill.config().ta_timing,
            signer: krill.signer(),
        };
        let cmd = TrustAnchorSignerInitCommand::new(
            handle,
            details,
            &krill.system_actor(),
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
        &self, actor: &Actor, krill: &KrillContext,
    ) -> KrillResult<ApiTrustAnchorSignedRequest> {
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::make_signer_request(&ta_handle(), actor)
        )?.get_signer_request(krill.config().ta_timing, krill.signer())
    }

    /// Returns the current request for the signer.
    pub fn ta_proxy_signer_get_request(
        &self, krill: &KrillContext
    ) -> KrillResult<ApiTrustAnchorSignedRequest> {
        self.get_trust_anchor_proxy()?.get_signer_request(
            krill.config().ta_timing, krill.signer()
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
    pub fn ta_init_fully_embedded(
        &self,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,
        ta_key_pem: Option<String>,
        actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        let ta_handle = ta_handle();

        // Initialise proxy
        self.ta_proxy_init(krill)?;

        // Add repository
        let pub_req = self.ta_proxy_publisher_request()?;

        // Create publisher
        krill.repo_manager().create_publisher(pub_req, actor)?;
        let repository_response = krill.repo_manager().repository_response(
            &ta_handle.convert()
        )?;

        // Add repository to proxy
        let contact = RepositoryContact::try_from_response(
            repository_response
        ).map_err(Error::rfc8183)?;
        self.ta_proxy_repository_update(contact, krill.system_actor())?;

        // Initialise signer
        self.ta_signer_init(ta_uris, ta_aia, ta_key_pem, krill)?;

        // Add signer to proxy
        let signer_info = self.get_trust_anchor_signer()?.get_signer_info();
        self.ta_proxy_signer_add(signer_info, krill.system_actor())?;

        self.sync_ta_proxy_signer_if_possible(krill)?;
        self.cas_repo_sync_single(&ta_handle, 0, krill)?;

        Ok(())
    }

    /// Renews the embedded testbed TA;
    pub fn ta_renew_testbed_ta(
        &self, krill: &KrillContext,
    ) -> KrillResult<()> {
        if krill.is_testbed_enabled() {
            let proxy = self.get_trust_anchor_proxy()?;
            if !proxy.has_open_request() {
                info!("Renew the testbed TA");
                self.sync_ta_proxy_signer_if_possible(krill)?;
            }
        }
        Ok(())
    }
}

/// # CA instances and identity
///
impl CaManager {
    /// Initializes a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(
        &self, handle: CaHandle, krill: &KrillContext,
    ) -> KrillResult<()> {
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
                CertAuthInitCommandDetails { signer: krill.signer() },
                &krill.system_actor(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            handle, actor,
            CertAuthCommandDetails::GenerateNewIdKey(krill.signer())
        )?;
        Ok(())
    }

    /// Returns all known CA handles.
    pub fn ca_handles(&self) -> KrillResult<Vec<CaHandle>> {
        Ok(self.ca_store.list()?)
    }

    /// Returns the CAs that the given policy allows read access to.
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
    pub fn delete_ca(
        &self,
        ca_handle: &CaHandle,
        actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        warn!("Deleting CA '{ca_handle}' as requested by: {actor}");

        let ca = self.get_ca(ca_handle)?;

        // Request revocations from all parents - best effort
        info!(
            "Will try to request revocations from all parents CA '{ca_handle}' \
             before removing it."
        );
        for parent in ca.parents() {
            if let Err(e) = self.ca_parent_revoke(
                ca_handle, parent, krill
            ) {
                warn!(
                    "Removing CA '{ca_handle}', but could not send revoke request \
                     to parent '{parent}': {e}"
                );
            }
        }

        // Clean all repos - again best effort
        info!(
            "Will try to clean up all repositories for CA '{ca_handle}' before \
             removing it."
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
                ca_handle, ca.id_cert(), &repo_contact, vec![], krill
            ).is_err() {
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
        trace!("Finding details for CA: {child} under parent: {ca}");
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
        trace!("Exporting CA: {child_handle} under parent: {ca}");
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        trace!("Importing CA: {} under parent: {}", import_child.name, ca);
        self.process_ca_command(ca.clone(), actor,
            CertAuthCommandDetails::ChildImport(
                import_child,
                krill.config(),
                krill.signer(),
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
        let service_uri = format!("{base_uri}rfc6492/{ca_handle}");
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
    pub fn ca_parent_remove(
        &self,
        handle: CaHandle,
        parent: ParentHandle,
        actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        // Best effort, request revocations for any remaining keys under this
        // parent.
        if let Err(e) = self.ca_parent_revoke(&handle, &parent, krill) {
            warn!(
                "Removing parent '{parent}' from CA '{handle}', but could not send \
                 revoke requests: {e}"
            );
        }

        self.status_store.remove_parent(&handle, &parent)?;
        self.process_ca_command(
            handle, actor,
            CertAuthCommandDetails::RemoveParent(parent),
        )?;
        Ok(())
    }

    /// Sends revocation requests for a parent of a CA.
    fn ca_parent_revoke(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        let ca = self.get_ca(handle)?;
        let revoke_requests = ca.revoke_under_parent(parent, krill.signer())?;
        self.send_revoke_requests(handle, parent, revoke_requests, krill)?;
        Ok(())
    }

    /// Schedules refreshing all CAs as soon as possible:
    ///
    /// Note: this function can be called manually through the API, but
    /// normally the CA refresh process is replanned on the task
    /// queue automatically.
    pub fn cas_schedule_refresh_all(
        &self,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        if let Ok(cas) = self.ca_store.list() {
            for ca_handle in cas {
                self.cas_schedule_refresh_single(ca_handle, krill)?;
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.ca_schedule_sync_parents(&ca_handle, krill)
    }

    /// Schedules an immediate check suspending all inactive children.
    ///
    /// This check will suspend all children of all CAs that have not been
    /// contacting the CA for a certain time if suspension is enabled.
    ///
    /// While this function can be called manually through the API, it is
    /// normally replanned on the task queue automatically if suspension is
    /// enabled.
    pub fn cas_schedule_suspend_all(
        &self,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        if krill.config().suspend_child_after_inactive_seconds().is_some() {
            if let Ok(cas) = self.ca_store.list() {
                for ca in cas {
                    krill.tasks().schedule(
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
        &self, ca_handle: &CaHandle, started: Timestamp, actor: &Actor,
        krill: &KrillContext,
    ) {
        // Set threshold hours if it was configured AND this server has been
        // started longer ago than the hours specified. Otherwise we
        // risk that *all* children without prior recorded status are
        // suspended on upgrade, or that *all* children are suspended
        // if the server had been down for more than the threshold hours.
        let threshold_seconds =
            krill.config().suspend_child_after_inactive_seconds()
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
                            format!("{threshold_seconds} seconds")
                        };

                        info!(
                            "Child '{child}' under CA '{ca_handle}' was inactive for more \
                             than {threshold_string}. Will suspend it."
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
                            "Could not suspend inactive child, error: {e}"
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        let Ok(ca) = self.get_ca(ca_handle) else {
            return Ok(())
        };

        if ca.nr_parents() <= krill.config().ca_refresh_parents_batch_size {
            // Nr of parents is below batch size, so just process all
            // of them
            for parent in ca.parents() {
                krill.tasks().schedule(
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
                krill.config().ca_refresh_parents_batch_size,
            ) {
                krill.tasks().schedule(
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

}

/// # Publishing
///
impl CaManager {
    /// Schedules synchronizing all CAs with their repositories.
    pub fn cas_schedule_repo_sync_all(
        &self, krill: &KrillContext,
    ) -> KrillResult<()> {
        for ca in self.ca_handles()? {
            self.cas_schedule_repo_sync(ca, krill)?;
        }
        Ok(())
    }

    /// Schedules synchronizing a CA with its repositories.
    pub fn cas_schedule_repo_sync(
        &self, ca_handle: CaHandle, krill: &KrillContext,
    ) -> KrillResult<()> {
        // no need to wait for an updated CA to be committed. 
        let ca_version = 0;
        krill.tasks().schedule(
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
    pub fn cas_repo_sync_single(
        &self,
        ca_handle: &CaHandle,
        ca_version: u64,
        krill: &KrillContext,
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
                self.ca_repo_sync(ca_handle, id, repo, objects, krill)?;
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
                        ca_handle, ca.id_cert(), &repo_contact, objects, krill
                    )?;
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
                        ca_handle,
                        ca.id_cert(),
                        deprecated.contact(),
                        vec![],
                        krill
                    ) {
                        warn!(
                            "Could not clean up deprecated repository: {e}"
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
    #[allow(clippy::too_many_arguments)]
    pub fn update_repo(
        &self,
        ca_handle: CaHandle,
        new_contact: RepositoryContact,
        check_repo: bool,
        actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        let ca = self.get_ca(&ca_handle)?;
        if check_repo {
            // First verify that this repository can be reached and responds
            // to a list request.
            self.send_rfc8181_list(
                &ca_handle, ca.id_cert(), &new_contact.server_info, krill
            ).map_err(|e| {
                Error::CaRepoIssue(ca_handle.clone(), e.to_string())
            })?;
        }
        self.process_ca_command(
            ca_handle, actor,
            CertAuthCommandDetails::RepoUpdate(
                new_contact,
                krill.signer()
            )
        )?;
        Ok(())
    }
}

/// # ASPA
///
impl CaManager {
    /// Returns the current ASPA definitions for this CA.
    pub fn ca_aspas_definitions_show(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<AspaDefinitionList> {
        Ok(self.get_ca(ca)?.aspas_definitions_show())
    }

    /// Adds a new ASPA definition for this CA.
    pub fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca, actor,
            CertAuthCommandDetails::AspasUpdate(
                updates,
                krill.config(),
                krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::AspasUpdateExisting(
                customer,
                update,
                krill.config(),
                krill.signer(),
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
        ca: &CaHandle,
    ) -> KrillResult<BgpSecCsrInfoList> {
        Ok(self.get_ca(ca)?.bgpsec_definitions_show())
    }

    /// Updates the BGPsec definitions for a CA.
    pub fn ca_bgpsec_definitions_update(
        &self,
        ca: CaHandle,
        updates: BgpSecDefinitionUpdates,
        actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::BgpSecUpdateDefinitions(
                updates,
                krill.config(),
                krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RouteAuthorizationsUpdate(
                updates,
                krill.config(),
                krill.signer(),
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
        &self, actor: &Actor, krill: &KrillContext,
    ) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::RouteAuthorizationsRenew(
                    krill.config(),
                    krill.signer(),
                )
            ) {
                error!(
                    "Renewing ROAs for CA '{ca}' failed with error: {e}"
                );
            }

            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::AspasRenew(
                    krill.config(),
                    krill.signer(),
                ),
            ) {
                error!(
                    "Renewing ASPAs for CA '{ca}' failed with error: {e}"
                );
            }

            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::BgpSecRenew(
                    krill.config(),
                    krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            if let Err(e) = self.process_ca_command(
                ca.clone(), actor,
                CertAuthCommandDetails::RouteAuthorizationsForceRenew(
                    krill.config(),
                    krill.signer(),
                ),
            ) {
                error!(
                    "Renewing ROAs for CA '{ca}' failed with error: {e}"
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RtaSign(
                name,
                request,
                krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RtaMultiPrepare(
                name,
                request,
                krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::RtaCoSign(
                name,
                rta,
                krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            handle.clone(), actor,
            CertAuthCommandDetails::KeyRollInitiate(
                max_age,
                krill.signer(),
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
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.process_ca_command(
            handle.clone(), actor,
            CertAuthCommandDetails::KeyRollActivate(
                staging,
                krill.config(),
                krill.signer(),
            )
        )?;
        Ok(())
    }
}

