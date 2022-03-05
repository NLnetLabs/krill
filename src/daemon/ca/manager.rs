use std::{collections::HashMap, ops::Deref, sync::Arc};

use api::{Publish, Update, Withdraw};
use futures::future::join_all;
use tokio::sync::Mutex;

use bytes::Bytes;
use chrono::Duration;

use rpki::{repository::crypto::KeyIdentifier, uri};

use crate::{
    commons::{
        actor::Actor,
        api::{
            self, AddChildRequest, AspaCustomer, AspaDefinitionList, AspaDefinitionUpdates, AspaProvidersUpdate,
            Base64, CaCommandDetails, CaCommandResult, CertAuthList, CertAuthSummary, ChildCaInfo, ChildHandle,
            CommandHistory, CommandHistoryCriteria, Entitlements, Handle, IssuanceRequest, IssuanceResponse, ListReply,
            ParentCaContact, ParentCaReq, ParentHandle, PublishDelta, RcvdCert, RepositoryContact, ResourceClassName,
            ResourceSet, RevocationRequest, RevocationResponse, RtaName, StoredEffect, UpdateChildRequest,
        },
        api::{rrdp::PublishElement, Timestamp},
        crypto::{IdCert, KrillSigner, ProtocolCms, ProtocolCmsBuilder},
        error::Error,
        eventsourcing::{Aggregate, AggregateStore, Command, CommandKey},
        remote::cmslogger::CmsLogger,
        remote::{rfc6492, rfc8181, rfc8183},
        util::httpclient,
        KrillResult,
    },
    constants::{CASERVER_DIR, REQUEUE_DELAY_SECONDS, STATUS_DIR},
    daemon::{
        auth::common::permissions::Permission,
        ca::{
            self, ta_handle, CaObjectsStore, CaStatus, CertAuth, Cmd, CmdDet, DeprecatedRepository, IniDet,
            ResourceTaggedAttestation, RouteAuthorizationUpdates, RtaContentRequest, RtaPrepareRequest, StatusStore,
        },
        config::Config,
        mq::MessageQueue,
    },
    pubd::RepositoryManager,
};

//------------ CaLocks ------------------------------------------------------

pub struct CaLockMap(HashMap<Handle, tokio::sync::RwLock<()>>);

impl CaLockMap {
    fn create_ca_lock(&mut self, ca: &Handle) {
        self.0.insert(ca.clone(), tokio::sync::RwLock::new(()));
    }

    fn has_ca(&self, ca: &Handle) -> bool {
        self.0.contains_key(ca)
    }

    fn drop_ca_lock(&mut self, ca: &Handle) {
        self.0.remove(ca);
    }
}

impl Default for CaLockMap {
    fn default() -> Self {
        CaLockMap(HashMap::new())
    }
}

pub struct CaLock<'a> {
    map: tokio::sync::RwLockReadGuard<'a, CaLockMap>,
    ca: Handle,
}

impl CaLock<'_> {
    async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.map.0.get(&self.ca).unwrap().read().await
    }

    async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.map.0.get(&self.ca).unwrap().write().await
    }
}

pub struct CaLocks {
    locks: tokio::sync::RwLock<CaLockMap>,
}

impl Default for CaLocks {
    fn default() -> Self {
        CaLocks {
            locks: tokio::sync::RwLock::new(CaLockMap::default()),
        }
    }
}

impl CaLocks {
    async fn ca(&self, ca: &Handle) -> CaLock<'_> {
        // self.create_lock_if_needed(ca).await;
        {
            let map = self.locks.read().await;
            if map.has_ca(ca) {
                return CaLock { map, ca: ca.clone() };
            }
        }

        {
            let mut lock = self.locks.write().await;
            lock.create_ca_lock(ca);
        }

        let map = self.locks.read().await;
        CaLock { map, ca: ca.clone() }
    }

    async fn drop_ca(&self, ca: &Handle) {
        let mut map = self.locks.write().await;
        map.drop_ca_lock(ca);
    }
}

//------------ CaManager -----------------------------------------------------

#[derive(Clone)]
pub struct CaManager {
    ca_store: Arc<AggregateStore<CertAuth>>,
    ca_objects_store: Arc<CaObjectsStore>,
    status_store: Arc<Mutex<StatusStore>>,
    locks: Arc<CaLocks>,
    config: Arc<Config>,
    signer: Arc<KrillSigner>,

    // System actor
    system_actor: Actor,
}

impl CaManager {
    /// Builds a new CaServer. Will return an error if the CA store cannot be initialized.
    pub async fn build(
        config: Arc<Config>,
        mq: Arc<MessageQueue>,
        signer: Arc<KrillSigner>,
        system_actor: Actor,
    ) -> KrillResult<Self> {
        // Create the AggregateStore for the event-sourced `CertAuth` structures that handle
        // most CA functions.
        let mut ca_store = AggregateStore::<CertAuth>::disk(&config.data_dir, CASERVER_DIR)?;

        if config.always_recover_data {
            // If the user chose to 'always recover data' then do so.
            // This is slow, but it will ensure that all commands and events are accounted for,
            // and there are no incomplete changes where some but not all files for a change were
            // written to disk.
            ca_store.recover()?;
        } else if let Err(e) = ca_store.warm() {
            // Otherwise we just tried to 'warm' the cache. This serves two purposes:
            // 1. this ensures that all `CertAuth` structs are available in memory
            // 2. this ensures that there are no apparent data issues
            //
            // If there are issues, then complain and try to recover.
            error!(
                "Could not warm up cache, data seems corrupt. Will try to recover!! Error was: {}",
                e
            );
            ca_store.recover()?;
        }

        // Create the `CaObjectStore` that is responsible for maintaining CA objects: the `CaObjects`
        // for a CA gets copies of all ROAs and delegated certificates from the `CertAuth` and is responsible
        // for manifests and CRL generation.
        let ca_objects_store = Arc::new(CaObjectsStore::disk(
            &config.data_dir,
            config.issuance_timing.clone(),
            signer.clone(),
        )?);

        // Register the `CaObjectsStore` as a pre-save listener to the 'ca_store' so that it can update
        // its ROAs and delegated certificates and/or generate manifests and CRLs when relevant changes
        // occur in a `CertAuth`.
        ca_store.add_pre_save_listener(ca_objects_store.clone());

        // Register the `MessageQueue` as a post-save listener to 'ca_store' so that relevant changes in
        // a `CertAuth` can trigger follow up actions. Most importantly: synchronize with a parent CA or
        // the RPKI repository.
        ca_store.add_post_save_listener(mq);

        // Create the status store which will maintain the last known connection status between each CA
        // and their parent(s) and repository.
        let status_store = StatusStore::new(&config.data_dir, STATUS_DIR)?;

        // Create the per-CA lock structure so that we can guarantee safe access to each CA, while allowing
        // multiple CAs in a single Krill instance to interact: e.g. a child can talk to its parent and they
        // are locked individually.
        let locks = Arc::new(CaLocks::default());

        Ok(CaManager {
            ca_store: Arc::new(ca_store),
            ca_objects_store,
            status_store: Arc::new(Mutex::new(status_store)),
            locks,
            config,
            signer,
            system_actor,
        })
    }

    pub fn testbed_enabled(&self) -> bool {
        self.config.testbed().is_some()
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub async fn get_trust_anchor(&self) -> KrillResult<Arc<CertAuth>> {
        let ta_handle = ca::ta_handle();
        let lock = self.locks.ca(&ta_handle).await;
        let _ = lock.read().await;
        self.ca_store.get_latest(&ta_handle).map_err(Error::AggregateStoreError)
    }

    /// Initializes an embedded trust anchor with all resources.
    pub async fn init_ta(
        &self,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,
        repo_manager: &Arc<RepositoryManager>,
        actor: &Actor,
    ) -> KrillResult<()> {
        let ta_handle = ca::ta_handle();
        let lock = self.locks.ca(&ta_handle).await;
        let _ = lock.write().await;
        if self.ca_store.has(&ta_handle)? {
            Err(Error::TaAlreadyInitialized)
        } else {
            // init normal CA
            let init = IniDet::init(&ta_handle, self.signer.deref())?;
            self.ca_store.add(init)?;

            // add to repo
            let ta = self.get_trust_anchor().await?;
            let pub_req = ta.publisher_request();
            repo_manager.create_publisher(pub_req, actor)?;
            let repository_response = repo_manager.repository_response(&ta_handle)?;
            let contact = RepositoryContact::new(repository_response);

            let upd_repo_cmd = CmdDet::update_repo(&ta_handle, contact, self.signer.clone(), actor);
            self.ca_store.command(upd_repo_cmd)?;

            // make trust anchor
            let make_ta_cmd =
                CmdDet::make_trust_anchor(&ta_handle, ta_uris, Some(ta_aia.clone()), self.signer.clone(), actor);
            let ta = self.ca_store.command(make_ta_cmd)?;

            // receive the self signed cert (now as child of self)
            let ta_cert = ta.parent(&ta_handle).unwrap().to_ta_cert();
            let rcvd_cert = RcvdCert::new(ta_cert.clone(), ta_aia, ResourceSet::all_resources());

            let rcv_cert = CmdDet::upd_received_cert(
                &ta_handle,
                ResourceClassName::default(),
                rcvd_cert,
                self.config.clone(),
                self.signer.clone(),
                actor,
            );
            self.ca_store.command(rcv_cert)?;

            Ok(())
        }
    }

    /// Send a command to a CA
    async fn send_command(&self, cmd: Cmd) -> KrillResult<Arc<CertAuth>> {
        let lock = self.locks.ca(cmd.handle()).await;
        let _ = lock.write().await;
        self.ca_store.command(cmd)
    }

    /// Republish the embedded TA and CAs if needed, i.e. if they are close
    /// to their next update time.
    pub async fn republish_all(&self) -> KrillResult<Vec<Handle>> {
        self.ca_objects_store.reissue_all()
    }
}

/// # CA instances and identity
///
impl CaManager {
    /// Initializes a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(&self, handle: &Handle) -> KrillResult<()> {
        if handle == &ta_handle() || handle.as_str() == "version" {
            Err(Error::TaNameReserved)
        } else if self.ca_store.has(handle)? {
            Err(Error::CaDuplicate(handle.clone()))
        } else {
            // Initialize the CA in self.ca_store, but note that there is no need to create
            // a new CA entry in self.ca_objects_store or self.status_store, because they will
            // generate empty default entries if needed.
            let init = IniDet::init(handle, self.signer.deref())?;
            self.ca_store.add(init)?;
            Ok(())
        }
    }

    /// Updates the self-signed ID certificate for a CA. Use this with care as
    /// RFC 8183 only talks about initial ID exchanges in the form of XML files.
    /// It does not talk about updating identity certificates and keys. Krill supports
    /// that a new ID key pair and certificate is generated, and has functions to update
    /// this for a parent, a child, a repo and a publisher, but other implementations may
    /// not support that identities are updated after initialization.
    pub async fn ca_update_id(&self, handle: Handle, actor: &Actor) -> KrillResult<()> {
        let cmd = CmdDet::update_id(&handle, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Get the CAs that the given actor is permitted to see.
    pub fn ca_list(&self, actor: &Actor) -> KrillResult<CertAuthList> {
        Ok(CertAuthList::new(
            self.ca_store
                .list()?
                .into_iter()
                .filter(|handle| matches!(actor.is_allowed(Permission::CA_READ, handle.clone()), Ok(true)))
                .map(CertAuthSummary::new)
                .collect(),
        ))
    }

    /// Gets a CA by the given handle, returns an `Err(ServerError::UnknownCA)` if it
    /// does not exist.
    pub async fn get_ca(&self, handle: &Handle) -> KrillResult<Arc<CertAuth>> {
        let lock = self.locks.ca(handle).await;
        let _ = lock.read().await;
        self.ca_store
            .get_latest(handle)
            .map_err(|_| Error::CaUnknown(handle.clone()))
    }

    /// Checks whether a CA by the given handle exists.
    pub fn has_ca(&self, handle: &Handle) -> KrillResult<bool> {
        self.ca_store.has(handle).map_err(Error::AggregateStoreError)
    }

    /// Gets current CA status
    pub async fn get_ca_status(&self, ca: &Handle) -> KrillResult<Arc<CaStatus>> {
        if self.has_ca(ca)? {
            self.status_store.lock().await.get_ca_status(ca).await
        } else {
            Err(Error::CaUnknown(ca.clone()))
        }
    }

    /// Delete a CA. Let it do best effort revocation requests and withdraw
    /// all its objects first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub async fn delete_ca(&self, ca_handle: &Handle, actor: &Actor) -> KrillResult<()> {
        warn!("Deleting CA '{}' as requested by: {}", ca_handle, actor);

        let ca = self.get_ca(ca_handle).await?;

        // Request revocations from all parents - best effort
        info!(
            "Will try to request revocations from all parents CA '{}' before removing it.",
            ca_handle
        );
        for parent in ca.parents() {
            if let Err(e) = self.ca_parent_revoke(ca_handle, parent).await {
                warn!(
                    "Removing CA '{}', but could not send revoke requests to parent '{}': {}",
                    ca_handle, parent, e
                );
            }
        }

        // Clean all repos - again best effort
        info!(
            "Will try to clean up all repositories for CA '{}' before removing it.",
            ca_handle
        );
        let mut repos: Vec<RepositoryContact> = self
            .ca_repo_elements(ca_handle)
            .await?
            .into_iter()
            .map(|(contact, _)| contact)
            .collect();

        for deprecated in self.ca_deprecated_repos(ca_handle)? {
            repos.push(deprecated.into());
        }

        for repo_contact in repos {
            if self.ca_repo_sync(ca_handle, &repo_contact, vec![]).await.is_err() {
                info!(
                    "Could not clean up deprecated repository. This is fine - objects there are no longer referenced."
                );
            }
        }

        self.ca_store.drop_aggregate(ca_handle)?;
        self.status_store.lock().await.remove_ca(ca_handle).await?;

        self.locks.drop_ca(ca_handle).await;

        Ok(())
    }

    /// Re-synchronize the CAs and CaStatus
    ///
    /// - remove any surplus CA status entries
    /// - create missing CA status entries
    /// - check children for existing CAs:
    ///    - remove surplus from status
    ///    - add missing
    pub async fn resync_ca_statuses(&self) -> KrillResult<()> {
        let cas = self.ca_store.list()?;

        let mut ca_statuses = self.status_store.lock().await.cas().await?;

        // loop over existing CAs and get their status
        for ca_handle in cas {
            let ca = self.get_ca(&ca_handle).await?;
            let status = match ca_statuses.remove(&ca_handle) {
                Some(status) => status,
                None => {
                    // Getting a missing status will ensure that a new empty status is generated.
                    self.status_store.lock().await.get_ca_status(&ca_handle).await?
                }
            };

            let mut status_children = status.children().clone();

            // add default status for missing children
            for child in ca.children() {
                if status_children.remove(child).is_none() {
                    self.status_store
                        .lock()
                        .await
                        .set_child_default_if_missing(&ca_handle, child)
                        .await?;
                }
            }

            // remove surplus children status
            for surplus_child in status_children.keys() {
                self.status_store
                    .lock()
                    .await
                    .remove_child(&ca_handle, surplus_child)
                    .await?;
            }
        }

        // remove the status for any left-over CAs with status
        for surplus_ca in ca_statuses.keys() {
            info!("Removing the cached status for a removed CA: {}", surplus_ca);
            self.status_store.lock().await.remove_ca(surplus_ca).await?;
        }

        Ok(())
    }
}

/// # CA History
///
impl CaManager {
    /// Gets the history for a CA.
    pub async fn ca_history(&self, handle: &Handle, crit: CommandHistoryCriteria) -> KrillResult<CommandHistory> {
        let ca_lock = self.locks.ca(handle).await;
        let _lock = ca_lock.read().await;
        Ok(self.ca_store.command_history(handle, crit)?)
    }

    /// Shows the details for a CA command.
    pub fn ca_command_details(&self, handle: &Handle, command: CommandKey) -> KrillResult<CaCommandDetails> {
        let command = self.ca_store.get_command(handle, &command)?;

        let effect = command.effect().clone();
        match effect {
            StoredEffect::Error { msg } => Ok(CaCommandDetails::new(command, CaCommandResult::error(msg))),
            StoredEffect::Success { events } => {
                let mut stored_events = vec![];
                for version in events {
                    let evt = self.ca_store.get_event(handle, version)?.ok_or_else(|| {
                        Error::Custom(format!("Cannot find evt: {} in history for CA: {}", version, handle))
                    })?;
                    stored_events.push(evt);
                }

                Ok(CaCommandDetails::new(command, CaCommandResult::events(stored_events)))
            }
        }
    }
}

/// # CAs as parents
///
impl CaManager {
    /// Adds a child under a CA. The 'service_uri' is used here so that
    /// the appropriate `ParentCaContact` can be returned. If the `AddChildRequest`
    /// contains resources not held by this CA, then an `Error::CaChildExtraResources`
    /// is returned.
    pub async fn ca_add_child(
        &self,
        ca: &Handle,
        req: AddChildRequest,
        service_uri: &uri::Https,
        actor: &Actor,
    ) -> KrillResult<ParentCaContact> {
        info!("CA '{}' process add child request: {}", &ca, &req);
        let (child_handle, child_res, id_cert) = req.unpack();

        let add_child = CmdDet::child_add(ca, child_handle.clone(), id_cert, child_res, actor);
        self.send_command(add_child).await?;

        self.ca_parent_contact(ca, child_handle, service_uri).await
    }

    /// Show details for a child under the CA.
    pub async fn ca_show_child(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        trace!("Finding details for CA: {} under parent: {}", child, ca);
        let ca = self.get_ca(ca).await?;
        ca.get_child(child).map(|details| details.clone().into())
    }

    /// Show a contact for a child.
    pub async fn ca_parent_contact(
        &self,
        ca_handle: &Handle,
        child_handle: ChildHandle,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentCaContact> {
        let response = self.ca_parent_response(ca_handle, child_handle, service_uri).await?;
        Ok(ParentCaContact::for_rfc6492(response))
    }

    /// Gets an RFC8183 Parent Response for the child.
    pub async fn ca_parent_response(
        &self,
        ca: &Handle,
        child_handle: ChildHandle,
        service_uri: &uri::Https,
    ) -> KrillResult<rfc8183::ParentResponse> {
        let ca = self.get_ca(ca).await?;
        let service_uri = format!("{}rfc6492/{}", service_uri.to_string(), ca.handle());
        let service_uri = uri::Https::from_string(service_uri).unwrap();
        let service_uri = rfc8183::ServiceUri::Https(service_uri);

        Ok(rfc8183::ParentResponse::new(
            None,
            ca.id_cert().clone(),
            ca.handle().clone(),
            child_handle,
            service_uri,
        ))
    }

    /// Update a child under this CA. The submitted `UpdateChildRequest` can contain a
    /// new `IdCert`, or `ResourceSet`, or both. When resources are updated, the existing
    /// resource entitlements are replaced by the new value - i.e. this is not a delta
    /// and it affects all Internet Number Resource (INR) types (IPv4, IPV6, ASN). Setting
    /// resource entitlements beyond the resources held by the parent CA will return
    /// an `Error::CaChildExtraResources`.
    pub async fn ca_child_update(
        &self,
        ca: &Handle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        let (id_opt, resources_opt, suspend_opt) = req.unpack();

        if let Some(id) = id_opt {
            self.send_command(CmdDet::child_update_id(ca, child.clone(), id, actor))
                .await?;
        }
        if let Some(resources) = resources_opt {
            self.send_command(CmdDet::child_update_resources(ca, child.clone(), resources, actor))
                .await?;
        }
        if let Some(suspend) = suspend_opt {
            if suspend {
                self.send_command(CmdDet::child_suspend_inactive(ca, child, actor))
                    .await?;
            } else {
                self.send_command(CmdDet::child_unsuspend(ca, child, actor)).await?;
            }
        }
        Ok(())
    }

    /// Removes a child from this CA. This will also ensure that certificates issued to the child
    /// are revoked and withdrawn.
    pub async fn ca_child_remove(&self, ca: &Handle, child: ChildHandle, actor: &Actor) -> KrillResult<()> {
        self.status_store.lock().await.remove_child(ca, &child).await?;
        self.send_command(CmdDet::child_remove(ca, child, actor)).await?;

        Ok(())
    }

    /// Processes an RFC 6492 request sent to this CA:
    /// - parses the message bytes
    /// - validates the request
    /// - processes the child request
    /// - signs a response and returns the bytes
    pub async fn rfc6492(
        &self,
        ca_handle: &Handle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        let ca = self.get_ca(ca_handle).await?;

        let msg = match ProtocolCms::decode(msg_bytes.as_ref(), false) {
            Ok(msg) => msg,
            Err(e) => {
                let msg = format!(
                    "Could not decode RFC6492 message for: {}, msg: {}, err: {}",
                    ca_handle,
                    Base64::from_content(msg_bytes.as_ref()),
                    e
                );
                return Err(Error::custom(msg));
            }
        };

        let content = ca.verify_rfc6492(msg)?;

        let (child_handle, recipient, content) = content.unpack();

        // If the child was suspended, because it was inactive, then we can now conclude
        // that it's become active again. So unsuspend it first, before processing the request
        // further.
        let child_ca = ca.get_child(&child_handle)?;
        if child_ca.is_suspended() {
            info!(
                "Child '{}' under CA '{}' became active again, will unsuspend it.",
                child_handle, ca_handle
            );
            let req = UpdateChildRequest::unsuspend();
            self.ca_child_update(ca_handle, child_handle.clone(), req, actor)
                .await?;
        }

        let cms_logger = CmsLogger::for_rfc6492_rcvd(self.config.rfc6492_log_dir.as_ref(), &recipient, &child_handle);

        let (res, should_log_cms) = match content {
            rfc6492::Content::Qry(rfc6492::Qry::Revoke(req)) => {
                let res = self.revoke(ca_handle, child_handle.clone(), req, actor).await?;
                let msg = rfc6492::Message::revoke_response(child_handle.clone(), recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg).await, true)
            }
            rfc6492::Content::Qry(rfc6492::Qry::List) => {
                let entitlements = self.list(ca_handle, &child_handle).await?;
                let msg = rfc6492::Message::list_response(child_handle.clone(), recipient, entitlements);
                (self.wrap_rfc6492_response(ca_handle, msg).await, false)
            }
            rfc6492::Content::Qry(rfc6492::Qry::Issue(req)) => {
                let res = self.issue(ca_handle, &child_handle, req, actor).await?;
                let msg = rfc6492::Message::issue_response(child_handle.clone(), recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg).await, true)
            }
            _ => (Err(Error::custom("Unsupported RFC6492 message")), true),
        };

        // Log CMS messages if needed, and if enabled by config (this is a no-op if it isn't)
        match &res {
            Ok(reply_bytes) => {
                if should_log_cms {
                    cms_logger.received(&msg_bytes)?;
                    cms_logger.reply(reply_bytes)?;
                }
            }
            Err(e) => {
                cms_logger.received(&msg_bytes)?;
                cms_logger.err(e)?;
            }
        }

        // Set child status
        match &res {
            Ok(_) => {
                self.status_store
                    .lock()
                    .await
                    .set_child_success(ca.handle(), &child_handle, user_agent)
                    .await?;
            }
            Err(e) => {
                self.status_store
                    .lock()
                    .await
                    .set_child_failure(ca.handle(), &child_handle, user_agent, e)
                    .await?;
            }
        }

        res
    }

    async fn wrap_rfc6492_response(&self, handle: &Handle, msg: rfc6492::Message) -> KrillResult<Bytes> {
        trace!("RFC6492 Response wrapping for {}", handle);
        self.get_ca(handle)
            .await?
            .sign_rfc6492_response(msg, self.signer.deref())
    }

    /// List the entitlements for a child: 3.3.2 of RFC 6492.
    async fn list(&self, ca: &Handle, child: &Handle) -> KrillResult<Entitlements> {
        let ca = self.get_ca(ca).await?;
        Ok(ca.list(child, &self.config.issuance_timing)?)
    }

    /// Issue a Certificate in response to an RFC 6492 Certificate Issuance request sent by a child.
    ///
    /// See: https://tools.ietf.org/html/rfc6492#section3.4.1-2
    async fn issue(
        &self,
        ca: &Handle,
        child: &ChildHandle,
        issue_req: IssuanceRequest,
        actor: &Actor,
    ) -> KrillResult<IssuanceResponse> {
        let class_name = issue_req.class_name();
        let pub_key = issue_req.csr().public_key();

        let cmd = CmdDet::child_certify(
            ca,
            child.clone(),
            issue_req.clone(),
            self.config.clone(),
            self.signer.clone(),
            actor,
        );

        let ca = self.send_command(cmd).await?;

        // The updated CA will now include the newly issued certificate.
        let response = ca.issuance_response(child, class_name, pub_key, &self.config.issuance_timing)?;

        Ok(response)
    }

    /// Process an RFC 6492  revocation request sent by a child.
    /// See: https://tools.ietf.org/html/rfc6492#section3.5.1-2
    async fn revoke(
        &self,
        ca_handle: &Handle,
        child: ChildHandle,
        revoke_request: RevocationRequest,
        actor: &Actor,
    ) -> KrillResult<RevocationResponse> {
        let res = (&revoke_request).into(); // response provided that no errors are returned earlier

        let cmd = CmdDet::child_revoke_key(ca_handle, child, revoke_request, actor);
        self.send_command(cmd).await?;

        Ok(res)
    }
}

/// # CAs as children
///
impl CaManager {
    /// Adds a new parent, or updates an existing parent of a CA. Adding a parent will trigger that the
    /// CA connects to this new parent in order to learn its resource entitlements and set up the resource
    /// class(es) under it, and request certificate(s).
    pub async fn ca_parent_add_or_update(
        &self,
        handle: Handle,
        parent_req: ParentCaReq,
        actor: &Actor,
    ) -> KrillResult<()> {
        let ca = self.get_ca(&handle).await?;

        let (parent, contact) = parent_req.unpack();

        let cmd = if !ca.parent_known(&parent) {
            CmdDet::add_parent(&handle, parent, contact, actor)
        } else {
            CmdDet::update_parent(&handle, parent, contact, actor)
        };

        self.send_command(cmd).await?;
        Ok(())
    }

    /// Removes a parent from a CA, this will trigger that best effort revocations of existing
    /// keys under this parent are requested. Any resource classes under the parent will be removed
    /// and all relevant content will be withdrawn from the repository.
    pub async fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle, actor: &Actor) -> KrillResult<()> {
        // best effort, request revocations for any remaining keys under this parent.
        if let Err(e) = self.ca_parent_revoke(&handle, &parent).await {
            warn!(
                "Removing parent '{}' from CA '{}', but could not send revoke requests: {}",
                parent, handle, e
            );
        }

        self.status_store.lock().await.remove_parent(&handle, &parent).await?;

        let upd = CmdDet::remove_parent(&handle, parent, actor);
        self.send_command(upd).await?;
        Ok(())
    }

    /// Send revocation requests for a parent of a CA when the parent is removed.
    pub async fn ca_parent_revoke(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        let ca = self.get_ca(handle).await?;
        let revoke_requests = ca.revoke_under_parent(parent, &self.signer)?;
        self.send_revoke_requests(handle, parent, revoke_requests).await?;
        Ok(())
    }

    /// Refresh all CAs:
    /// - process all CAs in parallel
    /// - process all parents for CAs in parallel
    ///    - send pending requests if present, or
    ///    - ask parent for updates and process if present
    ///
    /// Note: this function can be called manually through the API, but is normally
    ///       triggered in the background, every 10 mins by default, or as configured
    ///       by 'ca_refresh' in the configuration.
    pub async fn cas_refresh_all(&self, started: Timestamp, actor: &Actor) {
        if let Ok(cas) = self.ca_store.list() {
            let mut updates = vec![];

            for ca_handle in cas {
                updates.push(self.cas_refresh_single(ca_handle, started, actor));
            }

            join_all(updates).await;
        }
    }

    /// Refresh a single CA with its parents, and possibly suspend inactive children.
    pub async fn cas_refresh_single(&self, ca_handle: Handle, started: Timestamp, actor: &Actor) {
        self.ca_sync_parents(&ca_handle, actor).await;
        self.ca_suspend_inactive_children(&ca_handle, started, actor).await;
    }

    /// Suspend child CAs
    async fn ca_suspend_inactive_children(&self, ca_handle: &Handle, started: Timestamp, actor: &Actor) {
        // Set threshold hours if it was configured AND this server has been started
        // longer ago than the hours specified. Otherwise we risk that *all* children
        // without prior recorded status are suspended on upgrade, or that *all* children
        // are suspended if the server had been down for more than the threshold hours.
        let threshold_seconds = self
            .config
            .suspend_child_after_inactive_seconds()
            .filter(|secs| started < Timestamp::now_minus_seconds(*secs));

        // suspend inactive children, if so configured
        if let Some(threshold_seconds) = threshold_seconds {
            if let Ok(ca_status) = self.get_ca_status(ca_handle).await {
                let connections = ca_status.get_children_connection_stats();

                for child in connections.suspension_candidates(threshold_seconds) {
                    let threshold_string = if threshold_seconds >= 3600 {
                        format!("{} hours", threshold_seconds / 3600)
                    } else {
                        format!("{} seconds", threshold_seconds)
                    };

                    info!(
                        "Child '{}' under CA '{}' was inactive for more than {}. Will suspend it.",
                        child, ca_handle, threshold_string
                    );
                    if let Err(e) = self
                        .status_store
                        .lock()
                        .await
                        .set_child_suspended(ca_handle, &child)
                        .await
                    {
                        panic!("System level error encountered while updating ca status: {}", e);
                    }

                    let req = UpdateChildRequest::suspend();
                    if let Err(e) = self.ca_child_update(ca_handle, child, req, actor).await {
                        error!("Could not suspend inactive child, error: {}", e);
                    }
                }
            }
        }
    }

    /// Synchronizes a CA with its parents - up to the configures batch size.
    /// Remaining parents will be done in a future run.
    async fn ca_sync_parents(&self, ca_handle: &Handle, actor: &Actor) {
        let mut updates = vec![];

        if let Ok(ca) = self.get_ca(ca_handle).await {
            // get updates from parents
            {
                if ca.nr_parents() <= self.config.ca_refresh_parents_batch_size {
                    // Nr of parents is below batch size, so just process all of them
                    for parent in ca.parents() {
                        updates.push(self.ca_sync_parent_infallible(ca_handle.clone(), parent.clone(), actor.clone()));
                    }
                } else {
                    // more parents than the batch size exist, so get candidates based on
                    // the known parent statuses for this CA.
                    match self.status_store.lock().await.get_ca_status(ca_handle).await {
                        Err(e) => {
                            panic!("System level error encountered while updating ca status: {}", e);
                        }
                        Ok(status) => {
                            for parent in status
                                .parents()
                                .sync_candidates(ca.parents().collect(), self.config.ca_refresh_parents_batch_size)
                            {
                                updates.push(self.ca_sync_parent_infallible(
                                    ca_handle.clone(),
                                    parent.clone(),
                                    actor.clone(),
                                ));
                            }
                        }
                    };
                }
            }
            join_all(updates).await;
        }
    }

    /// Synchronizes a CA with a parent, logging failures.
    async fn ca_sync_parent_infallible(&self, ca: Handle, parent: ParentHandle, actor: Actor) {
        if let Err(e) = self.ca_sync_parent(&ca, &parent, &actor).await {
            error!(
                "Failed to synchronize CA '{}' with parent '{}'. Error was: {}",
                ca, parent, e
            );
        }
    }

    /// Synchronizes a CA with one of its parents:
    ///   - send pending requests if present; otherwise
    ///   - get and process updated entitlements
    ///
    /// Note: if new request events are generated as a result of processing updated entitlements
    ///       then they will trigger that this synchronization is called again so that the pending
    ///       requests can be sent.
    pub async fn ca_sync_parent(&self, handle: &Handle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> {
        let ca = self.get_ca(handle).await?;

        if ca.has_pending_requests(parent) {
            self.send_requests(handle, parent, actor).await
        } else {
            self.get_updates_from_parent(handle, parent, actor).await
        }
    }

    /// Try to get updates from a specific parent of a CA.
    async fn get_updates_from_parent(&self, handle: &Handle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> {
        if handle != &ta_handle() {
            let ca = self.get_ca(handle).await?;

            if ca.repository_contact().is_ok() {
                let ca = self.get_ca(handle).await?;
                let parent_contact = ca.parent(parent)?;
                let entitlements = self
                    .get_entitlements_from_contact(handle, parent, parent_contact, true)
                    .await?;

                self.update_entitlements(handle, parent.clone(), entitlements, actor)
                    .await?;
            }
        }
        Ok(())
    }

    /// Sends requests to a specific parent for the CA matching handle.
    async fn send_requests(&self, handle: &Handle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> {
        self.send_revoke_requests_handle_responses(handle, parent, actor)
            .await?;
        self.send_cert_requests_handle_responses(handle, parent, actor).await
    }

    async fn send_revoke_requests_handle_responses(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        let child = self.get_ca(handle).await?;
        let requests = child.revoke_requests(parent);

        let revoke_responses = self.send_revoke_requests(handle, parent, requests).await?;

        for (rcn, revoke_responses) in revoke_responses.into_iter() {
            for response in revoke_responses.into_iter() {
                let cmd = CmdDet::key_roll_finish(handle, rcn.clone(), response, actor);
                self.send_command(cmd).await?;
            }
        }

        Ok(())
    }

    pub async fn send_revoke_requests(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let child = self.get_ca(handle).await?;
        match child.parent(parent)? {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),

            ParentCaContact::Rfc6492(parent_res) => {
                let parent_uri = parent_res.service_uri();

                let next_run_seconds = self.config.ca_refresh_seconds as i64;

                match self
                    .send_revoke_requests_rfc6492(revoke_requests, &child.id_key(), parent_res)
                    .await
                {
                    Err(e) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_failure(handle, parent, parent_uri, &e, next_run_seconds)
                            .await?;
                        Err(e)
                    }
                    Ok(res) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_last_updated(handle, parent, parent_uri, next_run_seconds)
                            .await?;
                        Ok(res)
                    }
                }
            }
        }
    }

    pub async fn send_revoke_unexpected_key(
        &self,
        handle: &Handle,
        rcn: ResourceClassName,
        revocation: RevocationRequest,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let child = self.ca_store.get_latest(handle)?;
        let parent = child.parent_for_rc(&rcn)?;
        let mut requests = HashMap::new();
        requests.insert(rcn, vec![revocation]);

        self.send_revoke_requests(handle, parent, requests).await
    }

    async fn send_revoke_requests_rfc6492(
        &self,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        signing_key: &KeyIdentifier,
        parent_res: &rfc8183::ParentResponse,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let mut revoke_map = HashMap::new();

        for (rcn, revoke_requests) in revoke_requests.into_iter() {
            let mut revocations = vec![];
            for req in revoke_requests.into_iter() {
                let sender = parent_res.child_handle().clone();
                let recipient = parent_res.parent_handle().clone();
                let cms_logger = CmsLogger::for_rfc6492_sent(self.config.rfc6492_log_dir.as_ref(), &sender, &recipient);

                let revoke = rfc6492::Message::revoke(sender, recipient, req.clone());

                let response = self
                    .send_rfc6492_and_validate_response(signing_key, parent_res, revoke.into_bytes(), Some(&cms_logger))
                    .await?;

                match response {
                    rfc6492::Res::Revoke(revoke_response) => revocations.push(revoke_response),
                    rfc6492::Res::NotPerformed(e) => {
                        // If we get one of the following responses:
                        //    1301         revoke - no such resource class
                        //    1302         revoke - no such key
                        //
                        // Then we can consider this revocation redundant from the parent side, so just add it
                        // as revoked to this CA and move on. While this may be unexpected this is unlikely to
                        // be a problem. If we would keep insisting that the parent revokes a key they already
                        // revoked, then we can end up in a stuck loop.
                        //
                        // More importantly we should re-sync things if we get 12** errors to certificate sign
                        // requests, but that is done in another function.
                        if e.status() == 1301 || e.status() == 1302 {
                            let revoke_response = (&req).into();
                            revocations.push(revoke_response)
                        } else {
                            return Err(Error::Rfc6492NotPerformed(e));
                        }
                    }
                    rfc6492::Res::List(_) => return Err(Error::custom("Got a List response to revoke request??")),
                    rfc6492::Res::Issue(_) => return Err(Error::custom("Issue response to revoke request??")),
                }
            }

            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
    }

    async fn send_cert_requests_handle_responses(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        let child = self.get_ca(handle).await?;
        let requests = child.cert_requests(parent);
        let signing_key = child.id_key();
        let parent_res = child.parent(parent)?.parent_response().ok_or(Error::TaNotAllowed)?;

        let sender = parent_res.child_handle();
        let recipient = parent_res.parent_handle();
        let cms_logger = Some(CmsLogger::for_rfc6492_sent(
            self.config.rfc6492_log_dir.as_ref(),
            sender,
            recipient,
        ));

        // We may need to do work for multiple resource class and there may therefore be
        // multiple errors. We want to keep track of those, rather than bailing out on the
        // first error, because an issue in one resource class does not necessarily mean
        // that there should be an issue in the the others.
        //
        // Of course for most CAs there will only be one resource class under a parent,
        // but we need to be prepared to deal with N classes.
        let mut errors = vec![];

        for (rcn, requests) in requests.into_iter() {
            // We could have multiple requests in a single resource class (multiple keys during rollover)
            for req in requests {
                let msg = rfc6492::Message::issue(sender.clone(), recipient.clone(), req).into_bytes();

                match self
                    .send_rfc6492_and_validate_response(&signing_key, parent_res, msg, cms_logger.as_ref())
                    .await
                {
                    Err(e) => {
                        // If any of the requests for an RC results in an error, then
                        // record the error and break the loop. We will sync again.
                        errors.push(Error::CaParentSyncError(
                            handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            e.to_string(),
                        ));
                        break;
                    }
                    Ok(response) => {
                        match response {
                            rfc6492::Res::Issue(issuance) => {
                                // Update the received certificate.
                                //
                                // In a typical exchange we will only have one key under an RC under a
                                // parent. During a key roll there may be multiple keys and requests. It
                                // is still fine to update the received certificate for key "A" even if we
                                // would get an error for the request for key "B". The reason is such an
                                // *unlikely* failure would still trigger an appropriate response at
                                // the resource class level in the next loop iteration below.
                                let (_, _, _, issued) = issuance.unwrap();
                                if let Err(e) = self
                                    .send_command(CmdDet::upd_received_cert(
                                        handle,
                                        rcn.clone(),
                                        RcvdCert::from(issued),
                                        self.config.clone(),
                                        self.signer.clone(),
                                        actor,
                                    ))
                                    .await
                                {
                                    // Note that sending the command to update a received certificate
                                    // cannot fail unless there are bigger issues like this being the wrong
                                    // response for this resource class. This would be extremely odd because
                                    // we only just asked the resource class which request to send. Still, in
                                    // order to handle this the most graceful way we can, we should just drop
                                    // this resource class and report an error. If there are are still resource
                                    // entitlements under the parent for this resource class, then a new class
                                    // will be automatically created when we synchronize the entitlements again.

                                    let reason = format!("received certificate cannot be added, error: {}", e);

                                    self.send_command(CmdDet::drop_resource_class(
                                        handle,
                                        rcn.clone(),
                                        reason.clone(),
                                        self.signer.clone(),
                                        actor,
                                    ))
                                    .await?;

                                    // push the error for reporting, this will also trigger that the CA will
                                    // sync with its parent again - and then it will just find revocation
                                    // requests for this RC - which are sent on a best effort basis
                                    errors.push(Error::CaParentSyncError(
                                        handle.clone(),
                                        parent.clone(),
                                        rcn.clone(),
                                        reason,
                                    ));
                                    break;
                                }
                            }
                            rfc6492::Res::NotPerformed(not_performed) => {
                                match not_performed.status() {
                                    1201 | 1202 => {
                                        // Okay, so it looks like the parent *just* told the CA that it was entitled
                                        // to certain resources in a resource class and now in response to certificate
                                        // sign request they say the resource class is gone (1201), or there are no resources
                                        // in it (1202). This can happen as a result of a race condition if the child CA
                                        // was asking the entitlements just moments before the parent removed them.

                                        let reason = "parent removed entitlement to resource class".to_string();

                                        self.send_command(CmdDet::drop_resource_class(
                                            handle,
                                            rcn.clone(),
                                            reason.clone(),
                                            self.signer.clone(),
                                            actor,
                                        ))
                                        .await?;

                                        // push the error for reporting, this will also trigger that the CA will
                                        // sync with its parent again - and then it will just find revocation
                                        // requests for this RC - which are sent on a best effort basis
                                        errors.push(Error::CaParentSyncError(
                                            handle.clone(),
                                            parent.clone(),
                                            rcn.clone(),
                                            reason,
                                        ));
                                        break;
                                    }
                                    1204 => {
                                        // The parent says that the CA is re-using a key across RCs. Krill CAs never
                                        // re-use keys - so this is extremely unlikely. Still there seems to be a
                                        // disagreement and in this case the parent has the last word. Recovering by
                                        // dropping all keys in the RC and making a new pending key should be possible,
                                        // but it's complicated with regards to corner cases: e.g. what if we were in
                                        // the middle of key roll..
                                        //
                                        // So, the most straightforward way to deal with this is by dropping this current
                                        // RC altogether. Then the CA will find its resource entitlements in a future
                                        // synchronization with the parent and just create a new RC - and issue all
                                        // eligible certificates and ROAs under it.

                                        let reason = "parent claims we are re-using keys".to_string();
                                        self.send_command(CmdDet::drop_resource_class(
                                            handle,
                                            rcn.clone(),
                                            reason.clone(),
                                            self.signer.clone(),
                                            actor,
                                        ))
                                        .await?;

                                        // push the error for reporting, this will also trigger that the CA will
                                        // sync with its parent again - and then it will just find revocation
                                        // requests for this RC - which are sent on a best effort basis
                                        errors.push(Error::CaParentSyncError(
                                            handle.clone(),
                                            parent.clone(),
                                            rcn.clone(),
                                            reason,
                                        ));
                                        break;
                                    }
                                    _ => {
                                        // Other not performed responses can be due to temporary issues at the
                                        // parent (e.g. it had an internal error of some kind), or because of
                                        // protocol version mismatches and such (in future maybe?).
                                        //
                                        // In any event we cannot take any action to recover, so just report
                                        // them and let the schedular try to sync with the parent again.
                                        let issue = format!(
                                            "parent returned not performed response to certificate request: {}",
                                            not_performed
                                        );
                                        errors.push(Error::CaParentSyncError(
                                            handle.clone(),
                                            parent.clone(),
                                            rcn.clone(),
                                            issue,
                                        ));
                                        break;
                                    }
                                }
                            }
                            rfc6492::Res::List(_) => {
                                // A list response to certificate sign request??
                                let issue = "parent returned a list response to a certificate request".to_string();
                                errors.push(Error::CaParentSyncError(
                                    handle.clone(),
                                    parent.clone(),
                                    rcn.clone(),
                                    issue,
                                ));
                                break;
                            }
                            rfc6492::Res::Revoke(_) => {
                                // A list response to certificate sign request??
                                let issue = "parent returned a revoke response to a certificate request".to_string();
                                errors.push(Error::CaParentSyncError(
                                    handle.clone(),
                                    parent.clone(),
                                    rcn.clone(),
                                    issue,
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        let uri = parent_res.service_uri();
        if errors.is_empty() {
            self.status_store
                .lock()
                .await
                .set_parent_last_updated(handle, parent, uri, self.config.ca_refresh_seconds as i64)
                .await?;

            Ok(())
        } else {
            let e = if errors.len() == 1 {
                errors.pop().unwrap()
            } else {
                Error::Multiple(errors)
            };

            self.status_store
                .lock()
                .await
                .set_parent_failure(handle, parent, uri, &e, REQUEUE_DELAY_SECONDS)
                .await?;

            Err(e)
        }
    }

    /// Updates the CA resource classes, if entitlements are different from
    /// what the CA currently has under this parent. Returns [`Ok(true)`] in
    /// case there were any updates, implying that there will be open requests
    /// for the parent CA.
    async fn update_entitlements(
        &self,
        handle: &Handle,
        parent: ParentHandle,
        entitlements: Entitlements,
        actor: &Actor,
    ) -> KrillResult<bool> {
        let current_version = self.get_ca(handle).await?.version();

        let update_entitlements_command =
            CmdDet::update_entitlements(handle, parent, entitlements, self.signer.clone(), actor);

        let new_version = self.send_command(update_entitlements_command).await?.version();

        Ok(new_version > current_version)
    }

    pub async fn get_entitlements_from_contact(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
        existing_parent: bool,
    ) -> KrillResult<api::Entitlements> {
        match contact {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),
            ParentCaContact::Rfc6492(res) => {
                let result = self.get_entitlements_rfc6492(ca, res).await;
                let uri = res.service_uri();
                let next_run_seconds = self.config.ca_refresh_seconds as i64;

                match &result {
                    Err(error) => {
                        if existing_parent {
                            // only update the status store with errors for existing parents
                            // otherwise we end up with entries if a new parent is rejected because
                            // of the error.
                            self.status_store
                                .lock()
                                .await
                                .set_parent_failure(ca, parent, uri, error, next_run_seconds)
                                .await?;
                        }
                    }
                    Ok(entitlements) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_entitlements(ca, parent, uri, entitlements, next_run_seconds)
                            .await?;
                    }
                }
                result
            }
        }
    }

    async fn get_entitlements_rfc6492(
        &self,
        handle: &Handle,
        parent_res: &rfc8183::ParentResponse,
    ) -> KrillResult<api::Entitlements> {
        debug!(
            "Getting entitlements for CA '{}' from parent '{}'",
            handle,
            parent_res.parent_handle()
        );

        let child = self.ca_store.get_latest(handle)?;

        // create a list request
        let sender = parent_res.child_handle().clone();
        let recipient = parent_res.parent_handle().clone();

        let list = rfc6492::Message::list(sender, recipient);

        let response = self
            .send_rfc6492_and_validate_response(&child.id_key(), parent_res, list.into_bytes(), None)
            .await?;

        match response {
            rfc6492::Res::NotPerformed(np) => Err(Error::Custom(format!("Not performed: {}", np))),
            rfc6492::Res::List(ent) => Ok(ent),
            _ => Err(Error::custom("Got unexpected response to list query")),
        }
    }

    async fn send_rfc6492_and_validate_response(
        &self,
        signing_key: &KeyIdentifier,
        parent_res: &rfc8183::ParentResponse,
        msg: Bytes,
        cms_logger: Option<&CmsLogger>,
    ) -> KrillResult<rfc6492::Res> {
        let response = self
            .send_protocol_msg_and_validate(
                signing_key,
                parent_res.service_uri(),
                parent_res.id_cert(),
                rfc6492::CONTENT_TYPE,
                msg,
                cms_logger,
            )
            .await?;

        rfc6492::Message::from_signed_message(&response)
            .map_err(Error::custom)?
            .into_reply()
            .map_err(Error::custom)
    }
}

/// # Publishing
///
impl CaManager {
    /// Synchronize all CAs with their repositories. Meant to be called by the background
    /// schedular. This will log issues, but will not fail on errors with individual CAs -
    /// because otherwise this would prevent other CAs from syncing. Note however, that the
    /// repository status is tracked per CA and can be monitored.
    ///
    /// This function can still fail on internal errors, e.g. I/O issues when saving state
    /// changes to the repo status structure.
    pub async fn cas_repo_sync_all(&self, actor: &Actor) {
        match self.ca_list(actor) {
            Ok(ca_list) => {
                for ca in ca_list.cas() {
                    let ca_handle = ca.handle();
                    if let Err(e) = self.cas_repo_sync_single(ca_handle).await {
                        error!(
                            "Could not synchronize CA '{}' with its repository/-ies. Error: {}",
                            ca_handle, e
                        );
                    }
                }
            }
            Err(e) => error!("Could not get CA list! {}", e),
        }
    }

    /// Synchronize a CA with its repositories.
    ///
    /// Note typically a CA will have only one active repository, but in case
    /// there are multiple during a migration, this function will ensure that
    /// they are all synchronized.
    ///
    /// In case the CA had deprecated repositories, then a clean up will be
    /// attempted. I.e. the CA will try to withdraw all objects from the deprecated
    /// repository. If this clean up fails then the number of clean-up attempts
    /// for the repository in question is incremented, and this function will
    /// fail. When there have been 5 failed attempts, then the old repository
    /// is assumed to be unreachable and it will be dropped - i.e. the CA will
    /// no longer try to clean up objects.
    pub async fn cas_repo_sync_single(&self, ca_handle: &Handle) -> KrillResult<()> {
        // Note that this is a no-op for new CAs which do not yet have any repository configured.
        for (repo_contact, ca_elements) in self.ca_repo_elements(ca_handle).await? {
            self.ca_repo_sync(ca_handle, &repo_contact, ca_elements).await?;
        }

        // Clean-up of old repos
        for deprecated in self.ca_deprecated_repos(ca_handle)? {
            info!(
                "Will try to clean up deprecated repository '{}' for CA '{}'",
                deprecated.contact(),
                ca_handle
            );

            if let Err(e) = self.ca_repo_sync(ca_handle, deprecated.contact(), vec![]).await {
                warn!("Could not clean up deprecated repository: {}", e);

                if deprecated.clean_attempts() < 5 {
                    self.ca_deprecated_repo_increment_clean_attempts(ca_handle, deprecated.contact())?;
                    return Err(e);
                }
            }

            self.ca_deprecated_repo_remove(ca_handle, deprecated.contact())?;
        }

        Ok(())
    }

    async fn ca_repo_sync(
        &self,
        ca_handle: &Handle,
        repo_contact: &RepositoryContact,
        publish_elements: Vec<PublishElement>,
    ) -> KrillResult<()> {
        let list_reply = self.send_rfc8181_list(ca_handle, repo_contact.response()).await?;

        #[allow(clippy::mutable_key_type)]
        let delta = {
            let elements: HashMap<_, _> = list_reply.into_elements().into_iter().map(|el| el.unpack()).collect();

            let mut all_objects: HashMap<_, _> = publish_elements.into_iter().map(|el| el.unpack()).collect();

            let mut withdraws = vec![];
            let mut updates = vec![];
            for (uri, hash) in elements.into_iter() {
                match all_objects.remove(&uri) {
                    Some(base64) => {
                        if base64.to_encoded_hash() != hash {
                            updates.push(Update::new(None, uri, base64, hash))
                        }
                    }
                    None => withdraws.push(Withdraw::new(None, uri, hash)),
                }
            }
            let publishes = all_objects
                .into_iter()
                .map(|(uri, base64)| Publish::new(None, uri, base64))
                .collect();

            PublishDelta::new(publishes, updates, withdraws)
        };

        self.send_rfc8181_delta(ca_handle, repo_contact.response(), delta)
            .await?;

        Ok(())
    }

    /// Get the current objects for a CA for each repository that it's using.
    ///
    /// Notes:
    /// - typically a CA will use only one repository, but during migrations there may be multiple.
    /// - these object may not have been published (yet) - check `ca_repo_status`.
    pub async fn ca_repo_elements(&self, ca: &Handle) -> KrillResult<HashMap<RepositoryContact, Vec<PublishElement>>> {
        Ok(self.ca_objects_store.ca_objects(ca)?.repo_elements_map())
    }

    /// Get deprecated repositories so that they can be cleaned.
    pub fn ca_deprecated_repos(&self, ca: &Handle) -> KrillResult<Vec<DeprecatedRepository>> {
        Ok(self.ca_objects_store.ca_objects(ca)?.deprecated_repos().clone())
    }

    /// Remove a deprecated repo
    pub fn ca_deprecated_repo_remove(&self, ca: &Handle, to_remove: &RepositoryContact) -> KrillResult<()> {
        self.ca_objects_store.with_ca_objects(ca, |objects| {
            objects.deprecated_repo_remove(to_remove);
            Ok(())
        })
    }

    /// Increase the clean attempt counter for a deprecated repository
    pub fn ca_deprecated_repo_increment_clean_attempts(
        &self,
        ca: &Handle,
        contact: &RepositoryContact,
    ) -> KrillResult<()> {
        self.ca_objects_store.with_ca_objects(ca, |objects| {
            objects.deprecated_repo_inc_clean_attempts(contact);
            Ok(())
        })
    }

    /// Update repository where a CA publishes.
    pub async fn update_repo(
        &self,
        handle: Handle,
        new_contact: RepositoryContact,
        check_repo: bool,
        actor: &Actor,
    ) -> KrillResult<()> {
        if check_repo {
            // First verify that this repository can be reached and responds to a list request.
            self.send_rfc8181_list(&handle, new_contact.response())
                .await
                .map_err(|e| Error::CaRepoIssue(handle.clone(), e.to_string()))?;
        }
        let cmd = CmdDet::update_repo(&handle, new_contact, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }

    async fn send_rfc8181_list(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
    ) -> KrillResult<ListReply> {
        let uri = repository.service_uri();

        let reply = match self
            .send_rfc8181_and_validate_response(ca_handle, repository, rfc8181::Message::list_query().into_bytes())
            .await
        {
            Err(e) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri.clone(), &e)
                    .await?;
                return Err(e);
            }
            Ok(reply) => reply,
        };

        let next_update = self
            .ca_objects_store
            .ca_objects(ca_handle)?
            .closest_next_update()
            .unwrap_or_else(|| Timestamp::now_plus_hours(self.config.republish_hours()));

        match reply {
            rfc8181::ReplyMessage::ListReply(list_reply) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_success(ca_handle, uri.clone(), next_update)
                    .await?;
                Ok(list_reply)
            }
            rfc8181::ReplyMessage::SuccessReply => {
                let err = Error::custom("Got success reply to list query?!");
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)
                    .await?;
                Err(err)
            }
            rfc8181::ReplyMessage::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)
                    .await?;
                Err(err)
            }
        }
    }

    pub async fn send_rfc8181_delta(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        delta: PublishDelta,
    ) -> KrillResult<()> {
        let message = rfc8181::Message::publish_delta_query(delta);
        let uri = repository.service_uri();

        let reply = match self
            .send_rfc8181_and_validate_response(ca_handle, repository, message.into_bytes())
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri.clone(), &e)
                    .await?;
                return Err(e);
            }
        };

        match reply {
            rfc8181::ReplyMessage::SuccessReply => {
                // Get all the currently published elements in ALL REPOS.
                // TODO: reflect the status for each REPO in the API / UI?
                // We probably should.. though it should be extremely rare and short-lived to
                // have more than one repository.
                let ca_objects = self.ca_objects_store.ca_objects(ca_handle)?;
                let published = ca_objects.all_publish_elements();
                let next_update = ca_objects
                    .closest_next_update()
                    .unwrap_or_else(|| Timestamp::now_plus_hours(self.config.republish_hours()));

                self.status_store
                    .lock()
                    .await
                    .set_status_repo_published(ca_handle, uri.clone(), published, next_update)
                    .await?;
                Ok(())
            }
            rfc8181::ReplyMessage::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)
                    .await?;
                Err(err)
            }
            rfc8181::ReplyMessage::ListReply(_) => {
                let err = Error::custom("Got list reply to delta query?!");
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)
                    .await?;
                Err(err)
            }
        }
    }

    async fn send_rfc8181_and_validate_response(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        msg: Bytes,
    ) -> KrillResult<rfc8181::ReplyMessage> {
        let ca = self.get_ca(ca_handle).await?;

        let cms_logger = CmsLogger::for_rfc8181_sent(self.config.rfc8181_log_dir.as_ref(), ca_handle);

        let response = self
            .send_protocol_msg_and_validate(
                &ca.id_key(),
                repository.service_uri(),
                repository.id_cert(),
                rfc8181::CONTENT_TYPE,
                msg,
                Some(&cms_logger),
            )
            .await?;

        rfc8181::Message::from_signed_message(&response)
            .map_err(Error::custom)?
            .into_reply()
            .map_err(Error::custom)
    }
}

/// # Support sending RFC 6492 and 8181 'protocol' messages, and verifying responses.
///
impl CaManager {
    async fn send_protocol_msg_and_validate(
        &self,
        signing_key: &KeyIdentifier,
        service_uri: &rfc8183::ServiceUri,
        service_id: &IdCert,
        content_type: &str,
        msg: Bytes,
        cms_logger: Option<&CmsLogger>,
    ) -> KrillResult<ProtocolCms> {
        let signed_msg = ProtocolCmsBuilder::create(signing_key, self.signer.deref(), msg)
            .map_err(Error::signer)?
            .as_bytes();

        let uri = service_uri.to_string();

        // check if the uri is for a parent ca under this same krill instance and if so send
        // the request directly. Otherwise post it the request over http (see issue: #791).
        //
        // Note that we only do this here to ensure that we have as much code re-use
        // (and automated testing) as possible. This also ensures that both sides perform
        // signing and validation same as though they would have been on different servers.
        let res = if let Some(parent) = service_uri.local_parent(&self.config.service_uri()) {
            self.rfc6492(
                &parent,
                signed_msg.clone(),
                Some("local-child".to_string()),
                &self.system_actor,
            )
            .await?
        } else {
            let timeout = self.config.post_protocol_msg_timeout_seconds;

            httpclient::post_binary_with_full_ua(&uri, &signed_msg, content_type, timeout)
                .await
                .map_err(Error::HttpClientError)?
        };

        if let Some(logger) = cms_logger {
            logger.sent(&signed_msg)?;
            logger.reply(&res)?;
        }

        // unpack and validate response
        let msg = match ProtocolCms::decode(res.as_ref(), false).map_err(Error::custom) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Could not parse protocol response");
                return Err(e);
            }
        };

        if let Err(e) = msg.validate(service_id) {
            error!("Could not validate protocol response: {}", base64::encode(res.as_ref()));
            return Err(Error::custom(e));
        }

        Ok(msg)
    }
}

/// # Autonomous System Provider Authorization functions
///
impl CaManager {
    /// Show current ASPA definitions for this CA.
    pub async fn ca_aspas_definitions_show(&self, ca: Handle) -> KrillResult<AspaDefinitionList> {
        let ca = self.get_ca(&ca).await?;
        Ok(ca.aspas_definitions_show())
    }

    /// Add a new ASPA definition for this CA and the customer ASN in the update.
    pub async fn ca_aspas_definitions_update(
        &self,
        ca: Handle,
        updates: AspaDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_command(CmdDet::aspas_definitions_update(
            &ca,
            updates,
            self.config.clone(),
            self.signer.clone(),
            actor,
        ))
        .await?;
        Ok(())
    }

    /// Update the ASPA definition for this CA and the customer ASN in the update.
    pub async fn ca_aspas_update_aspa(
        &self,
        ca: Handle,
        customer: AspaCustomer,
        update: AspaProvidersUpdate,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_command(CmdDet::aspas_update_aspa(
            &ca,
            customer,
            update,
            self.config.clone(),
            self.signer.clone(),
            actor,
        ))
        .await?;
        Ok(())
    }
}

/// # Route Authorization functions
///
impl CaManager {
    /// Update the routes authorized by a CA. This will trigger that ROAs
    /// are made in the resource classes that contain the prefixes. If the
    /// update is rejected, e.g. because the CA does not have the necessary
    /// prefixes then an `Error::RoaDeltaError` will be returned.
    /// If the update is successful, new manifest(s) and CRL(s) will be created,
    /// and resynchronization between the CA and its repository will be triggered.
    /// Finally note that ROAs may be issues on a per prefix basis, or aggregated
    /// by ASN based on the defaults or values configured.
    pub async fn ca_routes_update(
        &self,
        ca: Handle,
        updates: RouteAuthorizationUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_command(CmdDet::route_authorizations_update(
            &ca,
            updates,
            self.config.clone(),
            self.signer.clone(),
            actor,
        ))
        .await?;
        Ok(())
    }

    /// Re-issue about to expire objects in all CAs. This is a no-op in case
    /// ROAs do not need re-issuance. If new objects are created they will also
    /// be published (event will trigger that MFT and CRL are also made, and
    /// and the CA in question synchronizes with its repository).
    ///
    /// Note: this does not re-issue delegated CA certificates, because child
    /// CAs are expected to note extended validity eligibility and request
    /// updated certificates themselves.
    pub async fn renew_objects_all(&self, actor: &Actor) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            let cmd = Cmd::new(
                &ca,
                None,
                CmdDet::RouteAuthorizationsRenew(self.config.clone(), self.signer.clone()),
                actor,
            );
            self.send_command(cmd).await?;

            let cmd = Cmd::new(
                &ca,
                None,
                CmdDet::AspasRenew(self.config.clone(), self.signer.clone()),
                actor,
            );
            self.send_command(cmd).await?;
        }
        Ok(())
    }

    /// Force the reissuance of all ROAs in all CAs. This function was added
    /// because we need to re-issue ROAs in Krill 0.9.3 to force that a short
    /// subject CN is used for the EE certificate: i.e. the SKI rather than the
    /// full public key. But there may also be other cases in future where
    /// forcing to re-issue ROAs may be useful.
    pub async fn force_renew_roas_all(&self, actor: &Actor) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            let cmd = Cmd::new(
                &ca,
                None,
                CmdDet::RouteAuthorizationsForceRenew(self.config.clone(), self.signer.clone()),
                actor,
            );
            self.send_command(cmd).await?;
        }
        Ok(())
    }
}

/// # Resource Tagged Attestation functions
///
impl CaManager {
    /// Sign a one-off single-signed RTA
    pub async fn rta_sign(
        &self,
        ca: Handle,
        name: RtaName,
        request: RtaContentRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        let cmd = CmdDet::rta_sign(&ca, name, request, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Prepare a multi-singed RTA
    pub async fn rta_multi_prep(
        &self,
        ca: &Handle,
        name: RtaName,
        request: RtaPrepareRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        let cmd = CmdDet::rta_multi_prep(ca, name, request, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Co-sign an existing RTA
    pub async fn rta_multi_cosign(
        &self,
        ca: Handle,
        name: RtaName,
        rta: ResourceTaggedAttestation,
        actor: &Actor,
    ) -> KrillResult<()> {
        let cmd = CmdDet::rta_multi_sign(&ca, name, rta, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }
}

/// CA Key Roll functions
///
impl CaManager {
    /// Initiate an RFC 6489 key roll for all active keys in a CA older than the specified duration.
    pub async fn ca_keyroll_init(&self, handle: Handle, max_age: Duration, actor: &Actor) -> KrillResult<()> {
        let init_key_roll = CmdDet::key_roll_init(&handle, max_age, self.signer.clone(), actor);
        self.send_command(init_key_roll).await?;
        Ok(())
    }

    /// Activate a new key, as part of the key roll process (RFC 6489). Only new keys that
    /// have an age equal to or greater than the staging period are promoted. The RFC mandates
    /// a staging period of 24 hours, but we may use a shorter period for testing and/or emergency
    /// manual key rolls.
    pub async fn ca_keyroll_activate(&self, handle: Handle, staging: Duration, actor: &Actor) -> KrillResult<()> {
        let activate_cmd = CmdDet::key_roll_activate(&handle, staging, self.config.clone(), self.signer.clone(), actor);
        self.send_command(activate_cmd).await?;
        Ok(())
    }
}
