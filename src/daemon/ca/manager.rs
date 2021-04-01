use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use api::{Publish, Update, Withdraw};
use futures::future::join_all;
use tokio::sync::Mutex;

use bytes::Bytes;
use chrono::Duration;

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::{
    commons::{
        actor::Actor,
        api::rrdp::PublishElement,
        api::{
            self, AddChildRequest, Base64, CaCommandDetails, CaCommandResult, CertAuthList, CertAuthSummary,
            ChildCaInfo, ChildHandle, CommandHistory, CommandHistoryCriteria, Entitlements, Handle, IssuanceRequest,
            IssuanceResponse, IssuedCert, ListReply, ParentCaContact, ParentCaReq, ParentHandle, ParentStatuses,
            PublishDelta, RcvdCert, RepoStatus, RepositoryContact, ResourceClassName, ResourceSet, RevocationRequest,
            RevocationResponse, RtaName, StoredEffect, UpdateChildRequest,
        },
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
            self, ta_handle, CaObjectsStore, CertAuth, Cmd, CmdDet, IniDet, ResourceTaggedAttestation,
            RouteAuthorizationUpdates, RtaContentRequest, RtaPrepareRequest, StatusStore,
        },
        config::Config,
        mq::MessageQueue,
    },
    pubd::RepositoryManager,
};

use super::DeprecatedRepository;

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
}

impl CaManager {
    /// Builds a new CaServer. Will return an error if the CA store cannot be initialized.
    pub async fn build(config: Arc<Config>, mq: Arc<MessageQueue>, signer: Arc<KrillSigner>) -> KrillResult<Self> {
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
        let ca_objects_store = Arc::new(CaObjectsStore::disk(config.clone(), signer.clone())?);

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
            Err(Error::TaAlreadyInitialised)
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
            let make_ta_cmd = CmdDet::make_trust_anchor(&ta_handle, ta_uris, self.signer.clone(), actor);
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
            if let Err(e) = self.ca_parent_revoke(ca_handle, &parent).await {
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
        self.locks.drop_ca(ca_handle).await;
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
        self.ca_store
            .command_history(handle, crit)
            .map_err(|_| Error::CaUnknown(handle.clone()))
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
        let (child_handle, child_res, request) = req.unpack();
        let (tag, _, id_cert) = request.unpack();

        let add_child = CmdDet::child_add(&ca, child_handle.clone(), id_cert, child_res, actor);
        self.send_command(add_child).await?;

        self.ca_parent_contact(ca, child_handle, tag, service_uri).await
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
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentCaContact> {
        let response = self
            .ca_parent_response(ca_handle, child_handle, tag, service_uri)
            .await?;
        Ok(ParentCaContact::for_rfc6492(response))
    }

    /// Gets an RFC8183 Parent Response for the child.
    pub async fn ca_parent_response(
        &self,
        ca: &Handle,
        child_handle: ChildHandle,
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> KrillResult<rfc8183::ParentResponse> {
        let ca = self.get_ca(ca).await?;
        let service_uri = format!("{}rfc6492/{}", service_uri.to_string(), ca.handle());
        let service_uri = uri::Https::from_string(service_uri).unwrap();
        let service_uri = rfc8183::ServiceUri::Https(service_uri);

        Ok(rfc8183::ParentResponse::new(
            tag,
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
        let (id_opt, resources_opt) = req.unpack();

        if let Some(id) = id_opt {
            self.send_command(CmdDet::child_update_id(ca, child.clone(), id, actor))
                .await?;
        }
        if let Some(resources) = resources_opt {
            self.send_command(CmdDet::child_update_resources(ca, child, resources, actor))
                .await?;
        }
        Ok(())
    }

    /// Removes a child from this CA. This will also ensure that certificates issued to the child
    /// are revoked and withdrawn.
    pub async fn ca_child_remove(&self, ca: &Handle, child: ChildHandle, actor: &Actor) -> KrillResult<()> {
        self.send_command(CmdDet::child_remove(ca, child, actor)).await?;
        Ok(())
    }

    /// Processes an RFC 6492 request sent to this CA:
    /// - parses the message bytes
    /// - validates the request
    /// - processes the child request
    /// - signs a response and returns the bytes
    pub async fn rfc6492(&self, ca_handle: &Handle, msg_bytes: Bytes, actor: &Actor) -> KrillResult<Bytes> {
        let ca = self.get_ca(ca_handle).await?;

        let msg = match ProtocolCms::decode(msg_bytes.clone(), false) {
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

        let (child, recipient, content) = content.unpack();

        let cms_logger = CmsLogger::for_rfc6492_rcvd(self.config.rfc6492_log_dir.as_ref(), &recipient, &child);

        let (res, should_log_cms) = match content {
            rfc6492::Content::Qry(rfc6492::Qry::Revoke(req)) => {
                let res = self.revoke(ca_handle, child.clone(), req, actor).await?;
                let msg = rfc6492::Message::revoke_response(child, recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg).await, true)
            }
            rfc6492::Content::Qry(rfc6492::Qry::List) => {
                let entitlements = self.list(ca_handle, &child).await?;
                let msg = rfc6492::Message::list_response(child, recipient, entitlements);
                (self.wrap_rfc6492_response(ca_handle, msg).await, false)
            }
            rfc6492::Content::Qry(rfc6492::Qry::Issue(req)) => {
                let res = self.issue(ca_handle, &child, req, actor).await?;
                let msg = rfc6492::Message::issue_response(child, recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg).await, true)
            }
            _ => (Err(Error::custom("Unsupported RFC6492 message")), true),
        };

        match &res {
            Ok(reply_bytes) => {
                if should_log_cms {
                    cms_logger.received(&msg_bytes)?;
                    cms_logger.reply(&reply_bytes)?;
                }
            }
            Err(e) => {
                cms_logger.received(&msg_bytes)?;
                cms_logger.err(e)?;
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
        let response = ca.issuance_response(child, &class_name, pub_key, &self.config.issuance_timing)?;

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
    /// Adds a parent to a CA. This will trigger that the CA connects to this new parent
    /// in order to learn its resource entitlements and set up the resource class(es) under
    /// this parent, and request certificate(s).
    pub async fn ca_parent_add(&self, handle: Handle, parent: ParentCaReq, actor: &Actor) -> KrillResult<()> {
        let (parent_handle, parent_contact) = parent.unpack();

        let add = CmdDet::add_parent(&handle, parent_handle, parent_contact, actor);
        self.send_command(add).await?;
        Ok(())
    }

    /// Updates a parent of a CA, this can be used to update the service uri and/or
    /// identity certificate for an existing parent.
    pub async fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
        actor: &Actor,
    ) -> KrillResult<()> {
        let upd = CmdDet::update_parent(&handle, parent, contact, actor);
        self.send_command(upd).await?;
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

        let upd = CmdDet::remove_parent(&handle, parent, actor);
        self.send_command(upd).await?;
        Ok(())
    }

    /// Send revocation requests for a parent of a CA when the parent is removed.
    pub async fn ca_parent_revoke(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        let ca = self.get_ca(&handle).await?;
        let revoke_requests = ca.revoke_under_parent(&parent, &self.signer)?;
        self.send_revoke_requests(&handle, &parent, revoke_requests).await?;
        Ok(())
    }

    /// Returns the parent statuses for this CA.
    pub async fn ca_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> {
        if self.ca_store.has(ca)? {
            self.status_store.lock().await.get_parent_statuses(ca).await
        } else {
            Err(Error::CaUnknown(ca.clone()))
        }
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
    pub async fn cas_refresh_all(&self, actor: &Actor) {
        if let Ok(cas) = self.ca_store.list() {
            let mut updates = vec![];

            for ca_handle in cas {
                if let Ok(ca) = self.get_ca(&ca_handle).await {
                    for parent in ca.parents() {
                        updates.push(self.ca_sync_parent_infallible(ca_handle.clone(), parent.clone(), actor.clone()));
                    }
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
            self.send_requests(&handle, parent, actor).await
        } else {
            self.get_updates_from_parent(&handle, &parent, actor).await
        }
    }

    /// Try to get updates from a specific parent of a CA.
    async fn get_updates_from_parent(&self, handle: &Handle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> {
        if handle == &ta_handle() {
            Ok(()) // The (test) TA never needs updates.
        } else {
            let ca = self.get_ca(&handle).await?;

            let next_run_seconds = self.config.ca_refresh as i64;

            match ca.repository_contact() {
                Ok(contact) => {
                    let uri = contact.uri();
                    match self.get_entitlements_from_parent(handle, parent).await {
                        Err(e) => {
                            self.status_store
                                .lock()
                                .await
                                .set_parent_failure(handle, parent, uri, &e, next_run_seconds)
                                .await?;
                            Err(e)
                        }
                        Ok(entitlements) => {
                            self.status_store
                                .lock()
                                .await
                                .set_parent_entitlements(handle, parent, uri, &entitlements, next_run_seconds)
                                .await?;
                            if !self
                                .update_entitlements(handle, parent.clone(), entitlements, actor)
                                .await?
                            {
                                return Ok(()); // Nothing to do
                            }

                            Ok(()) // Pending requests will be picked up by the scheduler.
                        }
                    }
                }
                Err(_) => Ok(()),
            }
        }
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
                let uri = parent_res.service_uri().to_string();

                let next_run_seconds = self.config.ca_refresh as i64;

                match self
                    .send_revoke_requests_rfc6492(revoke_requests, &child.id_key(), parent_res)
                    .await
                {
                    Err(e) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_failure(handle, parent, uri, &e, next_run_seconds)
                            .await?;
                        Err(e)
                    }
                    Ok(res) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_last_updated(handle, parent, uri, next_run_seconds)
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
                    .send_rfc6492_and_validate_response(signing_key, parent_res, revoke.into_bytes(), Some(cms_logger))
                    .await?;

                match response {
                    rfc6492::Res::Revoke(revoke_response) => revocations.push(revoke_response),
                    rfc6492::Res::NotPerformed(e) => return Err(Error::Rfc6492NotPerformed(e)),
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
        let cert_requests = child.cert_requests(parent);

        let issued_certs = match child.parent(parent)? {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),

            ParentCaContact::Rfc6492(parent_res) => {
                let uri = parent_res.service_uri().to_string();
                match self
                    .send_cert_requests_rfc6492(cert_requests, &child.id_key(), &parent_res)
                    .await
                {
                    Err(e) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_failure(handle, parent, uri, &e, REQUEUE_DELAY_SECONDS)
                            .await?;
                        Err(e)
                    }
                    Ok(res) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_last_updated(handle, parent, uri, self.config.ca_refresh as i64)
                            .await?;
                        Ok(res)
                    }
                }
            }
        }?;

        for (class_name, issued_certs) in issued_certs.into_iter() {
            for issued in issued_certs.into_iter() {
                self.send_command(CmdDet::upd_received_cert(
                    handle,
                    class_name.clone(),
                    RcvdCert::from(issued),
                    self.config.clone(),
                    self.signer.clone(),
                    actor,
                ))
                .await?;
            }
        }

        Ok(())
    }

    async fn send_cert_requests_rfc6492(
        &self,
        requests: HashMap<ResourceClassName, Vec<IssuanceRequest>>,
        signing_key: &KeyIdentifier,
        parent_res: &rfc8183::ParentResponse,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<IssuedCert>>> {
        let mut issued_map = HashMap::new();

        for (rcn, requests) in requests.into_iter() {
            let mut issued_certs = vec![];

            for req in requests.into_iter() {
                let sender = parent_res.child_handle().clone();
                let recipient = parent_res.parent_handle().clone();

                let cms_logger = CmsLogger::for_rfc6492_sent(self.config.rfc6492_log_dir.as_ref(), &sender, &recipient);

                let issue = rfc6492::Message::issue(sender, recipient, req);

                let response = self
                    .send_rfc6492_and_validate_response(signing_key, parent_res, issue.into_bytes(), Some(cms_logger))
                    .await?;

                match response {
                    rfc6492::Res::NotPerformed(e) => return Err(Error::Rfc6492NotPerformed(e)),
                    rfc6492::Res::Issue(issue_response) => {
                        let (_, _, _, issued) = issue_response.unwrap();
                        issued_certs.push(issued);
                    }
                    rfc6492::Res::List(_) => return Err(Error::custom("List reply to issue request??")),
                    rfc6492::Res::Revoke(_) => return Err(Error::custom("Revoke reply to issue request??")),
                }
            }

            issued_map.insert(rcn, issued_certs);
        }

        Ok(issued_map)
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

    async fn get_entitlements_from_parent(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> KrillResult<api::Entitlements> {
        let ca = self.get_ca(&handle).await?;
        let contact = ca.parent(parent)?;
        self.get_entitlements_from_contact(handle, contact).await
    }

    pub async fn get_entitlements_from_contact(
        &self,
        handle: &Handle,
        contact: &ParentCaContact,
    ) -> KrillResult<api::Entitlements> {
        match contact {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),
            ParentCaContact::Rfc6492(res) => self.get_entitlements_rfc6492(handle, res).await,
        }
    }

    async fn get_entitlements_rfc6492(
        &self,
        handle: &Handle,
        parent_res: &rfc8183::ParentResponse,
    ) -> KrillResult<api::Entitlements> {
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
        cms_logger: Option<CmsLogger>,
    ) -> KrillResult<rfc6492::Res> {
        let response = self
            .send_procotol_msg_and_validate(
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
                    if let Err(e) = self.ca_repo_sync_all(ca_handle).await {
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
    pub async fn ca_repo_sync_all(&self, ca_handle: &Handle) -> KrillResult<()> {
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

            if let Err(e) = self.ca_repo_sync(ca_handle, &deprecated.contact(), vec![]).await {
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
    pub async fn update_repo(&self, handle: Handle, new_contact: RepositoryContact, actor: &Actor) -> KrillResult<()> {
        let cmd = CmdDet::update_repo(&handle, new_contact, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Returns the RepoStatus for a CA, this includes the last connection time and result, and the
    /// objects currently known to be published.
    ///
    /// NOTE: This contains the status of the **CURRENT** repository only. It could be extended to
    /// include the status of the old repository during a migration.
    pub async fn ca_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> {
        let lock = self.locks.ca(ca).await;
        let _ = lock.read().await;
        if self.ca_store.has(ca)? {
            self.status_store.lock().await.get_repo_status(ca).await
        } else {
            Err(Error::CaUnknown(ca.clone()))
        }
    }

    /// Update the RepoStatus for a CA.
    pub async fn ca_repo_status_set_elements(&self, ca: &Handle) -> KrillResult<()> {
        let published = self.ca_objects_store.ca_objects(ca)?.all_publish_elements();
        let next_hours = self.config.issuance_timing.timing_publish_next_hours;

        self.status_store
            .lock()
            .await
            .set_status_repo_published(ca, "embedded".to_string(), published, next_hours)
            .await?;

        Ok(())
    }

    pub async fn send_rfc8181_list(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
    ) -> KrillResult<ListReply> {
        let uri = repository.service_uri().to_string();

        let reply = match self
            .send_rfc8181_and_validate_response(ca_handle, repository, rfc8181::Message::list_query().into_bytes())
            .await
        {
            Err(e) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri, &e)
                    .await?;
                return Err(e);
            }
            Ok(reply) => reply,
        };

        match reply {
            rfc8181::ReplyMessage::ListReply(list_reply) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_success(ca_handle, uri, self.config.republish_hours())
                    .await?;
                Ok(list_reply)
            }
            rfc8181::ReplyMessage::SuccessReply => {
                let err = Error::custom("Got success reply to list query?!");
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri, &err)
                    .await?;
                Err(err)
            }
            rfc8181::ReplyMessage::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri, &err)
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
        let uri = repository.service_uri().to_string();

        let reply = match self
            .send_rfc8181_and_validate_response(ca_handle, repository, message.into_bytes())
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri, &e)
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
                let published = self.ca_objects_store.ca_objects(ca_handle)?.all_publish_elements();

                self.status_store
                    .lock()
                    .await
                    .set_status_repo_published(ca_handle, uri, published, self.config.republish_hours())
                    .await?;
                Ok(())
            }
            rfc8181::ReplyMessage::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri, &err)
                    .await?;
                Err(err)
            }
            rfc8181::ReplyMessage::ListReply(_) => {
                let err = Error::custom("Got list reply to delta query?!");
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_failure(ca_handle, uri, &err)
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
            .send_procotol_msg_and_validate(
                &ca.id_key(),
                repository.service_uri(),
                repository.id_cert(),
                rfc8181::CONTENT_TYPE,
                msg,
                Some(cms_logger),
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
    async fn send_procotol_msg_and_validate(
        &self,
        signing_key: &KeyIdentifier,
        service_uri: &rfc8183::ServiceUri,
        service_id: &IdCert,
        content_type: &str,
        msg: Bytes,
        cms_logger: Option<CmsLogger>,
    ) -> KrillResult<ProtocolCms> {
        let signed_msg = ProtocolCmsBuilder::create(signing_key, self.signer.deref(), msg)
            .map_err(Error::signer)?
            .as_bytes();

        let uri = service_uri.to_string();

        let res = httpclient::post_binary(&uri, &signed_msg, content_type)
            .await
            .map_err(Error::HttpClientError)?;

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

    /// Re-issue about to expire ROAs in all CAs. This is a no-op in case
    /// ROAs do not need re-issuance. If new ROAs are created they will also
    /// be published (event will trigger that MFT and CRL are also made, and
    /// and the CA in question synchronizes with its repository).
    pub async fn renew_roas_all(&self, actor: &Actor) -> KrillResult<()> {
        for ca in self.ca_store.list()? {
            let cmd = Cmd::new(
                &ca,
                None,
                CmdDet::RouteAuthorizationsRenew(self.config.clone(), self.signer.clone()),
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
        let activate_cmd = CmdDet::key_roll_activate(&handle, staging, self.signer.clone(), actor);
        self.send_command(activate_cmd).await?;
        Ok(())
    }
}
