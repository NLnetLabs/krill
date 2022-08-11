use std::{collections::HashMap, convert::TryFrom, ops::Deref, str::FromStr, sync::Arc};

use bytes::Bytes;
use chrono::Duration;

use rpki::{
    ca::{
        idexchange::{self, ServiceUri},
        idexchange::{CaHandle, ChildHandle, ParentHandle},
        provisioning,
        provisioning::{
            IssuanceRequest, IssuanceResponse, ProvisioningCms, ResourceClassListResponse, ResourceClassName,
            RevocationRequest, RevocationResponse,
        },
        publication,
        publication::{ListReply, Publish, PublishDelta, Update, Withdraw},
    },
    crypto::KeyIdentifier,
    repository::resources::ResourceSet,
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::{
            rrdp::PublishElement, BgpSecCsrInfoList, BgpSecDefinitionUpdates, ParentServerInfo, PublicationServerInfo,
            Timestamp,
        },
        api::{
            AddChildRequest, AspaCustomer, AspaDefinitionList, AspaDefinitionUpdates, AspaProvidersUpdate,
            CaCommandDetails, CaCommandResult, CertAuthList, CertAuthSummary, ChildCaInfo, CommandHistory,
            CommandHistoryCriteria, ParentCaContact, ParentCaReq, ReceivedCert, RepositoryContact, RtaName,
            StoredEffect, UpdateChildRequest,
        },
        crypto::KrillSigner,
        error::Error,
        eventsourcing::{Aggregate, AggregateStore, Command, CommandKey},
        util::{cmslogger::CmsLogger, httpclient},
        KrillResult,
    },
    constants::{CASERVER_DIR, STATUS_DIR},
    daemon::{
        auth::common::permissions::Permission,
        auth::Handle,
        ca::{
            self, ta_handle, CaObjectsStore, CaStatus, CertAuth, Cmd, CmdDet, DeprecatedRepository, IniDet,
            ResourceTaggedAttestation, RouteAuthorizationUpdates, RtaContentRequest, RtaPrepareRequest, StatusStore,
        },
        config::Config,
        mq::{now, TaskQueue},
    },
    pubd::RepositoryManager,
};

//------------ CaLocks ------------------------------------------------------

#[derive(Debug, Default)]
pub struct CaLockMap(HashMap<CaHandle, tokio::sync::RwLock<()>>);

impl CaLockMap {
    fn create_ca_lock(&mut self, ca: CaHandle) {
        self.0.insert(ca, tokio::sync::RwLock::new(()));
    }

    fn has_ca(&self, ca: &CaHandle) -> bool {
        self.0.contains_key(ca)
    }

    fn drop_ca_lock(&mut self, ca: &CaHandle) {
        self.0.remove(ca);
    }
}

pub struct CaLock<'a> {
    map: tokio::sync::RwLockReadGuard<'a, CaLockMap>,
    ca: CaHandle,
}

impl CaLock<'_> {
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.map.0.get(&self.ca).unwrap().read().await
    }

    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
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
    pub async fn ca(&self, ca: CaHandle) -> CaLock<'_> {
        {
            let map = self.locks.read().await;
            if map.has_ca(&ca) {
                return CaLock { map, ca };
            }
        }

        {
            let mut lock = self.locks.write().await;
            lock.create_ca_lock(ca.clone());
        }

        let map = self.locks.read().await;
        CaLock { map, ca }
    }

    async fn drop_ca(&self, ca: &CaHandle) {
        let mut map = self.locks.write().await;
        map.drop_ca_lock(ca);
    }
}

//------------ CaManager -----------------------------------------------------

#[derive(Clone)]
pub struct CaManager {
    ca_store: Arc<AggregateStore<CertAuth>>,
    ca_objects_store: Arc<CaObjectsStore>,
    status_store: Arc<StatusStore>,
    locks: Arc<CaLocks>,

    // shared task queue:
    // - listens for events in the ca_store
    // - processed by the Scheduler
    // - can be used here to schedule tasks through the api
    tasks: Arc<TaskQueue>,

    config: Arc<Config>,
    signer: Arc<KrillSigner>,

    // System actor
    system_actor: Actor,
}

impl CaManager {
    /// Builds a new CaServer. Will return an error if the CA store cannot be initialized.
    pub async fn build(
        config: Arc<Config>,
        tasks: Arc<TaskQueue>,
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
        // for a CA gets copies of all ROAs and issued certificates from the `CertAuth` and is responsible
        // for manifests and CRL generation.
        let ca_objects_store = Arc::new(CaObjectsStore::disk(
            &config.data_dir,
            config.issuance_timing.clone(),
            signer.clone(),
        )?);

        // Register the `CaObjectsStore` as a pre-save listener to the 'ca_store' so that it can update
        // its ROAs and issued certificates and/or generate manifests and CRLs when relevant changes
        // occur in a `CertAuth`.
        ca_store.add_pre_save_listener(ca_objects_store.clone());

        // Register the `MessageQueue` as a post-save listener to 'ca_store' so that relevant changes in
        // a `CertAuth` can trigger follow up actions. Most importantly: synchronize with a parent CA or
        // the RPKI repository.
        ca_store.add_post_save_listener(tasks.clone());

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
            status_store: Arc::new(status_store),
            locks,
            tasks,
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
        let lock = self.locks.ca(ta_handle.clone()).await;
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
        let lock = self.locks.ca(ta_handle.clone()).await;
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
            let repository_response = repo_manager.repository_response(&ta_handle.convert())?;
            let contact = RepositoryContact::for_response(repository_response).map_err(Error::rfc8183)?;

            let upd_repo_cmd = CmdDet::update_repo(&ta_handle, contact, self.signer.clone(), actor);
            self.ca_store.command(upd_repo_cmd)?;

            // make trust anchor
            let make_ta_cmd =
                CmdDet::make_trust_anchor(&ta_handle, ta_uris, ta_aia.clone(), self.signer.clone(), actor);
            let ta = self.ca_store.command(make_ta_cmd)?;

            // receive the self signed cert (now as child of self)
            let rcvd_cert = ta.parent(&ta_handle.convert()).unwrap().to_ta_cert().clone();

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
        let lock = self.locks.ca(cmd.handle().clone()).await;
        let _ = lock.write().await;
        self.ca_store.command(cmd)
    }

    /// Republish the embedded TA and CAs if needed, i.e. if they are close
    /// to their next update time.
    pub async fn republish_all(&self, force: bool) -> KrillResult<Vec<CaHandle>> {
        self.ca_objects_store.reissue_all(force)
    }
}

/// # CA instances and identity
///
impl CaManager {
    /// Initializes a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(&self, handle: &CaHandle) -> KrillResult<()> {
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
    pub async fn ca_update_id(&self, handle: CaHandle, actor: &Actor) -> KrillResult<()> {
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
                .filter(|handle| matches!(actor.is_allowed(Permission::CA_READ, Handle::from(handle)), Ok(true)))
                .map(CertAuthSummary::new)
                .collect(),
        ))
    }

    /// Gets a CA by the given handle, returns an `Err(ServerError::UnknownCA)` if it
    /// does not exist.
    pub async fn get_ca(&self, handle: &CaHandle) -> KrillResult<Arc<CertAuth>> {
        let lock = self.locks.ca(handle.clone()).await;
        let _ = lock.read().await;
        self.ca_store
            .get_latest(handle)
            .map_err(|_| Error::CaUnknown(handle.clone()))
    }

    /// Checks whether a CA by the given handle exists.
    pub fn has_ca(&self, handle: &CaHandle) -> KrillResult<bool> {
        self.ca_store.has(handle).map_err(Error::AggregateStoreError)
    }

    /// Gets current CA status
    pub async fn get_ca_status(&self, ca: &CaHandle) -> KrillResult<CaStatus> {
        if self.has_ca(ca)? {
            Ok(self.status_store.get_ca_status(ca))
        } else {
            Err(Error::CaUnknown(ca.clone()))
        }
    }

    /// Delete a CA. Let it do best effort revocation requests and withdraw
    /// all its objects first. Note that any children of this CA will be left
    /// orphaned, and they will only learn of this sad fact when they choose
    /// to call home.
    pub async fn delete_ca(&self, ca_handle: &CaHandle, actor: &Actor) -> KrillResult<()> {
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
        self.status_store.remove_ca(ca_handle)?;

        self.locks.drop_ca(ca_handle).await;

        Ok(())
    }
}

/// # CA History
///
impl CaManager {
    /// Gets the history for a CA.
    pub async fn ca_history(&self, handle: &CaHandle, crit: CommandHistoryCriteria) -> KrillResult<CommandHistory> {
        let ca_lock = self.locks.ca(handle.clone()).await;
        let _lock = ca_lock.read().await;
        Ok(self.ca_store.command_history(handle, crit)?)
    }

    /// Shows the details for a CA command.
    pub fn ca_command_details(&self, handle: &CaHandle, command: CommandKey) -> KrillResult<CaCommandDetails> {
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
    /// Adds a child under a CA. If the `AddChildRequest` contains resources not held
    /// by this CA, then an `Error::CaChildExtraResources` is returned.
    pub async fn ca_add_child(
        &self,
        ca: &CaHandle,
        req: AddChildRequest,
        service_uri: &uri::Https,
        actor: &Actor,
    ) -> KrillResult<idexchange::ParentResponse> {
        info!("CA '{}' process add child request: {}", &ca, &req);
        let (child_handle, child_res, id_cert) = req.unpack();

        let add_child = CmdDet::child_add(ca, child_handle.clone(), id_cert.into(), child_res, actor);
        self.send_command(add_child).await?;

        self.ca_parent_response(ca, child_handle, service_uri).await
    }

    /// Show details for a child under the CA.
    pub async fn ca_show_child(&self, ca: &CaHandle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        trace!("Finding details for CA: {} under parent: {}", child, ca);
        let ca = self.get_ca(ca).await?;
        ca.get_child(child).map(|details| details.clone().into())
    }

    /// Show a contact for a child.
    pub async fn ca_parent_contact(
        &self,
        ca_handle: &CaHandle,
        child_handle: ChildHandle,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentCaContact> {
        let service_uri = Self::service_uri_for_ca(service_uri, ca_handle);
        let ca = self.get_ca(ca_handle).await?;

        let server_info = ParentServerInfo::new(
            service_uri,
            ca.id_cert().public_key().clone(),
            ca_handle.convert(),
            child_handle,
        );
        Ok(ParentCaContact::for_parent_server_info(server_info))
    }

    /// Gets an RFC8183 Parent Response for the child.
    pub async fn ca_parent_response(
        &self,
        ca_handle: &CaHandle,
        child_handle: ChildHandle,
        service_uri: &uri::Https,
    ) -> KrillResult<idexchange::ParentResponse> {
        let service_uri = Self::service_uri_for_ca(service_uri, ca_handle);
        let ca = self.get_ca(ca_handle).await?;

        Ok(idexchange::ParentResponse::new(
            ca.id_cert().base64().clone(),
            ca.handle().convert(),
            child_handle,
            service_uri,
            None,
        ))
    }

    fn service_uri_for_ca(base_uri: &uri::Https, ca_handle: &CaHandle) -> ServiceUri {
        let service_uri = format!("{}rfc6492/{}", base_uri, ca_handle);
        let service_uri = uri::Https::from_string(service_uri).unwrap();
        ServiceUri::Https(service_uri)
    }

    /// Update a child under this CA. The submitted `UpdateChildRequest` can contain a
    /// new `IdCert`, or `ResourceSet`, or both. When resources are updated, the existing
    /// resource entitlements are replaced by the new value - i.e. this is not a delta
    /// and it affects all Internet Number Resource (INR) types (IPv4, IPV6, ASN). Setting
    /// resource entitlements beyond the resources held by the parent CA will return
    /// an `Error::CaChildExtraResources`.
    pub async fn ca_child_update(
        &self,
        ca: &CaHandle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillResult<()> {
        let (id_opt, resources_opt, suspend_opt) = req.unpack();

        if let Some(id) = id_opt {
            self.send_command(CmdDet::child_update_id(ca, child.clone(), id.into(), actor))
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
    pub async fn ca_child_remove(&self, ca: &CaHandle, child: ChildHandle, actor: &Actor) -> KrillResult<()> {
        self.status_store.remove_child(ca, &child)?;
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
        ca_handle: &CaHandle,
        msg_bytes: Bytes,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<Bytes> {
        let ca = self.get_ca(ca_handle).await?;

        let req_msg = self.rfc6492_unwrap_request(&ca, &msg_bytes)?;

        // Create a logger for CMS (avoid cloning recipient)
        let cms_logger = CmsLogger::for_rfc6492_rcvd(
            self.config.rfc6492_log_dir.as_ref(),
            req_msg.recipient(),
            req_msg.sender(),
        );

        let res_msg = self.rfc6492_process_request(&ca, req_msg, user_agent, actor).await;

        match res_msg {
            Ok(msg) => {
                let should_log_cms = !msg.is_list_response();
                let reply_bytes = ca.sign_rfc6492_response(msg, self.signer.deref())?;

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

    /// Process an rfc6492 message and create an unsigned response
    pub async fn rfc6492_process_request(
        &self,
        ca: &CertAuth,
        req_msg: provisioning::Message,
        user_agent: Option<String>,
        actor: &Actor,
    ) -> KrillResult<provisioning::Message> {
        let (sender, recipient, payload) = req_msg.unpack();

        let child_handle = sender.convert();

        // If the child was suspended, because it was inactive, then we can now conclude
        // that it's become active again. So unsuspend it first, before processing the request
        // further.
        let child_ca = ca.get_child(&child_handle)?;
        if child_ca.is_suspended() {
            info!(
                "Child '{}' under CA '{}' became active again, will unsuspend it.",
                child_handle,
                ca.handle()
            );
            let req = UpdateChildRequest::unsuspend();
            self.ca_child_update(ca.handle(), child_handle.clone(), req, actor)
                .await?;
        }

        let res_msg = match payload {
            provisioning::Payload::Revoke(req) => {
                let res = self.revoke(ca.handle(), child_handle.clone(), req, actor).await?;
                Ok(provisioning::Message::revoke_response(sender, recipient, res))
            }
            provisioning::Payload::List => {
                let entitlements = self.list(ca.handle(), &child_handle).await?;
                Ok(provisioning::Message::list_response(sender, recipient, entitlements))
            }
            provisioning::Payload::Issue(req) => {
                let res = self.issue(ca.handle(), &child_handle, req, actor).await?;
                Ok(provisioning::Message::issue_response(sender, recipient, res))
            }
            _ => Err(Error::custom("Unsupported RFC6492 message")),
        };

        // Set child status
        match &res_msg {
            Ok(_) => {
                self.status_store
                    .set_child_success(ca.handle(), &child_handle, user_agent)?;
            }
            Err(e) => {
                self.status_store
                    .set_child_failure(ca.handle(), &child_handle, user_agent, e)?;
            }
        }

        res_msg
    }

    /// Unpack and validate a request message
    fn rfc6492_unwrap_request(&self, ca: &CertAuth, msg_bytes: &Bytes) -> KrillResult<provisioning::Message> {
        match ProvisioningCms::decode(msg_bytes.as_ref()) {
            Ok(msg) => ca.verify_rfc6492(msg),
            Err(e) => Err(Error::custom(format!(
                "Could not decode RFC6492 message for: {}, err: {}",
                ca.handle(),
                e
            ))),
        }
    }

    /// List the entitlements for a child: 3.3.2 of RFC 6492.
    async fn list(&self, ca: &CaHandle, child: &ChildHandle) -> KrillResult<ResourceClassListResponse> {
        let ca = self.get_ca(ca).await?;
        ca.list(child, &self.config.issuance_timing)
    }

    /// Issue a Certificate in response to an RFC 6492 Certificate Issuance request sent by a child.
    ///
    /// See: https://tools.ietf.org/html/rfc6492#section3.4.1-2
    async fn issue(
        &self,
        ca: &CaHandle,
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

    /// Process an RFC 6492 revocation request sent by a child.
    /// See: https://tools.ietf.org/html/rfc6492#section3.5.1-2
    async fn revoke(
        &self,
        ca_handle: &CaHandle,
        child: ChildHandle,
        revoke_request: RevocationRequest,
        actor: &Actor,
    ) -> KrillResult<RevocationResponse> {
        let res = RevocationResponse::from(&revoke_request); // response provided that no errors are returned earlier

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
        handle: CaHandle,
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
    pub async fn ca_parent_remove(&self, handle: CaHandle, parent: ParentHandle, actor: &Actor) -> KrillResult<()> {
        // best effort, request revocations for any remaining keys under this parent.
        if let Err(e) = self.ca_parent_revoke(&handle, &parent).await {
            warn!(
                "Removing parent '{}' from CA '{}', but could not send revoke requests: {}",
                parent, handle, e
            );
        }

        self.status_store.remove_parent(&handle, &parent)?;

        let upd = CmdDet::remove_parent(&handle, parent, actor);
        self.send_command(upd).await?;
        Ok(())
    }

    /// Send revocation requests for a parent of a CA when the parent is removed.
    pub async fn ca_parent_revoke(&self, handle: &CaHandle, parent: &ParentHandle) -> KrillResult<()> {
        let ca = self.get_ca(handle).await?;
        let revoke_requests = ca.revoke_under_parent(parent, &self.signer)?;
        self.send_revoke_requests(handle, parent, revoke_requests).await?;
        Ok(())
    }

    /// Schedule refreshing all CAs as soon as possible:
    ///
    /// Note: this function can be called manually through the API, but normally the
    ///       CA refresh process is replanned on the task queue automatically.
    pub async fn cas_schedule_refresh_all(&self) {
        if let Ok(cas) = self.ca_store.list() {
            for ca_handle in cas {
                self.cas_schedule_refresh_single(ca_handle).await;
            }
        }
    }

    /// Refresh a single CA with its parents, and possibly suspend inactive children.
    pub async fn cas_schedule_refresh_single(&self, ca_handle: CaHandle) {
        self.ca_schedule_sync_parents(&ca_handle).await;
    }

    /// Schedule check suspending any children under all CAs as soon as possible:
    ///
    /// Note: this function can be called manually through the API, but normally this
    ///       is replanned on the task queue automatically IF suspension is enabled.
    pub fn cas_schedule_suspend_all(&self) {
        if self.config.suspend_child_after_inactive_seconds().is_some() {
            if let Ok(cas) = self.ca_store.list() {
                for ca_handle in cas {
                    self.tasks.suspend_children(ca_handle, now());
                }
            }
        }
    }

    /// Suspend child CAs
    pub async fn ca_suspend_inactive_children(&self, ca_handle: &CaHandle, started: Timestamp, actor: &Actor) {
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
                    if let Err(e) = self.status_store.set_child_suspended(ca_handle, &child) {
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
    async fn ca_schedule_sync_parents(&self, ca_handle: &CaHandle) {
        if let Ok(ca) = self.get_ca(ca_handle).await {
            // get updates from parents
            {
                if ca.nr_parents() <= self.config.ca_refresh_parents_batch_size {
                    // Nr of parents is below batch size, so just process all of them
                    for parent in ca.parents() {
                        self.tasks.sync_parent(ca_handle.clone(), parent.clone(), now());
                    }
                } else {
                    // more parents than the batch size exist, so get candidates based on
                    // the known parent statuses for this CA.
                    let status = self.status_store.get_ca_status(ca_handle);

                    for parent in status
                        .parents()
                        .sync_candidates(ca.parents().collect(), self.config.ca_refresh_parents_batch_size)
                    {
                        self.tasks.sync_parent(ca_handle.clone(), parent, now());
                    }
                }
            }
        }
    }

    /// Synchronizes a CA with one of its parents:
    ///   - send pending requests if present; otherwise
    ///   - get and process updated entitlements
    ///
    /// Note: if new request events are generated as a result of processing updated entitlements
    ///       then they will trigger that this synchronization is called again so that the pending
    ///       requests can be sent.
    pub async fn ca_sync_parent(&self, handle: &CaHandle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> {
        let ca = self.get_ca(handle).await?;

        if ca.has_pending_requests(parent) {
            self.send_requests(handle, parent, actor).await
        } else {
            self.get_updates_from_parent(handle, parent, actor).await
        }
    }

    /// Try to get updates from a specific parent of a CA.
    async fn get_updates_from_parent(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
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
    async fn send_requests(&self, handle: &CaHandle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> {
        self.send_revoke_requests_handle_responses(handle, parent, actor)
            .await?;
        self.send_cert_requests_handle_responses(handle, parent, actor).await
    }

    async fn send_revoke_requests_handle_responses(
        &self,
        handle: &CaHandle,
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
        handle: &CaHandle,
        parent: &ParentHandle,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let child = self.get_ca(handle).await?;
        match child.parent(parent)? {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),

            ParentCaContact::Rfc6492(server_info) => {
                let parent_uri = server_info.service_uri();

                match self
                    .send_revoke_requests_rfc6492(
                        revoke_requests,
                        &child.id_cert().public_key().key_identifier(),
                        server_info,
                    )
                    .await
                {
                    Err(e) => {
                        self.status_store.set_parent_failure(handle, parent, parent_uri, &e)?;
                        Err(e)
                    }
                    Ok(res) => {
                        self.status_store.set_parent_last_updated(handle, parent, parent_uri)?;
                        Ok(res)
                    }
                }
            }
        }
    }

    pub async fn send_revoke_unexpected_key(
        &self,
        handle: &CaHandle,
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
        server_info: &ParentServerInfo,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let mut revoke_map = HashMap::new();

        for (rcn, revoke_requests) in revoke_requests.into_iter() {
            let mut revocations = vec![];
            for req in revoke_requests.into_iter() {
                let sender = server_info.child_handle().convert();
                let recipient = server_info.parent_handle().convert();

                let revoke = provisioning::Message::revoke(sender, recipient, req.clone());

                let response = self
                    .send_rfc6492_and_validate_response(revoke, server_info, signing_key)
                    .await?;

                let payload = response.into_payload();
                let payload_type = payload.payload_type();

                match payload {
                    provisioning::Payload::RevokeResponse(revoke_response) => revocations.push(revoke_response),
                    provisioning::Payload::ErrorResponse(e) => {
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
                    _ => {
                        return Err(Error::custom(format!(
                            "Got unexpected response type '{}' to revoke query",
                            payload_type
                        )))
                    }
                }
            }

            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
    }

    async fn send_cert_requests_handle_responses(
        &self,
        ca_handle: &CaHandle,
        parent: &ParentHandle,
        actor: &Actor,
    ) -> KrillResult<()> {
        let ca = self.get_ca(ca_handle).await?;
        let requests = ca.cert_requests(parent);
        let signing_key = ca.id_cert().public_key().key_identifier();
        let server_info = ca.parent(parent)?.parent_server_info().ok_or(Error::TaNotAllowed)?;

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
                let sender = server_info.child_handle().convert();
                let recipient = server_info.parent_handle().convert();

                let msg = provisioning::Message::issue(sender, recipient, req);

                match self
                    .send_rfc6492_and_validate_response(msg, server_info, &signing_key)
                    .await
                {
                    Err(e) => {
                        // If any of the requests for an RC results in an error, then
                        // record the error and break the loop. We will sync again.
                        errors.push(Error::CaParentSyncError(
                            ca_handle.clone(),
                            parent.clone(),
                            rcn.clone(),
                            e.to_string(),
                        ));
                        break;
                    }
                    Ok(response) => {
                        let payload = response.into_payload();
                        let payload_type = payload.payload_type();

                        match payload {
                            provisioning::Payload::IssueResponse(response) => {
                                // Update the received certificate.
                                //
                                // In a typical exchange we will only have one key under an RC under a
                                // parent. During a key roll there may be multiple keys and requests. It
                                // is still fine to update the received certificate for key "A" even if we
                                // would get an error for the request for key "B". The reason is such an
                                // *unlikely* failure would still trigger an appropriate response at
                                // the resource class level in the next loop iteration below.
                                let issued = response.into_issued();
                                let (uri, limit, cert) = issued.unpack();

                                match ResourceSet::try_from(&cert) {
                                    Err(e) => {
                                        // Cannot get resources from the issued certificate. This should
                                        // never happen, but it would occur if the parent gave us a certificate
                                        // with 'inherited' resources. This may be allowed under RFC 6492,
                                        // or rather.. it's not strictly disallowed as perhaps it should be?
                                        //
                                        // In any case.. report the error - but we do not expect that this
                                        // will happen in the wild.

                                        // push the error for reporting, this will also trigger that the CA will
                                        // sync with its parent again - and then it will just find revocation
                                        // requests for this RC - which are sent on a best effort basis
                                        errors.push(Error::CaParentSyncError(
                                            ca_handle.clone(),
                                            parent.clone(),
                                            rcn.clone(),
                                            format!("cannot parse resources on received certificate, error: {}", e),
                                        ));
                                        break;
                                    }
                                    Ok(resources) => {
                                        match ReceivedCert::create(cert, uri, resources, limit) {
                                            Err(e) => {
                                                errors.push(Error::CaParentSyncError(
                                                    ca_handle.clone(),
                                                    parent.clone(),
                                                    rcn.clone(),
                                                    format!("cannot use issued certificate, error: {}", e),
                                                ));
                                                break;
                                            }
                                            Ok(rcvd_cert) => {
                                                if let Err(e) = self
                                                    .send_command(CmdDet::upd_received_cert(
                                                        ca_handle,
                                                        rcn.clone(),
                                                        rcvd_cert,
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

                                                    let reason =
                                                        format!("cannot process received certificate! error: {}", e);

                                                    self.send_command(CmdDet::drop_resource_class(
                                                        ca_handle,
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
                                                        ca_handle.clone(),
                                                        parent.clone(),
                                                        rcn.clone(),
                                                        reason,
                                                    ));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            provisioning::Payload::ErrorResponse(not_performed) => {
                                match not_performed.status() {
                                    1201 | 1202 => {
                                        // Okay, so it looks like the parent *just* told the CA that it was entitled
                                        // to certain resources in a resource class and now in response to certificate
                                        // sign request they say the resource class is gone (1201), or there are no resources
                                        // in it (1202). This can happen as a result of a race condition if the child CA
                                        // was asking the entitlements just moments before the parent removed them.

                                        let reason = "parent removed entitlement to resource class".to_string();

                                        self.send_command(CmdDet::drop_resource_class(
                                            ca_handle,
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
                                            ca_handle.clone(),
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
                                            ca_handle,
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
                                            ca_handle.clone(),
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
                                            ca_handle.clone(),
                                            parent.clone(),
                                            rcn.clone(),
                                            issue,
                                        ));
                                        break;
                                    }
                                }
                            }
                            _ => {
                                let issue =
                                    format!("unexpected response type '{}' to a certificate request", payload_type);
                                errors.push(Error::CaParentSyncError(
                                    ca_handle.clone(),
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

        let uri = server_info.service_uri();
        if errors.is_empty() {
            self.status_store.set_parent_last_updated(ca_handle, parent, uri)?;

            Ok(())
        } else {
            let e = if errors.len() == 1 {
                errors.pop().unwrap()
            } else {
                Error::Multiple(errors)
            };

            self.status_store.set_parent_failure(ca_handle, parent, uri, &e)?;

            Err(e)
        }
    }

    /// Updates the CA resource classes, if entitlements are different from
    /// what the CA currently has under this parent. Returns [`Ok(true)`] in
    /// case there were any updates, implying that there will be open requests
    /// for the parent CA.
    async fn update_entitlements(
        &self,
        ca: &CaHandle,
        parent: ParentHandle,
        entitlements: ResourceClassListResponse,
        actor: &Actor,
    ) -> KrillResult<bool> {
        let current_version = self.get_ca(ca).await?.version();

        let update_entitlements_command =
            CmdDet::update_entitlements(ca, parent, entitlements, self.signer.clone(), actor);

        let new_version = self.send_command(update_entitlements_command).await?.version();

        Ok(new_version > current_version)
    }

    pub async fn get_entitlements_from_contact(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
        existing_parent: bool,
    ) -> KrillResult<ResourceClassListResponse> {
        match contact {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),
            ParentCaContact::Rfc6492(server_info) => {
                let result = self.get_entitlements_rfc6492(ca, server_info).await;
                let uri = server_info.service_uri();

                match &result {
                    Err(error) => {
                        if existing_parent {
                            // only update the status store with errors for existing parents
                            // otherwise we end up with entries if a new parent is rejected because
                            // of the error.
                            self.status_store.set_parent_failure(ca, parent, uri, error)?;
                        }
                    }
                    Ok(entitlements) => {
                        self.status_store
                            .set_parent_entitlements(ca, parent, uri, entitlements)?;
                    }
                }
                result
            }
        }
    }

    async fn get_entitlements_rfc6492(
        &self,
        handle: &CaHandle,
        server_info: &ParentServerInfo,
    ) -> KrillResult<ResourceClassListResponse> {
        debug!(
            "Getting entitlements for CA '{}' from parent '{}'",
            handle,
            server_info.parent_handle()
        );

        let child = self.ca_store.get_latest(handle)?;

        // create a list request
        let sender = server_info.child_handle().convert();
        let recipient = server_info.parent_handle().convert();

        let list = provisioning::Message::list(sender, recipient);

        let response = self
            .send_rfc6492_and_validate_response(list, server_info, &child.id_cert().public_key().key_identifier())
            .await?;

        let payload = response.into_payload();
        let payload_type = payload.payload_type();

        match payload {
            provisioning::Payload::ErrorResponse(np) => Err(Error::Custom(format!("Not performed: {}", np))),
            provisioning::Payload::ListResponse(response) => Ok(response),
            _ => Err(Error::custom(format!(
                "Got unexpected response type '{}' to list query",
                payload_type
            ))),
        }
    }

    async fn send_rfc6492_and_validate_response(
        &self,
        message: provisioning::Message,
        server_info: &ParentServerInfo,
        signing_key: &KeyIdentifier,
    ) -> KrillResult<provisioning::Message> {
        let service_uri = server_info.service_uri();
        if let Some(parent) = Self::local_parent(service_uri, &self.config.service_uri()) {
            let parent_handle = CaHandle::new(parent.into_name());
            let parent = self.get_ca(&parent_handle).await?;
            let user_agent = Some("local-child".to_string());

            self.rfc6492_process_request(&parent, message, user_agent, &self.system_actor)
                .await
        } else {
            // Set up a logger for CMS exchanges. Note that this logger is always set
            // up and used, but.. it will only actually save files in case the given
            // rfc6492_log_dir is Some.
            let cms_logger = CmsLogger::for_rfc6492_sent(
                self.config.rfc6492_log_dir.as_ref(),
                message.sender(),
                message.recipient(),
            );

            let cms = self.signer.create_rfc6492_cms(message, signing_key)?.to_bytes();

            let res_bytes = self
                .post_protocol_cms_binary(&cms, service_uri, provisioning::CONTENT_TYPE, &cms_logger)
                .await?;

            match ProvisioningCms::decode(&res_bytes) {
                Err(e) => {
                    cms_logger.err(format!("Could not decode CMS: {}", e))?;
                    Err(Error::Rfc6492(e))
                }
                Ok(cms) => match cms.validate(server_info.public_key()) {
                    Err(e) => {
                        cms_logger.err(format!("Response invalid: {}", e))?;
                        Err(Error::Rfc6492(e))
                    }
                    Ok(()) => Ok(cms.into_message()),
                },
            }
        }
    }

    async fn post_protocol_cms_binary(
        &self,
        msg: &Bytes,
        service_uri: &ServiceUri,
        content_type: &str,
        cms_logger: &CmsLogger,
    ) -> KrillResult<Bytes> {
        cms_logger.sent(msg)?;

        let timeout = self.config.post_protocol_msg_timeout_seconds;

        match httpclient::post_binary_with_full_ua(service_uri.as_str(), msg, content_type, timeout).await {
            Err(e) => {
                cms_logger.err(format!("Error posting CMS: {}", e))?;
                Err(Error::HttpClientError(e))
            }
            Ok(bytes) => {
                cms_logger.reply(&bytes)?;
                Ok(bytes)
            }
        }
    }

    /// Returns the handle of the local parent for this specific ServiceUri, and the
    /// configured base (service) URI. Provided that this indeed maps back to this
    /// same server and it is an RFC 6492 style Krill URI.
    pub fn local_parent(service_uri: &ServiceUri, base_uri: &uri::Https) -> Option<ParentHandle> {
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
    /// Schedule synchronizing all CAs with their repositories.
    pub fn cas_schedule_repo_sync_all(&self, actor: &Actor) {
        match self.ca_list(actor) {
            Ok(ca_list) => {
                for ca in ca_list.cas() {
                    self.cas_schedule_repo_sync(ca.handle().clone());
                }
            }
            Err(e) => error!("Could not get CA list! {}", e),
        }
    }

    /// Schedule synchronizing all CAs with their repositories.
    pub fn cas_schedule_repo_sync(&self, ca: CaHandle) {
        self.tasks.sync_repo(ca, now());
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
    pub async fn cas_repo_sync_single(&self, ca_handle: &CaHandle) -> KrillResult<()> {
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

    #[allow(clippy::mutable_key_type)]
    async fn ca_repo_sync(
        &self,
        ca_handle: &CaHandle,
        repo_contact: &RepositoryContact,
        publish_elements: Vec<PublishElement>,
    ) -> KrillResult<()> {
        debug!("CA '{}' sends list query to repo", ca_handle);
        let list_reply = self.send_rfc8181_list(ca_handle, repo_contact.server_info()).await?;

        let elements: HashMap<_, _> = list_reply.into_elements().into_iter().map(|el| el.unpack()).collect();

        let mut all_objects: HashMap<_, _> = publish_elements.into_iter().map(|el| el.unpack()).collect();

        let mut delta = PublishDelta::empty();

        for (uri, hash) in elements.into_iter() {
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
            self.send_rfc8181_delta(ca_handle, repo_contact.server_info(), delta)
                .await?;
            debug!("CA '{}' sent delta", ca_handle);
        } else {
            debug!("CA '{}' empty delta - nothing to publish", ca_handle);
        }

        Ok(())
    }

    /// Get the current objects for a CA for each repository that it's using.
    ///
    /// Notes:
    /// - typically a CA will use only one repository, but during migrations there may be multiple.
    /// - these object may not have been published (yet) - check `ca_repo_status`.
    pub async fn ca_repo_elements(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<HashMap<RepositoryContact, Vec<PublishElement>>> {
        Ok(self.ca_objects_store.ca_objects(ca)?.repo_elements_map())
    }

    /// Get deprecated repositories so that they can be cleaned.
    pub fn ca_deprecated_repos(&self, ca: &CaHandle) -> KrillResult<Vec<DeprecatedRepository>> {
        Ok(self.ca_objects_store.ca_objects(ca)?.deprecated_repos().clone())
    }

    /// Remove a deprecated repo
    pub fn ca_deprecated_repo_remove(&self, ca: &CaHandle, to_remove: &RepositoryContact) -> KrillResult<()> {
        self.ca_objects_store.with_ca_objects(ca, |objects| {
            objects.deprecated_repo_remove(to_remove);
            Ok(())
        })
    }

    /// Increase the clean attempt counter for a deprecated repository
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

    /// Update repository where a CA publishes.
    pub async fn update_repo(
        &self,
        ca: CaHandle,
        new_contact: RepositoryContact,
        check_repo: bool,
        actor: &Actor,
    ) -> KrillResult<()> {
        if check_repo {
            // First verify that this repository can be reached and responds to a list request.
            self.send_rfc8181_list(&ca, new_contact.server_info())
                .await
                .map_err(|e| Error::CaRepoIssue(ca.clone(), e.to_string()))?;
        }
        let cmd = CmdDet::update_repo(&ca, new_contact, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }

    async fn send_rfc8181_list(
        &self,
        ca_handle: &CaHandle,
        server_info: &PublicationServerInfo,
    ) -> KrillResult<ListReply> {
        let uri = server_info.service_uri();
        let ca = self.get_ca(ca_handle).await?;
        let signing_key = ca.id_cert().public_key().key_identifier();

        let message = publication::Message::list_query();

        let reply = match self
            .send_rfc8181_and_validate_response(message, server_info, ca_handle, &signing_key)
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store.set_status_repo_failure(ca_handle, uri.clone(), &e)?;
                return Err(e);
            }
        };

        let next_update = self
            .ca_objects_store
            .ca_objects(ca_handle)?
            .closest_next_update()
            .unwrap_or_else(|| Timestamp::now_plus_hours(self.config.republish_hours()));

        match reply {
            publication::Reply::List(list_reply) => {
                self.status_store
                    .set_status_repo_success(ca_handle, uri.clone(), next_update)?;
                Ok(list_reply)
            }
            publication::Reply::Success => {
                let err = Error::custom("Got success reply to list query?!");
                self.status_store
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)?;
                Err(err)
            }
            publication::Reply::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)?;
                Err(err)
            }
        }
    }

    pub async fn send_rfc8181_delta(
        &self,
        ca_handle: &CaHandle,
        server_info: &PublicationServerInfo,
        delta: PublishDelta,
    ) -> KrillResult<()> {
        let uri = server_info.service_uri();
        let ca = self.get_ca(ca_handle).await?;
        let signing_key = ca.id_cert().public_key().key_identifier();

        let message = publication::Message::delta(delta);

        let reply = match self
            .send_rfc8181_and_validate_response(message, server_info, ca_handle, &signing_key)
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store.set_status_repo_failure(ca_handle, uri.clone(), &e)?;
                return Err(e);
            }
        };

        match reply {
            publication::Reply::Success => {
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
                    .set_status_repo_published(ca_handle, uri.clone(), published, next_update)?;
                Ok(())
            }
            publication::Reply::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                self.status_store
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)?;
                Err(err)
            }
            publication::Reply::List(_) => {
                let err = Error::custom("Got list reply to delta query?!");
                self.status_store
                    .set_status_repo_failure(ca_handle, uri.clone(), &err)?;
                Err(err)
            }
        }
    }

    async fn send_rfc8181_and_validate_response(
        &self,
        message: publication::Message,
        server_info: &PublicationServerInfo,
        ca_handle: &CaHandle,
        signing_key: &KeyIdentifier,
    ) -> KrillResult<publication::Reply> {
        // TODO: support local repository without http calls, but this CaManager does not
        //       have access to the repository, so this is a bit more complicated than the
        //       rfc6492 case..
        let service_uri = server_info.service_uri();

        // Set up a logger for CMS exchanges. Note that this logger is always set
        // up and used, but.. it will only actually save files in case the given
        // rfc8181_log_dir is Some.
        let cms_logger = CmsLogger::for_rfc8181_sent(self.config.rfc8181_log_dir.as_ref(), ca_handle);

        let cms = self.signer.create_rfc8181_cms(message, signing_key)?.to_bytes();

        let res_bytes = self
            .post_protocol_cms_binary(&cms, service_uri, publication::CONTENT_TYPE, &cms_logger)
            .await?;

        match publication::PublicationCms::decode(&res_bytes) {
            Err(e) => {
                cms_logger.err(format!("Could not decode CMS: {}", e))?;
                Err(Error::Rfc8181(e))
            }
            Ok(cms) => match cms.validate(server_info.public_key()) {
                Err(e) => {
                    cms_logger.err(format!("Response invalid: {}", e))?;
                    Err(Error::Rfc8181(e))
                }
                Ok(()) => cms.into_message().as_reply().map_err(Error::Rfc8181),
            },
        }
    }
}

/// # Autonomous System Provider Authorization functions
///
impl CaManager {
    /// Show current ASPA definitions for this CA.
    pub async fn ca_aspas_definitions_show(&self, ca: CaHandle) -> KrillResult<AspaDefinitionList> {
        let ca = self.get_ca(&ca).await?;
        Ok(ca.aspas_definitions_show())
    }

    /// Add a new ASPA definition for this CA and the customer ASN in the update.
    pub async fn ca_aspas_definitions_update(
        &self,
        ca: CaHandle,
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
        ca: CaHandle,
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

/// # BGPSec functions
///
impl CaManager {
    pub async fn ca_bgpsec_definitions_show(&self, ca: CaHandle) -> KrillResult<BgpSecCsrInfoList> {
        let ca = self.get_ca(&ca).await?;
        Ok(ca.bgpsec_definitions_show())
    }

    pub async fn ca_bgpsec_definitions_update(
        &self,
        ca: CaHandle,
        updates: BgpSecDefinitionUpdates,
        actor: &Actor,
    ) -> KrillResult<()> {
        self.send_command(CmdDet::bgpsec_update_definitions(
            &ca,
            updates,
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
        ca: CaHandle,
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
    /// Note: this does not re-issue issued CA certificates, because child
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

            if let Err(e) = self.send_command(cmd).await {
                error!("Renewing ROAs for CA '{}' failed with error: {}", ca, e);
            }

            let cmd = Cmd::new(
                &ca,
                None,
                CmdDet::AspasRenew(self.config.clone(), self.signer.clone()),
                actor,
            );

            if let Err(e) = self.send_command(cmd).await {
                error!("Renewing ASPAs for CA '{}' failed with error: {}", ca, e);
            }

            let cmd = Cmd::new(
                &ca,
                None,
                CmdDet::BgpSecRenew(self.config.clone(), self.signer.clone()),
                actor,
            );

            if let Err(e) = self.send_command(cmd).await {
                error!("Renewing BGPSec certificates for CA '{}' failed with error: {}", ca, e);
            }
        }
        Ok(())
    }

    /// Force the re-issuance of all ROAs in all CAs. This function was added
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
            if let Err(e) = self.send_command(cmd).await {
                error!("Renewing ROAs for CA '{}' failed with error: {}", ca, e);
            }
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
        ca: CaHandle,
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
        ca: &CaHandle,
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
        ca: CaHandle,
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
    pub async fn ca_keyroll_init(&self, handle: CaHandle, max_age: Duration, actor: &Actor) -> KrillResult<()> {
        let init_key_roll = CmdDet::key_roll_init(&handle, max_age, self.signer.clone(), actor);
        self.send_command(init_key_roll).await?;
        Ok(())
    }

    /// Activate a new key, as part of the key roll process (RFC 6489). Only new keys that
    /// have an age equal to or greater than the staging period are promoted. The RFC mandates
    /// a staging period of 24 hours, but we may use a shorter period for testing and/or emergency
    /// manual key rolls.
    pub async fn ca_keyroll_activate(&self, handle: CaHandle, staging: Duration, actor: &Actor) -> KrillResult<()> {
        let activate_cmd = CmdDet::key_roll_activate(&handle, staging, self.config.clone(), self.signer.clone(), actor);
        self.send_command(activate_cmd).await?;
        Ok(())
    }
}
