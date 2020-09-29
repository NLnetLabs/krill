use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use bytes::Bytes;
use chrono::Duration;

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::commons::api::{
    self, AddChildRequest, Base64, CaCommandDetails, CaCommandResult, CertAuthList, CertAuthSummary, ChildAuthRequest,
    ChildCaInfo, ChildHandle, CommandHistory, CommandHistoryCriteria, Entitlements, Handle, IssuanceRequest,
    IssuanceResponse, IssuedCert, ListReply, ParentCaContact, ParentCaReq, ParentHandle, ParentStatuses, PublishDelta,
    RcvdCert, RepoInfo, RepoStatus, RepositoryContact, ResourceClassName, ResourceSet, RevocationRequest,
    RevocationResponse, RtaName, StoredEffect, UpdateChildRequest,
};
use crate::commons::crypto::{IdCert, KrillSigner, ProtocolCms, ProtocolCmsBuilder};
use crate::commons::error::Error;
use crate::commons::eventsourcing::{Aggregate, AggregateStore, Command, CommandKey, DiskAggregateStore};
use crate::commons::remote::cmslogger::CmsLogger;
use crate::commons::remote::{rfc6492, rfc8181, rfc8183};
use crate::commons::util::httpclient;
use crate::commons::{KrillEmptyResult, KrillResult};
use crate::constants::{CASERVER_DIR, STATUS_DIR};
use crate::daemon::ca::{
    self, ta_handle, CertAuth, Cmd, CmdDet, IniDet, ResourceTaggedAttestation, RouteAuthorizationUpdates,
    RtaContentRequest, RtaPrepareRequest, StatusStore,
};
use crate::daemon::mq::EventQueueListener;

//------------ CaServer ------------------------------------------------------

pub struct CaLockMap(HashMap<Handle, tokio::sync::RwLock<()>>);

impl CaLockMap {
    fn create_ca_lock(&mut self, ca: &Handle) {
        self.0.insert(ca.clone(), tokio::sync::RwLock::new(()));
    }

    fn has_ca(&self, ca: &Handle) -> bool {
        self.0.contains_key(ca)
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
}

//------------ CaServer ------------------------------------------------------

#[derive(Clone)]
pub struct CaServer {
    signer: Arc<KrillSigner>,
    ca_store: Arc<DiskAggregateStore<CertAuth>>,
    locks: Arc<CaLocks>,
    status_store: Arc<Mutex<StatusStore>>,
    rfc8181_log_dir: Option<PathBuf>,
    rfc6492_log_dir: Option<PathBuf>,
}

impl CaServer {
    /// Builds a new CaServer. Will return an error if the TA store cannot be
    /// initialised.
    pub async fn build(
        work_dir: &PathBuf,
        rfc8181_log_dir: Option<&PathBuf>,
        rfc6492_log_dir: Option<&PathBuf>,
        events_queue: Arc<EventQueueListener>,
        signer: KrillSigner,
    ) -> KrillResult<Self> {
        let mut ca_store = DiskAggregateStore::<CertAuth>::new(work_dir, CASERVER_DIR)?;
        if let Err(e) = ca_store.warm() {
            error!(
                "Could not warm up cache, data seems corrupt. Will try to recover!! Error was: {}",
                e
            );
            ca_store.recover()?;
        }
        ca_store.add_listener(events_queue);

        let status_store = StatusStore::new(work_dir, STATUS_DIR)?;

        let locks = Arc::new(CaLocks::default());

        let signer = Arc::new(signer);

        Ok(CaServer {
            signer,
            ca_store: Arc::new(ca_store),
            locks,
            status_store: Arc::new(Mutex::new(status_store)),
            rfc6492_log_dir: rfc6492_log_dir.cloned(),
            rfc8181_log_dir: rfc8181_log_dir.cloned(),
        })
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub async fn get_trust_anchor(&self) -> KrillResult<Arc<CertAuth>> {
        let ta_handle = ca::ta_handle();
        let lock = self.locks.ca(&ta_handle).await;
        let _ = lock.read().await;
        self.ca_store.get_latest(&ta_handle).map_err(Error::AggregateStoreError)
    }

    /// Initialises an embedded trust anchor with all resources.
    pub async fn init_ta(&self, info: RepoInfo, ta_aia: uri::Rsync, ta_uris: Vec<uri::Https>) -> KrillResult<()> {
        let ta_handle = ca::ta_handle();
        let lock = self.locks.ca(&ta_handle).await;
        let _ = lock.write().await;
        if self.ca_store.has(&ta_handle) {
            Err(Error::TaAlreadyInitialised)
        } else {
            // init normal CA
            let init = IniDet::init(&ta_handle, self.signer.deref())?;
            self.ca_store.add(init)?;

            // add embedded repo
            let embedded = RepositoryContact::embedded(info);
            let upd_repo_cmd = CmdDet::update_repo(&ta_handle, embedded, self.signer.clone());
            self.ca_store.command(upd_repo_cmd)?;

            // make trust anchor
            let make_ta_cmd = CmdDet::make_trust_anchor(&ta_handle, ta_uris, self.signer.clone());
            let ta = self.ca_store.command(make_ta_cmd)?;

            // receive the self signed cert (now as child of self)
            let ta_cert = ta.parent(&ta_handle).unwrap().to_ta_cert();
            let rcvd_cert = RcvdCert::new(ta_cert.clone(), ta_aia, ResourceSet::all_resources());

            let rcv_cert =
                CmdDet::upd_received_cert(&ta_handle, ResourceClassName::default(), rcvd_cert, self.signer.clone());
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
    pub async fn republish_all(&self) -> KrillResult<()> {
        for ca in self.ca_list().await.cas() {
            if let Err(e) = self.republish(ca.handle()).await {
                error!("ServerError publishing: {}, ServerError: {}", ca.handle(), e)
            }
        }
        Ok(())
    }

    /// Republish a CA, this is a no-op when there is nothing to publish.
    pub async fn republish(&self, handle: &Handle) -> KrillResult<()> {
        let cmd = CmdDet::publish(handle, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Update repository where a CA publishes.
    pub async fn update_repo(&self, handle: Handle, new_contact: RepositoryContact) -> KrillResult<()> {
        let cmd = CmdDet::update_repo(&handle, new_contact, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Clean up old repo, if present.
    pub async fn remove_old_repo(&self, handle: &Handle) -> KrillResult<()> {
        let ca = self.get_ca(handle).await?;

        if ca.has_old_repo() {
            info!("Removing old repository after receiving updated certificate");
            let cmd = CmdDet::remove_old_repo(handle, self.signer.clone());
            self.send_command(cmd).await?;
        }
        Ok(())
    }

    /// Returns the RepoStatus for a CA
    pub async fn ca_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> {
        let lock = self.locks.ca(ca).await;
        let _ = lock.read().await;
        if self.ca_store.has(ca) {
            self.status_store.lock().await.get_repo_status(ca).await
        } else {
            Err(Error::CaUnknown(ca.clone()))
        }
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub async fn resync_all(&self) {
        if let Err(e) = self.get_updates_for_all_cas().await {
            error!("Failed to refresh CA certificates: {}", e);
        }
    }

    /// Adds a child under an embedded CA
    pub async fn ca_add_child(
        &self,
        parent: &ParentHandle,
        req: AddChildRequest,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentCaContact> {
        info!("CA '{}' process add child request: {}", &parent, &req);
        let (child_handle, child_res, child_auth) = req.unwrap();

        let id_cert = match &child_auth {
            ChildAuthRequest::Embedded => None,
            ChildAuthRequest::Rfc8183(req) => Some(req.id_cert().clone()),
        };

        let add_child = CmdDet::child_add(&parent, child_handle.clone(), id_cert, child_res);
        self.send_command(add_child).await?;

        let tag = match child_auth {
            ChildAuthRequest::Rfc8183(req) => req.tag().cloned(),
            _ => None,
        };

        self.ca_parent_contact(parent, child_handle, tag, service_uri).await
    }

    /// Show a contact for a child. Shows "embedded" if the parent does not know any id cert for the child.
    pub async fn ca_parent_contact(
        &self,
        parent: &ParentHandle,
        child_handle: ChildHandle,
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> KrillResult<ParentCaContact> {
        let ca = self.get_ca(parent).await?;
        let child = ca.get_child(&child_handle)?;
        if child.id_cert().is_some() {
            let response = self.ca_parent_response(parent, child_handle, tag, service_uri).await?;
            Ok(ParentCaContact::for_rfc6492(response))
        } else {
            Ok(ParentCaContact::Embedded)
        }
    }

    /// Gets an RFC8183 Parent Response for the child, regardless of whether the parent knows the ID certificate
    /// for this child. Note: a child can be updated and an ID cert can be added at all times.
    pub async fn ca_parent_response(
        &self,
        parent: &ParentHandle,
        child_handle: ChildHandle,
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> KrillResult<rfc8183::ParentResponse> {
        let ca = self.get_ca(parent).await?;
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

    /// Show details for a child under the TA.
    pub async fn ca_show_child(&self, parent: &ParentHandle, child: &ChildHandle) -> KrillResult<ChildCaInfo> {
        trace!("Finding details for CA: {} under parent: {}", child, parent);
        let ca = self.get_ca(parent).await?;
        ca.get_child(child).map(|details| details.clone().into())
    }

    /// Update a child under this CA.
    pub async fn ca_child_update(
        &self,
        handle: &Handle,
        child: ChildHandle,
        req: UpdateChildRequest,
    ) -> KrillResult<()> {
        let (id_opt, resources_opt) = req.unpack();

        if (id_opt.is_some() && resources_opt.is_some()) || (id_opt.is_none() && resources_opt.is_none()) {
            Err(Error::CaChildUpdateOneThing(handle.clone(), child))
        } else if let Some(id) = id_opt {
            self.send_command(CmdDet::child_update_id(handle, child, id)).await?;
            Ok(())
        } else {
            let resources = resources_opt.unwrap();
            self.send_command(CmdDet::child_update_resources(handle, child, resources))
                .await?;
            Ok(())
        }
    }

    /// Update a child under this CA.
    pub async fn ca_child_remove(&self, handle: &Handle, child: ChildHandle) -> KrillResult<()> {
        let signer = self.signer.clone();
        self.send_command(CmdDet::child_remove(handle, child, signer)).await?;
        Ok(())
    }
}

/// # CA support
///
impl CaServer {
    /// Gets a CA by the given handle, returns an `Err(ServerError::UnknownCA)` if it
    /// does not exist.
    pub async fn get_ca(&self, handle: &Handle) -> KrillResult<Arc<CertAuth>> {
        let lock = self.locks.ca(handle).await;
        let _ = lock.read().await;
        self.ca_store
            .get_latest(handle)
            .map_err(|_| Error::CaUnknown(handle.clone()))
    }

    /// Gets the history for a CA.
    pub async fn get_ca_history(&self, handle: &Handle, crit: CommandHistoryCriteria) -> KrillResult<CommandHistory> {
        let ca_lock = self.locks.ca(handle).await;
        let _lock = ca_lock.read().await;
        self.ca_store
            .command_history(handle, crit)
            .map_err(|_| Error::CaUnknown(handle.clone()))
    }

    /// Archive old (eligible) commands for CA
    pub async fn archive_ca_commands(&self, days: i64) -> KrillEmptyResult {
        for ca in self.ca_list().await.cas() {
            let lock = self.locks.ca(ca.handle()).await;
            let _ = lock.write().await;
            self.ca_store.archive_old_commands(ca.handle(), days)?;
        }
        Ok(())
    }

    /// Shows the details for a CA command
    pub fn get_ca_command_details(
        &self,
        handle: &Handle,
        command: CommandKey,
    ) -> KrillResult<Option<CaCommandDetails>> {
        if let Some(command) = self.ca_store.stored_command(handle, &command)? {
            let effect = command.effect().clone();
            match effect {
                StoredEffect::Error(msg) => Ok(Some(CaCommandDetails::new(command, CaCommandResult::error(msg)))),
                StoredEffect::Events(versions) => {
                    let mut stored_events = vec![];
                    for version in versions {
                        let evt = self.ca_store.stored_event(handle, version)?.ok_or_else(|| {
                            Error::Custom(format!("Cannot find evt: {} in history for CA: {}", version, handle))
                        })?;
                        stored_events.push(evt);
                    }

                    Ok(Some(CaCommandDetails::new(
                        command,
                        CaCommandResult::events(stored_events),
                    )))
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Checks whether a CA by the given handle exists.
    pub async fn has_ca(&self, handle: &Handle) -> bool {
        self.ca_store.has(handle)
    }

    /// Processes an RFC6492 sent to this CA.
    pub async fn rfc6492(&self, ca_handle: &Handle, msg_bytes: Bytes) -> KrillResult<Bytes> {
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

        let cms_logger = CmsLogger::for_rfc6492_rcvd(self.rfc6492_log_dir.as_ref(), &recipient, &child);

        let (res, should_log_cms) = match content {
            rfc6492::Content::Qry(rfc6492::Qry::Revoke(req)) => {
                let res = self.revoke(ca_handle, child.clone(), req).await?;
                let msg = rfc6492::Message::revoke_response(child, recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg).await, true)
            }
            rfc6492::Content::Qry(rfc6492::Qry::List) => {
                let entitlements = self.list(ca_handle, &child).await?;
                let msg = rfc6492::Message::list_response(child, recipient, entitlements);
                (self.wrap_rfc6492_response(ca_handle, msg).await, false)
            }
            rfc6492::Content::Qry(rfc6492::Qry::Issue(req)) => {
                let res = self.issue(ca_handle, &child, req).await?;
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

    /// List the entitlements for a child: 3.3.2 of RFC6492
    pub async fn list(&self, parent: &Handle, child: &Handle) -> KrillResult<Entitlements> {
        let ca = self.get_ca(parent).await?;
        Ok(ca.list(child)?)
    }

    /// Issue a Certificate in response to a Certificate Issuance request
    ///
    /// See: https://tools.ietf.org/html/rfc6492#section3.4.1-2
    pub async fn issue(
        &self,
        parent: &Handle,
        child: &ChildHandle,
        issue_req: IssuanceRequest,
    ) -> KrillResult<IssuanceResponse> {
        let class_name = issue_req.class_name();
        let pub_key = issue_req.csr().public_key();

        let cmd = CmdDet::child_certify(parent, child.clone(), issue_req.clone(), self.signer.clone());

        let ca = self.send_command(cmd).await?;

        // The updated CA will now include the newly issued certificate.
        let response = ca.issuance_response(child, &class_name, pub_key)?;

        Ok(response)
    }

    /// See: https://tools.ietf.org/html/rfc6492#section3.5.1-2
    pub async fn revoke(
        &self,
        ca_handle: &Handle,
        child: ChildHandle,
        revoke_request: RevocationRequest,
    ) -> KrillResult<RevocationResponse> {
        let res = (&revoke_request).into(); // response provided that no errors are returned earlier

        let cmd = CmdDet::child_revoke_key(ca_handle, child, revoke_request, self.signer.clone());
        self.send_command(cmd).await?;

        Ok(res)
    }

    /// Get the current CAs
    pub async fn ca_list(&self) -> CertAuthList {
        CertAuthList::new(self.ca_store.list().into_iter().map(CertAuthSummary::new).collect())
    }

    /// Initialises a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(&self, handle: &Handle) -> KrillResult<()> {
        if handle == &ta_handle() || handle.as_str() == "version" {
            Err(Error::TaNameReserved)
        } else if self.ca_store.has(handle) {
            Err(Error::CaDuplicate(handle.clone()))
        } else {
            let init = IniDet::init(handle, self.signer.deref())?;
            self.ca_store.add(init)?;
            Ok(())
        }
    }

    pub async fn ca_update_id(&self, handle: Handle) -> KrillResult<()> {
        let cmd = CmdDet::update_id(&handle, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Adds a parent to a CA
    pub async fn ca_parent_add(&self, handle: Handle, parent: ParentCaReq) -> KrillResult<()> {
        let (parent_handle, parent_contact) = parent.unpack();

        let add = CmdDet::add_parent(&handle, parent_handle, parent_contact);
        self.send_command(add).await?;
        Ok(())
    }

    /// Updates a parent of a CA
    pub async fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> KrillResult<()> {
        let upd = CmdDet::update_parent(&handle, parent, contact);
        self.send_command(upd).await?;
        Ok(())
    }

    /// Removes a parent from a CA
    pub async fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle) -> KrillResult<()> {
        let upd = CmdDet::remove_parent(&handle, parent);
        self.send_command(upd).await?;
        Ok(())
    }

    /// Returns the parent statuses for this CA
    pub async fn ca_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> {
        if self.ca_store.has(ca) {
            self.status_store.lock().await.get_parent_statuses(ca).await
        } else {
            Err(Error::CaUnknown(ca.clone()))
        }
    }

    /// Perform a key roll for all active keys in a CA older than the specified duration.
    pub async fn ca_keyroll_init(&self, handle: Handle, max_age: Duration) -> KrillResult<()> {
        let init_key_roll = CmdDet::key_roll_init(&handle, max_age, self.signer.clone());
        self.send_command(init_key_roll).await?;
        Ok(())
    }

    /// Activate a new key, as part of the key roll process (RFC6489). Only new keys that
    /// have an age equal to or greater than the staging period are promoted. The RFC mandates
    /// a staging period of 24 hours, but we may use a shorter period for testing and/or emergency
    /// manual key rolls.
    pub async fn ca_keyroll_activate(&self, handle: Handle, staging: Duration) -> KrillResult<()> {
        let activate_cmd = CmdDet::key_roll_activate(&handle, staging, self.signer.clone());
        self.send_command(activate_cmd).await?;
        Ok(())
    }

    /// Try to get updates for all embedded CAs, will skip the TA and/or CAs that
    /// have no parents. Will try to process all and log possible errors, i.e. do
    /// not bail out because of issues with one CA.
    pub async fn get_updates_for_all_cas(&self) -> KrillResult<()> {
        for handle in self.ca_store.list() {
            if let Ok(ca) = self.get_ca(&handle).await {
                for parent in ca.parents() {
                    if let Err(e) = self.get_updates_from_parent(&handle, &parent).await {
                        error!("Failed to refresh CA certificates for {}, error: {}", &handle, e);
                    } else {
                        info!("Synchronised CA '{}' with parent '{}'", &handle, &parent);
                    }
                }
            }
        }

        Ok(())
    }

    /// Try to get update for parents, if they were delayed because there was no repository configured
    /// when they were added
    pub async fn get_delayed_updates(&self, ca_handle: &Handle) -> KrillResult<()> {
        if ca_handle == &ta_handle() {
            Ok(()) // The (test) TA never needs updates.
        } else {
            let ca = self.get_ca(ca_handle).await?;
            // If this is the first time the repo was configured, then the current resources will be
            // empty and certs should now be requested from parents. If there *are* current resources,
            // then there was a repository, and new certificates have already been requested for the
            // new repository as part of the update repository process. So, in that case we do *not*
            // need to request anything now.
            if ca.all_resources().is_empty() {
                for parent in ca.parents() {
                    self.get_updates_from_parent(ca_handle, parent).await?;
                }
            }
            Ok(())
        }
    }

    /// Try to update a specific CA
    pub async fn get_updates_from_parent(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        if handle == &ta_handle() {
            Ok(()) // The (test) TA never needs updates.
        } else {
            let ca = self.get_ca(&handle).await?;

            match ca.get_repository_contact() {
                Ok(contact) => {
                    let uri = contact.uri();
                    match self.get_entitlements_from_parent(handle, parent).await {
                        Err(e) => {
                            self.status_store
                                .lock()
                                .await
                                .set_parent_failure(handle, parent, uri, &e)
                                .await?;
                            Err(e)
                        }
                        Ok(entitlements) => {
                            self.status_store
                                .lock()
                                .await
                                .set_parent_entitlements(handle, parent, uri, &entitlements)
                                .await?;
                            if !self
                                .update_resource_classes(handle, parent.clone(), entitlements)
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
    pub async fn send_requests(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        self.send_revoke_requests_handle_responses(handle, parent).await?;
        self.send_cert_requests_handle_responses(handle, parent).await
    }

    /// Sends requests to all parents for the CA matching the handle.
    pub async fn send_all_requests(&self, handle: &Handle) -> KrillResult<()> {
        let ca = self.get_ca(handle).await?;

        for parent in ca.parents() {
            self.send_requests(handle, parent).await?;
        }

        Ok(())
    }

    async fn send_revoke_requests_handle_responses(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        let child = self.get_ca(handle).await?;
        let requests = child.revoke_requests(parent);

        let revoke_responses = self.send_revoke_requests(handle, parent, requests).await?;

        for (rcn, revoke_responses) in revoke_responses.into_iter() {
            for response in revoke_responses.into_iter() {
                let cmd = CmdDet::key_roll_finish(handle, rcn.clone(), response);
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
            ParentCaContact::Embedded => {
                self.send_revoke_requests_embedded(revoke_requests, handle, parent)
                    .await
            }
            ParentCaContact::Rfc6492(parent_res) => {
                let uri = parent_res.service_uri().to_string();

                match self
                    .send_revoke_requests_rfc6492(revoke_requests, child.id_key(), parent_res)
                    .await
                {
                    Err(e) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_failure(handle, parent, uri, &e)
                            .await?;
                        Err(e)
                    }
                    Ok(res) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_last_updated(handle, parent, uri)
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

    async fn send_revoke_requests_embedded(
        &self,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        handle: &Handle,
        parent_h: &ParentHandle,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let mut revoke_map = HashMap::new();

        for (rcn, revoke_requests) in revoke_requests.into_iter() {
            let mut revocations = vec![];
            for req in revoke_requests.into_iter() {
                revocations.push((&req).into());

                let cmd = CmdDet::child_revoke_key(parent_h, handle.clone(), req, self.signer.clone());

                self.send_command(cmd).await?;
            }
            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
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
                let cms_logger = CmsLogger::for_rfc6492_sent(self.rfc6492_log_dir.as_ref(), &sender, &recipient);

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

    async fn send_cert_requests_handle_responses(&self, handle: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        let child = self.get_ca(handle).await?;
        let cert_requests = child.cert_requests(parent);

        let issued_certs = match child.parent(parent)? {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),
            ParentCaContact::Embedded => self.send_cert_requests_embedded(cert_requests, handle, parent).await,
            ParentCaContact::Rfc6492(parent_res) => {
                let uri = parent_res.service_uri().to_string();
                match self
                    .send_cert_requests_rfc6492(cert_requests, child.id_key(), &parent_res)
                    .await
                {
                    Err(e) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_failure(handle, parent, uri, &e)
                            .await?;
                        Err(e)
                    }
                    Ok(res) => {
                        self.status_store
                            .lock()
                            .await
                            .set_parent_last_updated(handle, parent, uri)
                            .await?;
                        Ok(res)
                    }
                }
            }
        }?;

        for (class_name, issued_certs) in issued_certs.into_iter() {
            for issued in issued_certs.into_iter() {
                let received = RcvdCert::from(issued);
                let upd_rcvd_cmd = CmdDet::upd_received_cert(handle, class_name.clone(), received, self.signer.clone());
                self.send_command(upd_rcvd_cmd).await?;
            }
        }

        Ok(())
    }

    async fn send_cert_requests_embedded(
        &self,
        requests: HashMap<ResourceClassName, Vec<IssuanceRequest>>,
        handle: &Handle,
        parent_h: &ParentHandle,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<IssuedCert>>> {
        let mut issued_map = HashMap::new();

        for (rcn, requests) in requests.into_iter() {
            let mut issued_certs = vec![];
            for req in requests.into_iter() {
                let pub_key = req.csr().public_key().clone();
                let parent_class = req.class_name().clone();

                let cmd = CmdDet::child_certify(parent_h, handle.clone(), req, self.signer.clone());

                let parent = self.send_command(cmd).await?;

                let response = parent.issuance_response(handle, &parent_class, &pub_key)?;

                let (_, _, _, issued) = response.unwrap();

                issued_certs.push(issued);
            }

            issued_map.insert(rcn, issued_certs);
        }

        Ok(issued_map)
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

                let cms_logger = CmsLogger::for_rfc6492_sent(self.rfc6492_log_dir.as_ref(), &sender, &recipient);

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
    async fn update_resource_classes(
        &self,
        handle: &Handle,
        parent: ParentHandle,
        entitlements: Entitlements,
    ) -> KrillResult<bool> {
        let current_version = self.get_ca(handle).await?.version();

        let update_entitlements_command =
            CmdDet::upd_resource_classes(handle, parent, entitlements, self.signer.clone());

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
        self.get_entitlements_from_parent_and_contact(handle, parent, contact)
            .await
    }

    pub async fn get_entitlements_from_parent_and_contact(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
    ) -> KrillResult<api::Entitlements> {
        match contact {
            ParentCaContact::Ta(_) => Err(Error::TaNotAllowed),
            ParentCaContact::Embedded => self.get_entitlements_embedded(handle, parent).await,
            ParentCaContact::Rfc6492(res) => self.get_entitlements_rfc6492(handle, res).await,
        }
    }

    async fn get_entitlements_embedded(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> KrillResult<api::Entitlements> {
        let parent = self.ca_store.get_latest(parent)?;
        parent.list(handle)
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
            .send_rfc6492_and_validate_response(child.id_key(), parent_res, list.into_bytes(), None)
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

/// # Support sending publication messages, and verifying responses.
///
impl CaServer {
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

    async fn send_rfc8181_and_validate_response(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        msg: Bytes,
    ) -> KrillResult<rfc8181::ReplyMessage> {
        let ca = self.get_ca(ca_handle).await?;

        let cms_logger = CmsLogger::for_rfc8181_sent(self.rfc8181_log_dir.as_ref(), ca_handle);

        let response = self
            .send_procotol_msg_and_validate(
                ca.id_key(),
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

    pub async fn send_rfc8181_list(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        cleanup: bool,
    ) -> KrillResult<ListReply> {
        let uri = repository.service_uri().to_string();

        let reply = match self
            .send_rfc8181_and_validate_response(ca_handle, repository, rfc8181::Message::list_query().into_bytes())
            .await
        {
            Err(e) => {
                if !cleanup {
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_failure(ca_handle, uri, &e)
                        .await?;
                }
                return Err(e);
            }
            Ok(reply) => reply,
        };

        match reply {
            rfc8181::ReplyMessage::ListReply(list_reply) => {
                self.status_store
                    .lock()
                    .await
                    .set_status_repo_success(ca_handle, uri)
                    .await?;
                Ok(list_reply)
            }
            rfc8181::ReplyMessage::SuccessReply => {
                let err = Error::custom("Got success reply to list query?!");
                if !cleanup {
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_failure(ca_handle, uri, &err)
                        .await?;
                }
                Err(err)
            }
            rfc8181::ReplyMessage::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                if !cleanup {
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_failure(ca_handle, uri, &err)
                        .await?;
                }
                Err(err)
            }
        }
    }

    pub async fn send_rfc8181_delta(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        delta: PublishDelta,
        cleanup: bool,
    ) -> KrillResult<()> {
        let message = rfc8181::Message::publish_delta_query(delta);
        let uri = repository.service_uri().to_string();

        let reply = match self
            .send_rfc8181_and_validate_response(ca_handle, repository, message.into_bytes())
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                if !cleanup {
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_failure(ca_handle, uri, &e)
                        .await?;
                }
                return Err(e);
            }
        };

        match reply {
            rfc8181::ReplyMessage::SuccessReply => {
                if !cleanup {
                    let ca = self.get_ca(ca_handle).await?;
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_elements(ca_handle, uri, ca.all_objects())
                        .await?;
                }
                Ok(())
            }
            rfc8181::ReplyMessage::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {}", e));
                if !cleanup {
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_failure(ca_handle, uri, &err)
                        .await?;
                }
                Err(err)
            }
            rfc8181::ReplyMessage::ListReply(_) => {
                let err = Error::custom("Got list reply to delta query?!");
                if !cleanup {
                    self.status_store
                        .lock()
                        .await
                        .set_status_repo_failure(ca_handle, uri, &err)
                        .await?;
                }
                Err(err)
            }
        }
    }
}

/// # Support Route Authorization functions
///
impl CaServer {
    /// Update the routes authorized by a CA
    pub async fn ca_routes_update(&self, handle: Handle, updates: RouteAuthorizationUpdates) -> KrillResult<()> {
        let cmd = CmdDet::route_authorizations_update(&handle, updates, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }
}

/// # Support Resource Tagged Attestation functions
///
impl CaServer {
    /// Sign a one-off single-signed RTA
    pub async fn rta_sign(&self, ca: Handle, name: RtaName, request: RtaContentRequest) -> KrillResult<()> {
        let cmd = CmdDet::rta_sign(&ca, name, request, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Prepare a multi-singed RTA
    pub async fn rta_multi_prep(&self, ca: &Handle, name: RtaName, request: RtaPrepareRequest) -> KrillResult<()> {
        let cmd = CmdDet::rta_multi_prep(ca, name, request, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }

    /// Co-sign an existing RTA
    pub async fn rta_multi_cosign(&self, ca: Handle, name: RtaName, rta: ResourceTaggedAttestation) -> KrillResult<()> {
        let cmd = CmdDet::rta_multi_sign(&ca, name, rta, self.signer.clone());
        self.send_command(cmd).await?;
        Ok(())
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::fs;
    use std::sync::Arc;

    use crate::commons::api::RepoInfo;
    use crate::test;
    use crate::test::tmp_dir;

    use super::*;

    #[tokio::test]
    async fn add_ta() {
        let d = tmp_dir();
        let signer = KrillSigner::build(&d).unwrap();

        let event_queue = Arc::new(EventQueueListener::default());

        let server = CaServer::build(&d, None, None, event_queue, signer).await.unwrap();

        let repo_info = {
            let base_uri = test::rsync("rsync://localhost/repo/ta/");
            let rrdp_uri = test::https("https://localhost/repo/notification.xml");
            RepoInfo::new(base_uri, rrdp_uri)
        };

        let ta_uri = test::https("https://localhost/ta/ta.cer");
        let ta_aia = test::rsync("rsync://localhost/repo/ta.cer");

        assert!(server.get_trust_anchor().await.is_err());

        server.init_ta(repo_info, ta_aia, vec![ta_uri]).await.unwrap();

        assert!(server.get_trust_anchor().await.is_ok());

        let _ = fs::remove_dir_all(d);
    }
}
