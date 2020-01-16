use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use chrono::Duration;

use rpki::crypto::KeyIdentifier;
use rpki::uri;

use crate::commons::api::{
    self, AddChildRequest, Base64, CertAuthHistory, CertAuthList, CertAuthSummary,
    ChildAuthRequest, ChildCaInfo, ChildHandle, Entitlements, Handle, IssuanceRequest,
    IssuanceResponse, IssuedCert, ListReply, ParentCaContact, ParentCaReq, ParentHandle,
    PublishDelta, RcvdCert, RepoInfo, RepositoryContact, ResourceClassName, ResourceSet,
    RevocationRequest, RevocationResponse, UpdateChildRequest,
};
use crate::commons::eventsourcing::{Aggregate, AggregateStore, DiskAggregateStore};
use crate::commons::remote::builder::SignedMessageBuilder;
use crate::commons::remote::cmslogger::CmsLogger;
use crate::commons::remote::id::IdCert;
use crate::commons::remote::sigmsg::SignedMessage;
use crate::commons::remote::{rfc6492, rfc8181, rfc8183};
use crate::commons::util::httpclient;
use crate::constants::CASERVER_DIR;
use crate::daemon::ca::{
    self, ta_handle, CertAuth, Cmd, CmdDet, IniDet, RouteAuthorizationUpdates, ServerError,
    ServerResult, Signer,
};
use crate::daemon::mq::EventQueueListener;

//------------ CaServer ------------------------------------------------------

#[derive(Clone)]
pub struct CaServer<S: Signer> {
    signer: Arc<RwLock<S>>,
    ca_store: Arc<DiskAggregateStore<CertAuth<S>>>,
    cms_logger_work_dir: PathBuf,
}

impl<S: Signer> CaServer<S> {
    /// Builds a new CaServer. Will return an error if the TA store cannot be
    /// initialised.
    pub fn build(
        work_dir: &PathBuf,
        events_queue: Arc<EventQueueListener>,
        signer: Arc<RwLock<S>>,
    ) -> ServerResult<Self> {
        let mut ca_store = DiskAggregateStore::<CertAuth<S>>::new(work_dir, CASERVER_DIR)?;
        ca_store.add_listener(events_queue);

        Ok(CaServer {
            signer,
            ca_store: Arc::new(ca_store),
            cms_logger_work_dir: work_dir.clone(),
        })
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub fn get_trust_anchor(&self) -> ServerResult<Arc<CertAuth<S>>> {
        self.ca_store
            .get_latest(&ca::ta_handle())
            .map_err(|_| ServerError::TrustAnchorNotInitialisedError)
    }

    /// Initialises an embedded trust anchor with all resources.
    pub fn init_ta(
        &self,
        info: RepoInfo,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,
    ) -> ServerResult<()> {
        let handle = ca::ta_handle();
        if self.ca_store.has(&handle) {
            Err(ServerError::TrustAnchorInitialisedError)
        } else {
            // init normal CA
            let init = IniDet::init(&handle, self.signer.clone())?;
            self.ca_store.add(init)?;

            // add embedded repo
            let embedded = RepositoryContact::embedded(info);
            let upd_repo_cmd = CmdDet::update_repo(&handle, embedded, self.signer.clone());
            self.ca_store.command(upd_repo_cmd)?;

            // make trust anchor
            let make_ta_cmd = CmdDet::make_trust_anchor(&handle, ta_uris, self.signer.clone());
            let ta = self.ca_store.command(make_ta_cmd)?;

            // receive the self signed cert (now as child of self)
            let ta_cert = ta.parent(&handle).unwrap().to_ta_cert();
            let rcvd_cert = RcvdCert::new(ta_cert.clone(), ta_aia, ResourceSet::all_resources());

            let rcv_cert = CmdDet::upd_received_cert(
                &handle,
                ResourceClassName::default(),
                rcvd_cert,
                self.signer.clone(),
            );
            self.ca_store.command(rcv_cert)?;

            Ok(())
        }
    }

    /// Send a command to a CA
    fn send_command(&self, cmd: Cmd<S>) -> ServerResult<()> {
        self.ca_store.command(cmd)?;
        Ok(())
    }

    /// Republish the embedded TA and CAs if needed, i.e. if they are close
    /// to their next update time.
    pub fn republish_all(&self) -> ServerResult<()> {
        for ca in self.ca_list().cas() {
            if let Err(e) = self.republish(ca.handle()) {
                error!(
                    "ServerError publishing: {}, ServerError: {}",
                    ca.handle(),
                    e
                )
            }
        }
        Ok(())
    }

    /// Republish a CA, this is a no-op when there is nothing to publish.
    pub fn republish(&self, handle: &Handle) -> ServerResult<()> {
        let cmd = CmdDet::publish(handle, self.signer.clone());
        self.send_command(cmd)
    }

    /// Update repository where a CA publishes.
    pub fn update_repo(&self, handle: Handle, new_contact: RepositoryContact) -> ServerResult<()> {
        let cmd = CmdDet::update_repo(&handle, new_contact, self.signer.clone());
        self.send_command(cmd)
    }

    /// Clean up old repo, if present.
    pub fn remove_old_repo(&self, handle: &Handle) -> ServerResult<()> {
        let ca = self.ca_store.get_latest(handle)?;

        if ca.has_old_repo() {
            info!("Removing old repository after receiving updated certificate");
            let cmd = CmdDet::remove_old_repo(handle, self.signer.clone());
            self.send_command(cmd)
        } else {
            Ok(())
        }
    }

    /// Refresh all CAs: ask for updates and shrink as needed.
    pub fn refresh_all(&self) {
        info!("Refreshing all CAs");
        if let Err(e) = self.get_updates_for_all_cas() {
            error!("Failed to refresh CA certificates: {}", e);
        }
    }

    /// Adds a child under an embedded CA
    pub fn ca_add_child(
        &self,
        parent: &ParentHandle,
        req: AddChildRequest,
        service_uri: &uri::Https,
    ) -> ServerResult<ParentCaContact> {
        info!("CA '{}' process add child request: {}", &parent, &req);
        let (child_handle, child_res, child_auth) = req.unwrap();

        let id_cert = match &child_auth {
            ChildAuthRequest::Embedded => None,
            ChildAuthRequest::Rfc8183(req) => Some(req.id_cert().clone()),
        };

        let add_child = CmdDet::child_add(&parent, child_handle.clone(), id_cert, child_res);
        self.ca_store.command(add_child)?;

        let tag = match child_auth {
            ChildAuthRequest::Rfc8183(req) => req.tag().cloned(),
            _ => None,
        };

        self.ca_parent_contact(parent, child_handle, tag, service_uri)
    }

    /// Show a contact for a child. Shows "embedded" if the parent does not know any id cert for the child.
    pub fn ca_parent_contact(
        &self,
        parent: &ParentHandle,
        child_handle: ChildHandle,
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> ServerResult<ParentCaContact> {
        let ca = self.get_ca(parent)?;
        let child = ca.get_child(&child_handle)?;
        if child.id_cert().is_some() {
            let response = self.ca_parent_response(parent, child_handle, tag, service_uri)?;
            Ok(ParentCaContact::for_rfc6492(response))
        } else {
            Ok(ParentCaContact::Embedded)
        }
    }

    /// Gets an RFC8183 Parent Response for the child, regardless of whether the parent knows the ID certificate
    /// for this child. Note: a child can be updated and an ID cert can be added at all times.
    pub fn ca_parent_response(
        &self,
        parent: &ParentHandle,
        child_handle: ChildHandle,
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> ServerResult<rfc8183::ParentResponse> {
        let ca = self.get_ca(parent)?;
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
    pub fn ca_show_child(
        &self,
        parent: &ParentHandle,
        child: &ChildHandle,
    ) -> ServerResult<ChildCaInfo> {
        trace!("Finding details for CA: {} under parent: {}", child, parent);
        let ca = self.get_ca(parent)?;
        ca.get_child(child)
            .map(|details| details.clone().into())
            .map_err(ServerError::CertAuth)
    }

    /// Update a child under this CA.
    pub fn ca_child_update(
        &self,
        handle: &Handle,
        child: ChildHandle,
        req: UpdateChildRequest,
    ) -> ServerResult<()> {
        self.send_command(CmdDet::child_update(handle, child, req))
    }

    /// Update a child under this CA.
    pub fn ca_child_remove(&self, handle: &Handle, child: ChildHandle) -> ServerResult<()> {
        let signer = self.signer.clone();
        self.send_command(CmdDet::child_remove(handle, child, signer))
    }
}

/// # CA support
///
impl<S: Signer> CaServer<S> {
    /// Gets a CA by the given handle, returns an `Err(ServerError::UnknownCA)` if it
    /// does not exist.
    pub fn get_ca(&self, handle: &Handle) -> ServerResult<Arc<CertAuth<S>>> {
        self.ca_store
            .get_latest(handle)
            .map_err(|_| ServerError::UnknownCa(handle.to_string()))
    }

    /// Gets the history for a CA.
    pub fn get_ca_history(&self, handle: &Handle) -> ServerResult<CertAuthHistory> {
        self.ca_store
            .history(handle)
            .map(CertAuthHistory::from)
            .map_err(|_| ServerError::UnknownCa(handle.to_string()))
    }

    /// Checks whether a CA by the given handle exists.
    pub fn has_ca(&self, handle: &Handle) -> bool {
        self.ca_store.has(handle)
    }

    /// Processes an RFC6492 sent to this CA.
    pub fn rfc6492(&self, ca_handle: &Handle, msg_bytes: Bytes) -> ServerResult<Bytes> {
        let ca = self.ca_store.get_latest(ca_handle)?;

        let msg = match SignedMessage::decode(msg_bytes.clone(), false) {
            Ok(msg) => msg,
            Err(e) => {
                let msg = format!(
                    "Could not decode RFC6492 message for: {}, msg: {}, err: {}",
                    ca_handle,
                    Base64::from_content(msg_bytes.as_ref()),
                    e
                );
                return Err(ServerError::custom(msg));
            }
        };

        let content = ca.verify_rfc6492(msg)?;

        let (child, recipient, content) = content.unwrap();

        let cms_logger = CmsLogger::for_rfc6492_rcvd(&self.cms_logger_work_dir, &recipient, &child);

        let (res, should_log_cms) = match content {
            rfc6492::Content::Qry(rfc6492::Qry::Revoke(req)) => {
                let res = self.revoke(ca_handle, child.clone(), req)?;
                let msg = rfc6492::Message::revoke_response(child, recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg), true)
            }
            rfc6492::Content::Qry(rfc6492::Qry::List) => {
                let entitlements = self.list(ca_handle, &child)?;
                let msg = rfc6492::Message::list_response(child, recipient, entitlements);
                (self.wrap_rfc6492_response(ca_handle, msg), false)
            }
            rfc6492::Content::Qry(rfc6492::Qry::Issue(req)) => {
                let res = self.issue(ca_handle, &child, req)?;
                let msg = rfc6492::Message::issue_response(child, recipient, res);
                (self.wrap_rfc6492_response(ca_handle, msg), true)
            }
            _ => (
                Err(ServerError::custom("Unsupported RFC6492 message")),
                true,
            ),
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

    fn wrap_rfc6492_response(&self, handle: &Handle, msg: rfc6492::Message) -> ServerResult<Bytes> {
        trace!("RFC6492 Response wrapping for {}", handle);
        self.get_ca(handle)?
            .sign_rfc6492_response(msg, self.signer.read().unwrap().deref())
            .map_err(ServerError::CertAuth)
    }

    /// List the entitlements for a child: 3.3.2 of RFC6492
    pub fn list(&self, parent: &Handle, child: &Handle) -> ServerResult<Entitlements> {
        let ca = self.get_ca(parent)?;
        Ok(ca.list(child)?)
    }

    /// Issue a Certificate in response to a Certificate Issuance request
    ///
    /// See: https://tools.ietf.org/html/rfc6492#section3.4.1-2
    pub fn issue(
        &self,
        parent: &Handle,
        child: &ChildHandle,
        issue_req: IssuanceRequest,
    ) -> ServerResult<IssuanceResponse> {
        let class_name = issue_req.class_name();
        let pub_key = issue_req.csr().public_key();

        let cmd = CmdDet::child_certify(
            parent,
            child.clone(),
            issue_req.clone(),
            self.signer.clone(),
        );

        let ca = self.ca_store.command(cmd)?;

        // The updated CA will now include the newly issued certificate.
        let response = ca.issuance_response(child, &class_name, pub_key)?;

        Ok(response)
    }

    /// See: https://tools.ietf.org/html/rfc6492#section3.5.1-2
    pub fn revoke(
        &self,
        ca_handle: &Handle,
        child: ChildHandle,
        revoke_request: RevocationRequest,
    ) -> ServerResult<RevocationResponse> {
        let res = (&revoke_request).into(); // response provided that no errors are returned earlier

        let cmd = CmdDet::child_revoke_key(ca_handle, child, revoke_request, self.signer.clone());
        self.ca_store.command(cmd)?;

        Ok(res)
    }

    /// Get the current CAs
    pub fn ca_list(&self) -> CertAuthList {
        CertAuthList::new(
            self.ca_store
                .list()
                .into_iter()
                .map(CertAuthSummary::new)
                .collect(),
        )
    }

    /// Initialises a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(&self, handle: &Handle) -> ServerResult<()> {
        if self.ca_store.has(handle) {
            Err(ServerError::DuplicateCa(handle.to_string()))
        } else {
            let init = IniDet::init(handle, self.signer.clone())?;
            self.ca_store.add(init)?;
            Ok(())
        }
    }

    pub fn ca_update_id(&self, handle: Handle) -> ServerResult<()> {
        let cmd = CmdDet::update_id(&handle, self.signer.clone());
        self.send_command(cmd)
    }

    /// Adds a parent to a CA
    pub fn ca_parent_add(&self, handle: Handle, parent: ParentCaReq) -> ServerResult<()> {
        let (parent_handle, parent_contact) = parent.unpack();

        let add = CmdDet::add_parent(&handle, parent_handle, parent_contact);
        self.send_command(add)
    }

    /// Updates a parent of a CA
    pub fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
    ) -> ServerResult<()> {
        let upd = CmdDet::update_parent(&handle, parent, contact);
        self.send_command(upd)
    }

    /// Removes a parent from a CA
    pub fn ca_parent_remove(&self, handle: Handle, parent: ParentHandle) -> ServerResult<()> {
        let upd = CmdDet::remove_parent(&handle, parent);
        self.send_command(upd)
    }

    /// Perform a key roll for all active keys in a CA older than the specified duration.
    pub fn ca_keyroll_init(&self, handle: Handle, max_age: Duration) -> ServerResult<()> {
        let init_key_roll = CmdDet::key_roll_init(&handle, max_age, self.signer.clone());
        self.send_command(init_key_roll)
    }

    /// Activate a new key, as part of the key roll process (RFC6489). Only new keys that
    /// have an age equal to or greater than the staging period are promoted. The RFC mandates
    /// a staging period of 24 hours, but we may use a shorter period for testing and/or emergency
    /// manual key rolls.
    pub fn ca_keyroll_activate(&self, handle: Handle, staging: Duration) -> ServerResult<()> {
        let activate_cmd = CmdDet::key_roll_activate(&handle, staging, self.signer.clone());
        self.send_command(activate_cmd)
    }

    /// Try to get updates for all embedded CAs, will skip the TA and/or CAs that
    /// have no parents. Will try to process all and log possible errors, i.e. do
    /// not bail out because of issues with one CA.
    pub fn get_updates_for_all_cas(&self) -> ServerResult<()> {
        for handle in self.ca_store.list() {
            if let Ok(ca) = self.get_ca(&handle) {
                for parent in ca.parents() {
                    if let Err(e) = self.get_updates_from_parent(&handle, &parent) {
                        error!(
                            "Failed to refresh CA certificates for {}, error: {}",
                            &handle, e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Try to update a specific CA
    pub fn get_updates_from_parent(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> ServerResult<()> {
        if handle == &ta_handle() {
            Ok(())
        } else {
            let entitlements = self.get_entitlements_from_parent(handle, parent)?;

            if !self.update_resource_classes(handle, parent.clone(), entitlements)? {
                return Ok(()); // Nothing to do
            }

            self.send_requests(handle, parent)
        }
    }

    /// Sends requests to a specific parent for the CA matching handle.
    pub fn send_requests(&self, handle: &Handle, parent: &ParentHandle) -> ServerResult<()> {
        self.send_revoke_requests_handle_responses(handle, parent)?;
        self.send_cert_requests_handle_responses(handle, parent)
    }

    /// Sends requests to all parents for the CA matching the handle.
    pub fn send_all_requests(&self, handle: &Handle) -> ServerResult<()> {
        let ca = self.get_ca(handle)?;

        for parent in ca.parents() {
            self.send_requests(handle, parent)?;
        }

        Ok(())
    }

    fn send_revoke_requests_handle_responses(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> ServerResult<()> {
        let child = self.ca_store.get_latest(handle)?;
        let requests = child.revoke_requests(parent);

        let revoke_responses = self.send_revoke_requests(handle, parent, requests)?;

        for (rcn, revoke_responses) in revoke_responses.into_iter() {
            for response in revoke_responses.into_iter() {
                let cmd = CmdDet::key_roll_finish(handle, rcn.clone(), response);
                self.send_command(cmd)?;
            }
        }

        Ok(())
    }

    pub fn send_revoke_requests(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
    ) -> ServerResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let child = self.ca_store.get_latest(handle)?;
        match child.parent(parent)? {
            ParentCaContact::Ta(_) => {
                Err(ca::Error::NotAllowedForTa).map_err(ServerError::CertAuth)
            }
            ParentCaContact::Embedded => {
                self.send_revoke_requests_embedded(revoke_requests, handle, parent)
            }
            ParentCaContact::Rfc6492(parent_res) => {
                self.send_revoke_requests_rfc6492(revoke_requests, child.id_key(), parent_res)
            }
        }
    }

    fn send_revoke_requests_embedded(
        &self,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        handle: &Handle,
        parent_h: &ParentHandle,
    ) -> ServerResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let mut revoke_map = HashMap::new();

        for (rcn, revoke_requests) in revoke_requests.into_iter() {
            let mut revocations = vec![];
            for req in revoke_requests.into_iter() {
                revocations.push((&req).into());

                let cmd =
                    CmdDet::child_revoke_key(parent_h, handle.clone(), req, self.signer.clone());

                self.send_command(cmd)?;
            }
            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
    }

    fn send_revoke_requests_rfc6492(
        &self,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        signing_key: &KeyIdentifier,
        parent_res: &rfc8183::ParentResponse,
    ) -> ServerResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let mut revoke_map = HashMap::new();

        for (rcn, revoke_requests) in revoke_requests.into_iter() {
            let mut revocations = vec![];
            for req in revoke_requests.into_iter() {
                let sender = parent_res.child_handle().clone();
                let recipient = parent_res.parent_handle().clone();
                let cms_logger =
                    CmsLogger::for_rfc6492_sent(&self.cms_logger_work_dir, &sender, &recipient);

                let revoke = rfc6492::Message::revoke(sender, recipient, req.clone());

                match self.send_rfc6492_and_validate_response(
                    signing_key,
                    parent_res,
                    revoke.into_bytes(),
                    Some(cms_logger),
                ) {
                    Err(e) => error!("Could not send/validate revoke: {}", e),
                    Ok(response) => match response {
                        rfc6492::Res::Revoke(revoke_response) => revocations.push(revoke_response),
                        rfc6492::Res::NotPerformed(e) => error!("We got an error response: {}", e),
                        rfc6492::Res::List(_) => error!("List response to revoke request??"),
                        rfc6492::Res::Issue(_) => error!("Issue response to revoke request??"),
                    },
                }
            }

            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
    }

    fn send_cert_requests_handle_responses(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> ServerResult<()> {
        let child = self.ca_store.get_latest(handle)?;
        let cert_requests = child.cert_requests(parent);

        let issued_certs = match child.parent(parent)? {
            ParentCaContact::Ta(_) => {
                Err(ca::Error::NotAllowedForTa).map_err(ServerError::CertAuth)
            }
            ParentCaContact::Embedded => {
                self.send_cert_requests_embedded(cert_requests, handle, parent)
            }
            ParentCaContact::Rfc6492(parent_res) => {
                self.send_cert_requests_rfc6492(cert_requests, child.id_key(), &parent_res)
            }
        }?;

        for (class_name, issued_certs) in issued_certs.into_iter() {
            for issued in issued_certs.into_iter() {
                let received = RcvdCert::from(issued);

                let upd_rcvd_cmd = CmdDet::upd_received_cert(
                    handle,
                    class_name.clone(),
                    received,
                    self.signer.clone(),
                );

                self.send_command(upd_rcvd_cmd)?;
            }
        }

        Ok(())
    }

    fn send_cert_requests_embedded(
        &self,
        requests: HashMap<ResourceClassName, Vec<IssuanceRequest>>,
        handle: &Handle,
        parent_h: &ParentHandle,
    ) -> ServerResult<HashMap<ResourceClassName, Vec<IssuedCert>>> {
        let mut issued_map = HashMap::new();

        for (rcn, requests) in requests.into_iter() {
            let mut issued_certs = vec![];
            for req in requests.into_iter() {
                let pub_key = req.csr().public_key().clone();
                let parent_class = req.class_name().clone();

                let cmd = CmdDet::child_certify(parent_h, handle.clone(), req, self.signer.clone());

                let parent = self.ca_store.command(cmd)?;

                let response = parent.issuance_response(handle, &parent_class, &pub_key)?;

                let (_, _, _, issued) = response.unwrap();

                issued_certs.push(issued);
            }

            issued_map.insert(rcn, issued_certs);
        }

        Ok(issued_map)
    }

    fn send_cert_requests_rfc6492(
        &self,
        requests: HashMap<ResourceClassName, Vec<IssuanceRequest>>,
        signing_key: &KeyIdentifier,
        parent_res: &rfc8183::ParentResponse,
    ) -> ServerResult<HashMap<ResourceClassName, Vec<IssuedCert>>> {
        let mut issued_map = HashMap::new();

        for (rcn, requests) in requests.into_iter() {
            let mut issued_certs = vec![];

            for req in requests.into_iter() {
                let sender = parent_res.child_handle().clone();
                let recipient = parent_res.parent_handle().clone();

                let cms_logger =
                    CmsLogger::for_rfc6492_sent(&self.cms_logger_work_dir, &sender, &recipient);

                let issue = rfc6492::Message::issue(sender, recipient, req);

                match self.send_rfc6492_and_validate_response(
                    signing_key,
                    parent_res,
                    issue.into_bytes(),
                    Some(cms_logger),
                ) {
                    Err(e) => error!("Could not send/validate csr: {}", e),
                    Ok(response) => match response {
                        rfc6492::Res::NotPerformed(e) => error!("We got an error response: {}", e),
                        rfc6492::Res::Issue(issue_response) => {
                            let (_, _, _, issued) = issue_response.unwrap();
                            issued_certs.push(issued);
                        }
                        rfc6492::Res::List(_) => error!("List reply to issue request??"),
                        rfc6492::Res::Revoke(_) => error!("Revoke reply to issue request??"),
                    },
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
    fn update_resource_classes(
        &self,
        handle: &Handle,
        parent: ParentHandle,
        entitlements: Entitlements,
    ) -> ServerResult<bool> {
        let current_version = self.ca_store.get_latest(handle)?.version();

        let update_entitlements_command =
            CmdDet::upd_resource_classes(handle, parent, entitlements, self.signer.clone());

        let new_version = self
            .ca_store
            .command(update_entitlements_command)?
            .version();

        Ok(new_version > current_version)
    }

    fn get_entitlements_from_parent(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> ServerResult<api::Entitlements> {
        let ca = self.get_ca(&handle)?;
        let contact = ca.parent(parent)?;
        self.get_entitlements_from_parent_and_contact(handle, parent, contact)
        //        match self.get_ca(&handle)?.parent(parent)? {
        //            ParentCaContact::Ta(_) => {
        //                Err(ca::Error::NotAllowedForTa).map_err(ServerError::CertAuth)
        //            }
        //            ParentCaContact::Embedded => self.get_entitlements_embedded(handle, parent),
        //            ParentCaContact::Rfc6492(res) => self.get_entitlements_rfc6492(handle, res),
        //        }
    }

    pub fn get_entitlements_from_parent_and_contact(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
    ) -> ServerResult<api::Entitlements> {
        match contact {
            ParentCaContact::Ta(_) => {
                Err(ca::Error::NotAllowedForTa).map_err(ServerError::CertAuth)
            }
            ParentCaContact::Embedded => self.get_entitlements_embedded(handle, parent),
            ParentCaContact::Rfc6492(res) => self.get_entitlements_rfc6492(handle, res),
        }
    }

    fn get_entitlements_embedded(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
    ) -> ServerResult<api::Entitlements> {
        let parent = self.ca_store.get_latest(parent)?;
        parent.list(handle).map_err(ServerError::CertAuth)
    }

    fn get_entitlements_rfc6492(
        &self,
        handle: &Handle,
        parent_res: &rfc8183::ParentResponse,
    ) -> ServerResult<api::Entitlements> {
        let child = self.ca_store.get_latest(handle)?;

        // create a list request
        let sender = parent_res.child_handle().clone();
        let recipient = parent_res.parent_handle().clone();

        let list = rfc6492::Message::list(sender, recipient);

        let response = self.send_rfc6492_and_validate_response(
            child.id_key(),
            parent_res,
            list.into_bytes(),
            None,
        )?;

        match response {
            rfc6492::Res::NotPerformed(np) => {
                Err(ServerError::Custom(format!("Not performed: {}", np)))
            }
            rfc6492::Res::List(ent) => Ok(ent),
            _ => Err(ServerError::custom("Got unexpected response to list query")),
        }
    }

    fn send_rfc6492_and_validate_response(
        &self,
        signing_key: &KeyIdentifier,
        parent_res: &rfc8183::ParentResponse,
        msg: Bytes,
        cms_logger: Option<CmsLogger>,
    ) -> ServerResult<rfc6492::Res> {
        let response = self.send_procotol_msg_and_validate(
            signing_key,
            parent_res.service_uri(),
            parent_res.id_cert(),
            rfc6492::CONTENT_TYPE,
            msg,
            cms_logger,
        )?;

        rfc6492::Message::from_signed_message(&response)
            .map_err(ServerError::custom)?
            .into_reply()
            .map_err(ServerError::custom)
    }
}

/// # Support sending publication messages, and verifying responses.
///
impl<S: Signer> CaServer<S> {
    fn send_procotol_msg_and_validate(
        &self,
        signing_key: &KeyIdentifier,
        service_uri: &rfc8183::ServiceUri,
        service_id: &IdCert,
        content_type: &str,
        msg: Bytes,
        cms_logger: Option<CmsLogger>,
    ) -> ServerResult<SignedMessage> {
        let signed_msg =
            SignedMessageBuilder::create(signing_key, self.signer.read().unwrap().deref(), msg)
                .map_err(ServerError::signer)?
                .as_bytes();

        let uri = service_uri.to_string();

        let res = httpclient::post_binary(&uri, &signed_msg, content_type)
            .map_err(ServerError::HttpClientError)?;

        if let Some(logger) = cms_logger {
            logger.sent(&signed_msg)?;
            logger.reply(&res)?;
        }

        // unpack and validate response
        let msg = match SignedMessage::decode(res.as_ref(), false).map_err(ServerError::custom) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Could not parse protocol response");
                return Err(e);
            }
        };

        if let Err(e) = msg.validate(service_id) {
            error!(
                "Could not validate protocol response: {}",
                base64::encode(res.as_ref())
            );
            return Err(ServerError::custom(e));
        }

        Ok(msg)
    }

    fn send_rfc8181_and_validate_response(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        msg: Bytes,
    ) -> ServerResult<rfc8181::ReplyMessage> {
        let ca = self.get_ca(ca_handle)?;

        let cms_logger = CmsLogger::for_rfc8181_sent(&self.cms_logger_work_dir, ca_handle);

        let response = self.send_procotol_msg_and_validate(
            ca.id_key(),
            repository.service_uri(),
            repository.id_cert(),
            rfc8181::CONTENT_TYPE,
            msg,
            Some(cms_logger),
        )?;

        rfc8181::Message::from_signed_message(&response)
            .map_err(ServerError::custom)?
            .into_reply()
            .map_err(ServerError::custom)
    }

    pub fn send_rfc8181_list(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
    ) -> ServerResult<ListReply> {
        let reply = self.send_rfc8181_and_validate_response(
            ca_handle,
            repository,
            rfc8181::Message::list_query().into_bytes(),
        )?;

        match reply {
            rfc8181::ReplyMessage::ListReply(list_reply) => Ok(list_reply),
            rfc8181::ReplyMessage::SuccessReply => {
                Err(ServerError::custom("Got success reply to list query?!"))
            }
            rfc8181::ReplyMessage::ErrorReply(e) => Err(ServerError::custom(e)),
        }
    }

    pub fn send_rfc8181_delta(
        &self,
        ca_handle: &Handle,
        repository: &rfc8183::RepositoryResponse,
        delta: PublishDelta,
    ) -> ServerResult<()> {
        let message = rfc8181::Message::publish_delta_query(delta);

        let reply =
            self.send_rfc8181_and_validate_response(ca_handle, repository, message.into_bytes())?;

        match reply {
            rfc8181::ReplyMessage::SuccessReply => Ok(()),
            rfc8181::ReplyMessage::ErrorReply(e) => Err(ServerError::custom(e)),
            rfc8181::ReplyMessage::ListReply(_) => {
                Err(ServerError::custom("Got list reply to delta query?!"))
            }
        }
    }
}

/// # Support Route Authorization functions
///
impl<S: Signer> CaServer<S> {
    /// Update the routes authorized by a CA
    pub fn ca_routes_update(
        &self,
        handle: Handle,
        updates: RouteAuthorizationUpdates,
    ) -> ServerResult<()> {
        let cmd = CmdDet::route_authorizations_update(&handle, updates, self.signer.clone());
        self.send_command(cmd)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    use std::sync::{Arc, RwLock};

    use crate::commons::api::RepoInfo;
    use crate::commons::util::softsigner::OpenSslSigner;
    use crate::commons::util::test;

    #[test]
    fn add_ta() {
        test::test_under_tmp(|d| {
            let signer = OpenSslSigner::build(&d).unwrap();
            let signer = Arc::new(RwLock::new(signer));

            let event_queue = Arc::new(EventQueueListener::in_mem());

            let server = CaServer::<OpenSslSigner>::build(&d, event_queue, signer).unwrap();

            let repo_info = {
                let base_uri = test::rsync("rsync://localhost/repo/ta/");
                let rrdp_uri = test::https("https://localhost/repo/notification.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ta_uri = test::https("https://localhost/ta/ta.cer");
            let ta_aia = test::rsync("rsync://localhost/repo/ta.cer");

            assert!(server.get_trust_anchor().is_err());

            server
                .init_ta(repo_info.clone(), ta_aia, vec![ta_uri])
                .unwrap();

            assert!(server.get_trust_anchor().is_ok());
        })
    }
}
