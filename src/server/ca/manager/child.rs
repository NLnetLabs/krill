//! Provisioning protocol exchanges.

#![allow(unused)]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use rpki::uri;
use rpki::ca::provisioning;
use rpki::ca::idexchange::{CaHandle, ChildHandle, ParentHandle, ServiceUri};
use rpki::ca::provisioning::{
    IssuanceRequest, ProvisioningCms, ResourceClassListResponse,
    ResourceClassName, RevocationRequest, RevocationResponse,
};
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use crate::api::admin::{
    ParentCaContact, ParentServerInfo, UpdateChildRequest,
};
use crate::api::ca::ReceivedCert;
use crate::api::ta::ProvisioningRequest;
use crate::commons::httpclient;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::cmslogger::CmsLogger;
use crate::commons::error::Error;
use crate::commons::eventsourcing::Aggregate;
use crate::constants::{TA_NAME, ta_handle};
use crate::server::ca::CertAuth;
use crate::server::ca::commands::CertAuthCommandDetails;
use crate::server::manager::KrillContext;
use crate::server::taproxy::TrustAnchorProxyCommand;
use crate::tasigner::TrustAnchorSignerCommand;
use super::CaManager;


//------------ super::CaManager ----------------------------------------------

/// # RFC 6492 client
impl CaManager {
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
    pub fn ca_sync_parent(
        &self,
        handle: &CaHandle,
        min_ca_version: u64, // set this 0 if it does not matter
        parent: &ParentHandle,
        actor: &Actor,
        krill: &KrillContext,
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
                self.send_requests(handle, parent, actor, krill)?;
            }
            else {
                self.get_updates_from_parent(handle, parent, actor, krill)?;
            }
            Ok(true)
        }
    }

    /// Synchronizes the TA proxy with a local TA signer.
    ///
    /// If the TA signer is remote, logs a warning suggesting doing a
    /// manual synchronization, assuming that this method is only ever called
    /// if the TA proxy requires synchronization.
    pub fn sync_ta_proxy_signer_if_possible(
        &self, krill: &KrillContext,
    ) -> KrillResult<()> {
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
                krill.system_actor(),
            )
        )?;

        // Get sign request for signer.
        let signed_request = proxy.get_signer_request(
            krill.config().ta_timing, krill.signer()
        )?;

        // Remember the noce of the request so we can retrieve it.
        let request_nonce = signed_request.request.nonce.clone();

        // Let signer process request.
        let ta_signer = self.send_ta_signer_command(
            TrustAnchorSignerCommand::make_process_request_command(
                &ta_handle,
                signed_request.into(),
                krill.config().ta_timing,
                None, // do not override next manifest number
                krill.signer(),
                krill.system_actor(),
            )
        )?;

        // Get the response from the signer and give it to the proxy.
        let exchange = ta_signer.get_exchange(&request_nonce).unwrap();
        self.send_ta_proxy_command(
            TrustAnchorProxyCommand::process_signer_response(
                &ta_handle,
                exchange.clone().response,
                krill.system_actor(),
            )
        )?;
        Ok(())
    }

    /// Tries to get updates from a specific parent of a CA.
    ///
    /// Quietly does nothing for the TA CA.
    fn get_updates_from_parent(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
        actor: &Actor,
        krill: &KrillContext,
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
            handle, parent, parent_contact, true, krill
        )?;

        self.update_entitlements(
            handle, parent.clone(), entitlements, actor, krill
        )?;

        Ok(())
    }

    /// Sends requests to a specific parent for the CA matching handle.
    ///
    /// First sends all open revoke requests, then sends all open
    /// certificate requests.
    fn send_requests(
        &self, handle: &CaHandle, parent: &ParentHandle, actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        self.send_revoke_requests_handle_responses(
            handle, parent, actor, krill
        )?;
        self.send_cert_requests_handle_responses(
            handle, parent, actor, krill
        )
    }

    /// Sends all open revocation requests and handles the responses.
    fn send_revoke_requests_handle_responses(
        &self, handle: &CaHandle, parent: &ParentHandle, actor: &Actor,
        krill: &KrillContext,
    ) -> KrillResult<()> {
        let child = self.get_ca(handle)?;
        let requests = child.revoke_requests(parent);

        let revoke_responses = self.send_revoke_requests(
            handle, parent, requests, krill,
        )?;

        for (rcn, revoke_responses) in revoke_responses {
            for response in revoke_responses {
                self.process_ca_command(
                    handle.clone(), actor,
                    CertAuthCommandDetails::KeyRollFinish(
                        rcn.clone(),
                        response,
                    ),
                    krill,
                )?;
            }
        }

        Ok(())
    }

    /// Sends the given revoke requests to a parent.
    ///
    /// Returns the responses for the requests.
    pub fn send_revoke_requests(
        &self,
        handle: &CaHandle,
        parent: &ParentHandle,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        krill: &KrillContext,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>> {
        let child = self.get_ca(handle)?;
        let server_info = child.parent(parent)?.parent_server_info();

        match self.send_revoke_requests_rfc6492(
            revoke_requests,
            child.id_cert().public_key.key_identifier(),
            server_info,
            krill,
        ) {
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
    pub fn send_revoke_unexpected_key(
        &self,
        handle: &CaHandle,
        rcn: ResourceClassName,
        revocation: RevocationRequest,
        krill: &KrillContext,
    ) -> KrillResult<HashMap<ResourceClassName, Vec<RevocationResponse>>>
    {
        let child = self.ca_store.get_latest(handle)?;
        let parent = child.parent_for_rc(&rcn)?;
        let mut requests = HashMap::new();
        requests.insert(rcn, vec![revocation]);

        self.send_revoke_requests(handle, parent, requests, krill)
    }

    /// Sends revoke requests using the provisioning protocol.
    fn send_revoke_requests_rfc6492(
        &self,
        revoke_requests: HashMap<ResourceClassName, Vec<RevocationRequest>>,
        signing_key: KeyIdentifier,
        server_info: &ParentServerInfo,
        krill: &KrillContext,
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
                    revoke, server_info, signing_key, krill
                )?;

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
                            "Got unexpected response '{payload_type}' \
                             to revoke query"
                        )))
                    }
                }
            }

            revoke_map.insert(rcn, revocations);
        }

        Ok(revoke_map)
    }

    /// Sends certification requests to a parent CA and proceses the response.
    fn send_cert_requests_handle_responses(
        &self, ca_handle: &CaHandle, parent: &ParentHandle, actor: &Actor,
        krill: &KrillContext,
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
                    signing_key,
                    krill,
                ) {
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
                            ca_handle, parent, &rcn, actor, response,
                            krill
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
        krill: &KrillContext,
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
                    ),
                    krill,
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
                        ),
                        krill,
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
                            ),
                            krill,
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
                            ),
                            krill,
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
        krill: &KrillContext,
    ) -> KrillResult<bool> {
        let current_version = self.get_ca(ca)?.version();
        let new_version = self.process_ca_command(
            ca.clone(), actor,
            CertAuthCommandDetails::UpdateEntitlements(
                parent,
                entitlements,
            ),
            krill,
        )?.version();
        Ok(new_version > current_version)
    }

    /// Requests the entitlements from the parent.
    pub fn get_entitlements_from_contact(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        contact: &ParentCaContact,
        existing_parent: bool,
        krill: &KrillContext,
    ) -> KrillResult<ResourceClassListResponse> {
        let server_info = contact.parent_server_info();
        let uri = &server_info.service_uri;

        let result = self.get_entitlements_rfc6492(ca, server_info, krill);

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
    fn get_entitlements_rfc6492(
        &self,
        handle: &CaHandle,
        server_info: &ParentServerInfo,
        krill: &KrillContext,
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
            child.id_cert().public_key.key_identifier(),
            krill,
        )?;

        let payload = response.into_payload();
        let payload_type = payload.payload_type();

        match payload {
            provisioning::Payload::ListResponse(response) => Ok(response),
            provisioning::Payload::ErrorResponse(np) => {
                Err(Error::Custom(format!("Not performed: {np}")))
            }
            _ => {
                Err(Error::custom(format!(
                    "Got unexpected response type '{payload_type}' to list query"
                )))
            }
        }
    }

    fn send_rfc6492_and_validate_response(
        &self,
        message: provisioning::Message,
        server_info: &ParentServerInfo,
        signing_key: KeyIdentifier,
        krill: &KrillContext,
    ) -> KrillResult<provisioning::Message> {
        let service_uri = &server_info.service_uri;
        if let Some(parent) = Self::local_parent(
            service_uri, krill.service_uri()
        ) {
            let ca_handle = parent.into_converted();
            let user_agent = Some("local-child".to_string());

            self.rfc6492_process_request(
                &ca_handle,
                message,
                user_agent,
                krill.system_actor(),
                krill,
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
                krill.config().rfc6492_log_dir.as_ref(),
                &sender,
                &recipient,
            );

            let cms = krill.signer().create_rfc6492_cms(
                message, &signing_key
            )?.to_bytes();

            let (res_bytes, cms_logger) = self.post_protocol_cms_binary(
                cms,
                service_uri,
                provisioning::CONTENT_TYPE,
                cms_logger,
                krill,
            ).block().map_err(|_| Error::custom("provisioning post failed"))?;
            let res_bytes = res_bytes?;

            match ProvisioningCms::decode(&res_bytes) {
                Err(e) => {
                    error!(
                        "Could not decode response from parent (handle): \
                         {recipient}, for ca (handle): {sender}, \
                         at URI: {service_uri}. Error: {e}"
                    );
                    cms_logger.err(format!("Could not decode CMS: {e}"))?;
                    Err(Error::Rfc6492(e))
                }
                Ok(cms) => {
                    match cms.validate(&server_info.id_cert.public_key)
                    {
                        Ok(()) => Ok(cms.into_message()),
                        Err(e) => {
                            error!(
                                "Could not validate response from parent \
                                (handle): {recipient}, for ca (handle): \
                                {sender}, at URI: {service_uri}. Error: {e}"
                            );
                            cms_logger.err(
                                format!("Response invalid: {e}")
                            )?;
                            Err(Error::Rfc6492(e))
                        }
                    }
                }
            }
        }
    }

    /// Returns the handle for the parent if it is local.
    ///
    /// A parent is local if its `service_uri` is under `base_uri` and
    /// follows the format Krill is using.
    fn local_parent(
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

