//! CA as a parent.

use bytes::Bytes;
use log::info;
use rpki::ca::provisioning;
use rpki::ca::idexchange::{CaHandle, ChildHandle};
use rpki::ca::provisioning::{
    IssuanceRequest, ProvisioningCms, ResourceClassListResponse,
    RevocationRequest, RevocationResponse,
};
use crate::api::admin::UpdateChildRequest;
use crate::api::ta::ProvisioningRequest;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::cmslogger::CmsLogger;
use crate::commons::error::Error;
use crate::constants::TA_NAME;
use crate::server::ca::CertAuth;
use crate::server::ca::commands::CertAuthCommandDetails;
use crate::server::manager::KrillContext;
use crate::server::taproxy::TrustAnchorProxyCommand;
use super::CaManager;


//------------ super::CaManager ----------------------------------------------

/// # RFC 6492 server
impl CaManager {
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
        krill: &KrillContext,
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
            krill.config().rfc6492_log_dir.as_ref(),
            req_msg.recipient(),
            req_msg.sender(),
        );

        match self.rfc6492_process_request(
            ca_handle, req_msg, user_agent, actor, krill
        ) {
            Ok(msg) => {
                let should_log_cms = !msg.is_list_response();
                let reply_bytes = ca.sign_rfc6492_response(
                    msg, krill.signer()
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
    pub fn rfc6492_process_request(
        &self,
        ca_handle: &CaHandle,
        req_msg: provisioning::Message,
        user_agent: Option<String>,
        actor: &Actor,
        krill: &KrillContext,
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
                    krill,
                )?;
            }
        }

        let res_msg = match payload {
            provisioning::Payload::Revoke(req) => {
                self.rfc6492_revoke(
                    ca_handle, child_handle.clone(), req, actor, krill
                )
            }
            provisioning::Payload::List => {
                self.rfc6492_list(ca_handle, &child_handle, krill)
            }
            provisioning::Payload::Issue(req) => {
                self.rfc6492_issue(
                    ca_handle, child_handle.clone(), req, actor, krill
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
        krill: &KrillContext,
    ) -> KrillResult<provisioning::Message> {
        let list_response = if ca_handle.as_str() != TA_NAME {
            self.get_ca(ca_handle)?.list(child, &krill.config().issuance_timing)
        }
        else {
            self.get_trust_anchor_proxy()?.entitlements(
                child, &krill.config().ta_timing
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
        krill: &KrillContext,
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
                    krill.config(),
                    krill.signer(),
                ),
                krill,
            )?;

            // The updated CA will now include the newly issued certificate.
            let child = ca.get_child(&child_handle)?;
            let my_rcn = child.parent_name_for_rcn(child_rcn);

            let response = ca.issuance_response(
                &child_handle,
                &my_rcn,
                pub_key,
                &krill.config().issuance_timing,
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
        krill: &KrillContext,
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
                CertAuthCommandDetails::ChildRevokeKey(child, revoke_request),
                krill,
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

