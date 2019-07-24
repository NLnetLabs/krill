use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bytes::Bytes;

use rpki::uri;

use krill_commons::api;
use krill_commons::api::{
    DFLT_CLASS,
    Entitlements,
    IssuanceRequest,
    IssuanceResponse
};
use krill_commons::api::admin::{
    AddChildRequest,
    AddParentRequest,
    ChildAuthRequest,
    Handle,
    ParentCaContact,
    Token,
};
use krill_commons::api::ca::{
    CertAuthList,
    CertAuthSummary,
    IssuedCert,
    RcvdCert,
    RepoInfo,
};
use krill_commons::eventsourcing::{
    Aggregate,
    AggregateStore,
    DiskAggregateStore
};
use krill_commons::remote::builder::SignedMessageBuilder;
use krill_commons::remote::{rfc8183, rfc6492};
use krill_commons::remote::sigmsg::SignedMessage;
use krill_commons::util::httpclient;
use krill_commons::util::softsigner::SignerKeyId;

use crate::ca::{
    self,
    CmdDet,
    IniDet,
    Signer,
    CertAuth,
    ParentHandle,
    ServerResult,
    ServerError,
};
use crate::mq::EventQueueListener;


const CA_NS: &str = "cas";


//------------ CaServer ------------------------------------------------------

#[derive(Clone)]
pub struct CaServer<S: Signer> {
    signer: Arc<RwLock<S>>,
    ca_store: Arc<DiskAggregateStore<CertAuth<S>>>
}


impl<S: Signer> CaServer<S> {

    /// Builds a new CaServer. Will return an error if the TA store cannot be
    /// initialised.
    pub fn build(
        work_dir: &PathBuf,
        events_queue: Arc<EventQueueListener>,
        signer: S
    ) -> ServerResult<Self, S> {
        let mut ca_store = DiskAggregateStore::<CertAuth<S>>::new(work_dir, CA_NS)?;
        ca_store.add_listener(events_queue);

        Ok(CaServer {
            signer: Arc::new(RwLock::new(signer)),
            ca_store: Arc::new(ca_store)
        })
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub fn get_trust_anchor(&self) -> ServerResult<Arc<CertAuth<S>>, S> {
        self.ca_store
            .get_latest(&ca::ta_handle())
            .map_err(|_| ServerError::TrustAnchorNotInitialisedError)
    }

    /// Initialises an embedded trust anchor with all resources.
    pub fn init_ta(
        &self,
        info: RepoInfo,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>
    ) -> ServerResult<(), S> {
        let handle = ca::ta_handle();
        if self.ca_store.has(&handle) {
            Err(ServerError::TrustAnchorInitialisedError)
        } else {
            let init = IniDet::init_ta(
                &handle,
                info,
                ta_aia,
                ta_uris,
                self.signer.clone()
            )?;

            self.ca_store.add(init)?;

            Ok(())
        }
    }

    /// Republish the embedded TA and CAs if needed, i.e. if they are close
    /// to their next update time.
    pub fn republish_all(&self) -> ServerResult<(), S> {
        for ca in self.cas().cas() {
            if let Err(e) = self.republish(ca.name()) {
                error!("ServerError publishing: {}, ServerError: {}", ca.name(), e)
            }
        }
        Ok(())
    }


    /// Republish a CA, this is a no-op when there is nothing to publish.
    pub fn republish(&self, handle: &Handle) -> ServerResult<(), S> {
        debug!("Republish CA: {}", handle);
        let ca = self.ca_store.get_latest(handle)?;

        let cmd = CmdDet::publish(
            handle,
            self.signer.clone()
        );

        let events = ca.process_command(cmd)?;
        if ! events.is_empty() {
            self.ca_store.update(handle, ca, events)?;
        }

        Ok(())
    }

    /// Adds a child under the embedded TA
    pub fn ta_add_child(
        &self,
        req: AddChildRequest,
        service_uri: &uri::Https
    ) -> ServerResult<ParentCaContact, S> {
        let (handle, resources, auth) = req.unwrap();

        debug!("Adding child {} to TA", &handle);

        let ta = self.get_trust_anchor()?;
        let ta_handle = ca::ta_handle();

        let token = match &auth {
            ChildAuthRequest::Embedded(token) => token.clone(),
            ChildAuthRequest::Remote(token) => token.clone(),
            ChildAuthRequest::Rfc8183(_) => self.random_token()
        };

        let id_cert = match &auth {
            ChildAuthRequest::Embedded(_) | ChildAuthRequest::Remote(_) => None,
            ChildAuthRequest::Rfc8183(req) => Some(req.id_cert().clone())
        };

        let add_child = CmdDet::<S>::add_child(
            &ta_handle,
            handle.clone(),
            token,
            id_cert,
            resources
        );

        let events = ta.process_command(add_child)?;
        let ta = self.ca_store.update(&ta_handle, ta, events)?;

        match auth {
            ChildAuthRequest::Embedded(token) => {
                Ok(ParentCaContact::for_embedded(ta_handle, token))
            },
            ChildAuthRequest::Remote(_token) => {
                unimplemented!()
            },
            ChildAuthRequest::Rfc8183(req) => {

                let service_uri = format!(
                    "{}rfc6492/{}",
                    service_uri.to_string(),
                    ta.handle()
                );
                let service_uri = uri::Https::from_string(service_uri).unwrap();
                let service_uri = rfc8183::ServiceUri::Https(service_uri);

                let response = rfc8183::ParentResponse::new(
                    req.tag().cloned(),
                    ta.id_cert().clone(),
                    ta.handle().clone(),
                    handle,
                    service_uri
                );
                Ok(ParentCaContact::for_rfc6492(response))
            }
        }
    }

    /// Generates a random token for embedded CAs
    pub fn random_token(&self) -> Token {
        Token::random(self.signer.read().unwrap().deref())
    }
}

/// # CA support
///
impl<S: Signer> CaServer<S> {

    pub fn get_ca(&self, handle: &Handle) -> ServerResult<Arc<CertAuth<S>>, S> {
        self.ca_store.get_latest(handle)
            .map_err(|_| ServerError::UnknownCa(handle.to_string()))
    }

    /// Verifies an RFC6492 message and returns the child handle, token,
    /// and content of the request, so that the simple 'list' and 'issue'
    /// functions can be called.
    pub fn rfc6492(
        &self,
        parent_handle: &Handle,
        msg: SignedMessage
    ) -> ServerResult<Bytes, S> {
        debug!("RFC6492 Request: will check");
        let (content, token) = {
            let parent = self.ca_store.get_latest(parent_handle)?;
            parent.verify_rfc6492(msg)?
        };
        debug!("RFC6492 Request: verified");

        let (sender, recipient, content) = content.unwrap();
        let sender_handle = Handle::from(sender.as_str());

        match content {
            rfc6492::Content::Qry(rfc6492::Qry::Revoke(_)) => {
                unimplemented!("Revocation not yet supported")
            },
            rfc6492::Content::Qry(rfc6492::Qry::List) => {
                let entitlements = self.list(
                    parent_handle,
                    &sender_handle,
                    &token
                )?;

                let msg = rfc6492::Message::list_response(
                    sender,
                    recipient,
                    entitlements
                );

                self.wrap_rfc6492_response(parent_handle, msg)
            },
            rfc6492::Content::Qry(rfc6492::Qry::Issue(req)) => {
                let res = self.issue(
                    parent_handle,
                    &sender_handle,
                    req,
                    token
                )?;

                let msg = rfc6492::Message::issue_response(
                    sender,
                    recipient,
                    res
                );

                self.wrap_rfc6492_response(parent_handle, msg)
            },
            _ => Err(ServerError::custom("Unsupported RFC6492 message"))
        }
    }

    fn wrap_rfc6492_response(
        &self,
        handle: &Handle,
        msg: rfc6492::Message
    ) -> ServerResult<Bytes, S> {
        debug!("RFC6492 Response wrapping for {}", handle);
        let ca = self.ca_store.get_latest(handle)?;
        let res = ca.sign_rfc6492_response(
            msg,
            self.signer.read().unwrap().deref()
        ).map_err(ServerError::<S>::CertAuth);
        debug!("RFC6492 Response wrapped for {}", handle);
        res
    }

    /// List the entitlements for a child: 3.3.2 of RFC6492
    pub fn list(
        &self,
        parent: &Handle,
        child: &Handle,
        token: &Token
    ) -> ServerResult<Entitlements, S> {
        if parent != & ca::ta_handle() {
            unimplemented!("https://github.com/NLnetLabs/krill/issues/25");
        } else {
            let ta = self.get_trust_anchor()?;
            Ok(ta.list(child, token)?)
        }
    }

    /// Issue a Certificate in response to a Certificate Issuance request
    ///
    /// See: https://tools.ietf.org/html/rfc6492#section3.4.1-2
    pub fn issue(
        &self,
        parent: &Handle,
        child: &Handle,
        issue_req: IssuanceRequest,
        token: Token,
    ) -> ServerResult<IssuanceResponse, S> {
        if parent != & ca::ta_handle() {
            unimplemented!("https://github.com/NLnetLabs/krill/issues/25");
        } else {
            let ta = self.get_trust_anchor()?;

            let class_name = issue_req.class_name();
            let pub_key = issue_req.csr().public_key();

            if class_name != DFLT_CLASS {
                unimplemented!("Issue for multiple classes from CAs, issue #25")
            }

            let cmd = CmdDet::certify_child(
                parent,
                child.clone(),
                issue_req.clone(),
                token.clone(),
                self.signer.clone()
            );

            let events = ta.process_command(cmd)?;
            let ta = self.ca_store.update(parent, ta, events)?;

            // New entitlements will include this resource class, and
            // the newly issued certificate.
            let response = ta.issuance_response(
                child,
                &class_name,
                &pub_key,
                &token
            )?;

            Ok(response)
        }
    }

    /// Get the current CAs
    pub fn cas(&self) -> CertAuthList {
        CertAuthList::new(
            self.ca_store.list().into_iter()
                .map(CertAuthSummary::new)
                .collect()
        )
    }

    /// Initialises an embedded CA, without any parents (for now).
    pub fn init_ca(
        &self,
        handle: &Handle,
        token: Token,
        repo_info: RepoInfo,
    ) -> ServerResult<(), S> {
        if self.ca_store.has(handle) {
            Err(ServerError::DuplicateCa(handle.to_string()))
        } else {
            let init = IniDet::init(handle, token, repo_info, self.signer.clone())?;
            self.ca_store.add(init)?;
            Ok(())
        }
    }

    /// Adds a parent to a ca
    pub fn ca_add_parent(
        &self,
        handle: Handle,
        parent: AddParentRequest
    ) -> ServerResult<(), S> {
        let ca = self.get_ca(&handle)?;
        let (parent_handle, parent_contact) = parent.unwrap();

        let add = CmdDet::add_parent(
            &handle,
            parent_handle.as_str(),
            parent_contact
        );
        let events = ca.process_command(add)?;

        self.ca_store.update(&handle, ca, events)?;

        Ok(())
    }

    pub fn get_updates_from_parent(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: ParentCaContact
    ) -> ServerResult<(), S> {
        let entitlements = self.get_entitlements_from_parent(handle, &contact)?;

        if ! self.update_if_need(handle, parent, entitlements)? {
            return Ok(()) // Nothing to do
        }

        self.send_requests(handle, parent, &contact)
    }

    fn send_requests(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        contact: &ParentCaContact
    ) -> ServerResult<(), S> {
        match contact {
            ParentCaContact::Embedded(_p, token) => {
                self.send_requests_embedded(handle, parent, token)
            },
            ParentCaContact::Rfc6492(res) => {
                self.send_requests_rfc6492(handle, parent, res)
            }
            _ => unimplemented!()
        }

    }

    fn send_requests_embedded(
        &self,
        handle: &Handle,
        parent_h: &ParentHandle,
        token: &Token
    ) -> ServerResult<(), S> {
        let mut child = self.ca_store.get_latest(handle)?;
        let requests = child.cert_requests(parent_h);

        let mut parent = self.ca_store.get_latest(parent_h)?;

        let mut issued_certs: Vec<(String, IssuedCert)> = vec![];

        for req in requests.into_iter() {
            let (_,_, issuance_req) = req.unwrap();

            let class_name = issuance_req.class_name().to_string();
            let pub_key = issuance_req.csr().public_key().clone();

            let cmd = CmdDet::certify_child(
                parent_h,
                handle.clone(),
                issuance_req,
                token.clone(),
                self.signer.clone()
            );

            let events = parent.process_command(cmd)?;
            parent = self.ca_store.update(parent_h, parent, events)?;

            let response = parent.issuance_response(
                handle,
                &class_name,
                &pub_key,
                &token
            )?;

            let (_,_,_, issued) = response.unwrap();

            issued_certs.push((class_name, issued));
        }

        for (class_name, issued) in issued_certs {
            let received = RcvdCert::from(issued);

            let upd_rcvd_cmd = CmdDet::upd_received_cert(
                handle,
                parent_h,
                &class_name,
                received,
                self.signer.clone()
            );

            let evts = child.process_command(upd_rcvd_cmd)?;
            child = self.ca_store.update(handle, child, evts)?;
        }

        Ok(())
    }

    fn send_requests_rfc6492(
        &self,
        handle: &Handle,
        parent_h: &ParentHandle,
        parent_res: &rfc8183::ParentResponse
    ) -> ServerResult<(), S> {
        let mut child = self.ca_store.get_latest(handle)?;
        let requests = child.cert_requests(parent_h);

        for req in requests.into_iter() {
            let sender = parent_res.child_handle().to_string();
            let recipient = parent_res.parent_handle().to_string();
            let (_,_, issuance_req) = req.unwrap();
            let issue = rfc6492::Message::issue(sender, recipient, issuance_req);

            let res = self.send_rfc6492_and_validate_response(
                child.id_key(),
                parent_res,
                issue.into_bytes()
            )?;

            match res {
                rfc6492::Res::Error(_) => unimplemented!("Deal with error"),
                rfc6492::Res::Issue(issue_response) => {
                    let (class_name,_,_, issued) = issue_response.unwrap();
                    let received = RcvdCert::from(issued);

                    let update_rcvd_cmd = CmdDet::upd_received_cert(
                        handle,
                        parent_h,
                        &class_name,
                        received,
                        self.signer.clone()
                    );

                    let events = child.process_command(update_rcvd_cmd)?;
                    child = self.ca_store.update(handle, child, events)?;
                },
                _ => {
                    return Err(ServerError::custom("Got unexpected response to list query"))
                }
            }
        }

        Ok(())
    }

    /// Updates the CA if entitlements are different from what the CA
    /// currently has under this parent. Returns [`Ok(true)`] in case
    /// there were any updates. In that case the CA will have been updated
    /// with open certificate requests which can be retrieved.
    fn update_if_need(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        entitlements: Entitlements
    ) -> ServerResult<bool, S> {
        let child = self.ca_store.get_latest(handle)?;

        let update_entitlements_command = CmdDet::upd_entitlements(
            handle,
            parent,
            entitlements,
            self.signer.clone()
        );

        let events = child.process_command(update_entitlements_command)?;
        if ! events.is_empty() {
            self.ca_store.update(handle, child, events)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_entitlements_from_parent(
        &self,
        handle: &Handle,
        contact: &ParentCaContact
    ) -> ServerResult<api::Entitlements, S> {
        match contact {
            ParentCaContact::Embedded(parent, token) => {
                self.get_entitlements_embedded(handle, parent, token)
            },
            ParentCaContact::Rfc6492(res) => {
                self.get_entitlements_rfc6492(handle, res)
            }
            _ => unimplemented!()
        }
    }

    fn get_entitlements_embedded(
        &self,
        handle: &Handle,
        parent: &ParentHandle,
        token: &Token
    ) -> ServerResult<api::Entitlements, S> {
        let parent = self.ca_store.get_latest(parent)?;

        parent.list(handle, token).map_err(ServerError::CertAuth)
    }

    fn get_entitlements_rfc6492(
        &self,
        handle: &Handle,
        parent_res: &rfc8183::ParentResponse
    ) -> ServerResult<api::Entitlements, S> {
        let child = self.ca_store.get_latest(handle)?;

        // create a list request
        let sender = parent_res.child_handle().to_string();
        let recipient = parent_res.parent_handle().to_string();
        let list = rfc6492::Message::list(sender, recipient);

        let response = self.send_rfc6492_and_validate_response(
            child.id_key(),
            parent_res,
            list.into_bytes()
        )?;

        match response {
            rfc6492::Res::Error(_) => unimplemented!("Deal with error response"),
            rfc6492::Res::List(ent) => Ok(ent),
            _ => Err(ServerError::custom("Got unexpected response to list query"))
        }
    }

    fn send_rfc6492_and_validate_response(
        &self,
        signing_key: &SignerKeyId,
        parent_res: &rfc8183::ParentResponse,
        msg: Bytes
    ) -> ServerResult<rfc6492::Res, S>{
        // wrap it up and sign it
        let signed = {
            SignedMessageBuilder::create(
                signing_key,
                self.signer.read().unwrap().deref(),
                msg
            )
        }.map_err(ServerError::custom)?;

        error!("Sending: {}", base64::encode(&signed.as_bytes()));

        // send to the server
        let uri = parent_res.service_uri().to_string();
        debug!("Sending request to parent at: {}", &uri);
        let res = httpclient::post_binary(
            &uri,
            &signed.as_bytes(),
            rfc6492::CONTENT_TYPE
        ).map_err(ServerError::HttpClientError)?;

        // unpack and validate response
        let msg = match SignedMessage::decode(res.as_ref(), true)
            .map_err(ServerError::custom) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Could not parse response: {}", base64::encode(res.as_ref()));
                return Err(e)
            }
        };
        msg.validate(parent_res.id_cert()).map_err(ServerError::custom)?;
        rfc6492::Message::from_signed_message(&msg)
            .map_err(ServerError::custom)?
            .into_reply()
            .map_err(ServerError::custom)
    }
}










//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;

    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    use krill_commons::api::{DFLT_CLASS, IssuanceRequest};
    use krill_commons::api::admin::{
        Handle,
        Token,
        ParentCaContact
    };
    use krill_commons::api::ca::{
        RepoInfo,
        ResourceSet,
        RcvdCert
    };
    use krill_commons::eventsourcing::{
        Aggregate,
        AggregateStore,
        DiskAggregateStore
    };
    use krill_commons::util::softsigner::OpenSslSigner;
    use krill_commons::util::test;
    use krill_commons::util::test::{
        sub_dir,
        https,
        rsync,
        test_under_tmp,
    };
    use ca::EvtDet;

    fn signer(temp_dir: &PathBuf) -> OpenSslSigner {
        let signer_dir = sub_dir(temp_dir);
        OpenSslSigner::build(&signer_dir).unwrap()
    }

    #[test]
    fn add_ta() {
        test::test_under_tmp(|d| {
            let signer = OpenSslSigner::build(&d).unwrap();

            let event_queue = Arc::new(EventQueueListener::in_mem());

            let server = CaServer::<OpenSslSigner>::build(
                &d,
                event_queue,
                signer
            ).unwrap();

            let repo_info = {
                let base_uri = test::rsync("rsync://localhost/repo/ta/");
                let rrdp_uri = test::https("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ta_uri = test::https("https://localhost/ta/ta.cer");
            let ta_aia = test::rsync("rsync://localhost/repo/ta.cer");

            assert!(server.get_trust_anchor().is_err());

            server.init_ta(repo_info.clone(), ta_aia, vec![ta_uri]).unwrap();

            assert!(server.get_trust_anchor().is_ok());
        })
    }



    #[test]
    fn init_ta() {
        test_under_tmp(|d| {
            let ca_store = DiskAggregateStore::<CertAuth<OpenSslSigner>>::new(
                &d, CA_NS
            ).unwrap();

            let ta_repo_info = {
                let base_uri = rsync("rsync://localhost/repo/ta/");
                let rrdp_uri = https("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ta_handle = ca::ta_handle();


            let ta_uri = https("https://localhost/tal/ta.cer");
            let ta_aia = rsync("rsync://localhost/repo/ta.cer");

            let signer = signer(&d);
            let signer = Arc::new(RwLock::new(signer));

            //
            // --- Create TA and publish
            //

            let ta_ini = IniDet::init_ta(
                &ta_handle,
                ta_repo_info,
                ta_aia,
                vec![ta_uri],

                signer.clone()
            ).unwrap();

            ca_store.add(ta_ini).unwrap();
            let ta = ca_store.get_latest(&ta_handle).unwrap();

            //
            // --- Create Child CA
            //
            // Expect:
            //   - Child CA initialised
            //
            let child_handle = Handle::from("child");
            let child_token = Token::from("child");
            let child_rs = ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

            let ca_repo_info = {
                let base_uri = rsync("rsync://localhost/repo/ca/");
                let rrdp_uri = https("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ca_ini = IniDet::init(
                &child_handle,
                child_token.clone(),
                ca_repo_info,
                signer.clone()
            ).unwrap();

            ca_store.add(ca_ini).unwrap();
            let child = ca_store.get_latest(&child_handle).unwrap();

            //
            // --- Add Child to TA
            //
            // Expect:
            //   - Child added to TA
            //

            let cmd = CmdDet::add_child(
                &ta_handle,
                child_handle.clone(),
                child_token.clone(),
                None,
                child_rs
            );

            let events = ta.process_command(cmd).unwrap();
            let ta = ca_store.update(&ta_handle, ta, events).unwrap();

            //
            // --- Add TA as parent to child CA
            //
            // Expect:
            //   - Parent added
            //

            let parent = ParentCaContact::for_embedded(
                ta_handle.clone(),
                child_token.clone()
            );

            let add_parent = CmdDet::add_parent(
                &child_handle,
                ta_handle.as_str(),
                parent
            );

            let events = child.process_command(add_parent).unwrap();
            let child = ca_store.update(&child_handle, child, events).unwrap();

            //
            // --- Get resource entitlements for Child and let it process
            //
            // Expect:
            //   - No change in TA (just read-only entitlements)
            //   - Resource Class (DFLT) added to child with pending key
            //   - Certificate requested by child
            //

            let entitlements = ta.list(&child_handle, &child_token).unwrap();

            let upd_ent = CmdDet::upd_entitlements(
                &child_handle,
                &ta_handle,
                entitlements,
                signer.clone()
            );

            let events = child.process_command(upd_ent).unwrap();
            assert_eq!(2, events.len()); // rc and csr
            let req_evt = events[1].clone().into_details();
            let child = ca_store.update(&child_handle, child, events).unwrap();

            let req = match req_evt {
                EvtDet::CertificateRequested(req) => req,
                _ => panic!("Expected Csr")
            };

            let (_handle, _key_status, issuance_req) = req.unwrap();
            let (class_name, limit, csr) = issuance_req.unwrap();
            assert_eq!("all", &class_name);
            assert!(limit.is_empty());

            //
            // --- Send certificate request from child to TA
            //
            // Expect:
            //   - Certificate issued
            //   - Publication
            //

            let request = IssuanceRequest::new(
                DFLT_CLASS.to_string(), limit, csr
            );

            let ta_cmd = CmdDet::certify_child(
                &ta_handle,
                child_handle.clone(),
                request,
                child_token.clone(),
                signer.clone()
            );

            let ta_events = ta.process_command(ta_cmd).unwrap();
            let issued_evt = ta_events[0].clone().into_details();
            let _ta = ca_store.update(&ta_handle, ta, ta_events).unwrap();

            let issued = match issued_evt {
                EvtDet::CertificateIssued(issued) => issued,
                _ => panic!("Expected issued certificate.")
            };

            let (handle, issuance_res) = issued.unwrap();

            let (class_name, _, _, issued) = issuance_res.unwrap();

            assert_eq!(child_handle, handle);
            assert_eq!(DFLT_CLASS, class_name);

            //
            // --- Return issued certificate to child CA
            //
            // Expect:
            //   - Pending key activated
            //   - Publication

            let rcvd_cert = RcvdCert::from(issued);

            let upd_rcvd = CmdDet::upd_received_cert(
                &child_handle, &ta_handle, DFLT_CLASS, rcvd_cert, signer.clone()
            );

            let events = child.process_command(upd_rcvd).unwrap();
            let _child = ca_store.update(&child_handle, child, events).unwrap();
        })
    }
}