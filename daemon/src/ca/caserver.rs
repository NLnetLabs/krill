use std::{io, fmt};
use std::path::PathBuf;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::ops::Deref;

use rpki::uri;

use krill_commons::api::{DFLT_CLASS, Entitlements, IssuanceRequest, IssuanceResponse};
use krill_commons::api::admin::{AddChildRequest, Handle, ParentCaContact, AddParentRequest, Token, ChildAuthRequest};
use krill_commons::api::ca::{IssuedCert, RcvdCert, RepoInfo, CertAuthList, CertAuthSummary};
use krill_commons::eventsourcing::{Aggregate, AggregateStore, AggregateStoreError, DiskAggregateStore};
use krill_commons::util::httpclient;
use krill_commons::remote::builder::SignedMessageBuilder;
use krill_commons::remote::{rfc8183, rfc6492};

use crate::ca::ca::{
    CertAuth,
    CaCmdDet,
    CaIniDet,
    CaEvtDet,
};
use crate::ca::CaSigner;
use ca::CaError;
use mq::EventQueueListener;


pub const CA_NS: &str = "cas";
const TA_NAME: &str = "ta"; // reserved for TA

pub fn ta_handle() -> Handle {
    Handle::from(TA_NAME)
}

//------------ CaServer ------------------------------------------------------

#[derive(Clone)]
pub struct CaServer<S: CaSigner> {
    signer: Arc<RwLock<S>>,
    ca_store: Arc<RwLock<DiskAggregateStore<CertAuth<S>>>>
}


impl<S: CaSigner> CaServer<S> {

    /// Builds a new CaServer. Will return an error if the TA store cannot be
    /// initialised.
    pub fn build(
        work_dir: &PathBuf,
        events_queue: Arc<EventQueueListener>,
        signer: S
    ) -> CaResult<Self, S> {
        let mut ca_store = DiskAggregateStore::<CertAuth<S>>::new(work_dir, CA_NS)?;
        ca_store.add_listener(events_queue);

        Ok(CaServer {
            signer: Arc::new(RwLock::new(signer)),
            ca_store: Arc::new(RwLock::new(ca_store))
        })
    }

    fn ca_store_ro(&self) -> RwLockReadGuard<DiskAggregateStore<CertAuth<S>>> {
        self.ca_store.read().unwrap()
    }

    fn ca_store_rw(&self) -> RwLockWriteGuard<DiskAggregateStore<CertAuth<S>>> {
        self.ca_store.write().unwrap()
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub fn get_trust_anchor(&self) -> CaResult<Arc<CertAuth<S>>, S> {
        self.ca_store_ro()
            .get_latest(&ta_handle())
            .map_err(|_| Error::TrustAnchorNotInitialisedError)
    }

    /// Initialises an embedded trust anchor with all resources.
    pub fn init_ta(
        &self,
        info: RepoInfo,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>
    ) -> CaResult<(), S> {
        let handle = ta_handle();
        let ca_store = self.ca_store_rw();
        if ca_store.has(&handle) {
            Err(Error::TrustAnchorInitialisedError)
        } else {
            let init = CaIniDet::init_ta(
                &handle,
                info,
                ta_aia,
                ta_uris,
                self.signer.clone()
            )?;

            ca_store.add(init)?;

            Ok(())
        }
    }

    /// Republish the embedded TA and CAs if needed, i.e. if they are close
    /// to their next update time.
    pub fn republish_all(&self) -> CaResult<(), S> {
        debug!("Publishing");
        self.ta_publish()
    }

    /// Republish the TA if close to the next update time.
    ///
    /// Note: a command is always sent to the TA, but has no side-effects
    /// if there is no need to re-publish.
    pub fn ta_publish(&self) -> CaResult<(), S> {
        // if there is a TA, publish it
        let ta_handle = ta_handle();

        let ca_store = self.ca_store_rw();

        // bail out w/o error in case there is no embedded TA
        if ! ca_store.has(&ta_handle) {
            debug!("No embedded TA present");
            return Ok(())
        }

        if let Ok(ta) = ca_store.get_latest(&ta_handle) {
            debug!("Publishing TA");
            let ta_republish = CaCmdDet::publish(
                &ta_handle,
                self.signer.clone()
            );

            let events = ta.process_command(ta_republish)?;
            if ! events.is_empty() {
                ca_store.update(&ta_handle, ta, events)?;
            }
        } else {
            error!("TA present, but could not be loaded");
        }

        Ok(())
    }

    /// Adds a child under the embedded TA
    pub fn ta_add_child(
        &self,
        req: AddChildRequest,
        service_uri: &uri::Https
    ) -> CaResult<ParentCaContact, S> {
        let (handle, resources, auth) = req.unwrap();

        debug!("Adding child {} to TA", &handle);

        let ta = self.get_trust_anchor()?;
        let ta_handle = ta_handle();

        let token = match &auth {
            ChildAuthRequest::Embedded(token) => token.clone(),
            ChildAuthRequest::Remote(token) => token.clone(),
            ChildAuthRequest::Rfc8183(_) => self.random_token()
        };

        let id_cert = match &auth {
            ChildAuthRequest::Embedded(_) | ChildAuthRequest::Remote(_) => None,
            ChildAuthRequest::Rfc8183(req) => Some(req.id_cert().clone())
        };

        let add_child = CaCmdDet::<S>::add_child(
            &ta_handle,
            handle.clone(),
            token,
            id_cert,
            resources
        );

        let events = ta.process_command(add_child)?;
        let ta = self.ca_store.write().unwrap().update(&ta_handle, ta, events)?;

        match auth {
            ChildAuthRequest::Embedded(token) => {
                Ok(ParentCaContact::for_embedded(ta_handle, token))
            },
            ChildAuthRequest::Remote(_token) => {
                unimplemented!()
            },
            ChildAuthRequest::Rfc8183(req) => {

                let service_uri = format!(
                    "{}rfc6492/{}/{}",
                    service_uri.to_string(),
                    ta.handle(),
                    &handle
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
impl<S: CaSigner> CaServer<S> {

    pub fn get_ca(&self, handle: &Handle) -> CaResult<Arc<CertAuth<S>>, S> {
        self.ca_store.read().unwrap().get_latest(handle)
            .map_err(|_| Error::UnknownCa(handle.to_string()))
    }

    /// List the entitlements for a child: 3.3.2 of RFC6492
    pub fn list(
        &self,
        parent: &Handle,
        child: &Handle,
        token: &Token
    ) -> CaResult<Entitlements, S> {
        if parent != & ta_handle() {
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
    ) -> CaResult<IssuanceResponse, S> {
        if parent != & ta_handle() {
            unimplemented!("https://github.com/NLnetLabs/krill/issues/25");
        } else {
            let ta = self.get_trust_anchor()?;

            let class_name = issue_req.class_name();
            let pub_key = issue_req.csr().public_key();

            if class_name != DFLT_CLASS {
                unimplemented!("Issue for multiple classes from CAs, issue #25")
            }

            let cmd = CaCmdDet::certify_child(
                parent,
                child.clone(),
                issue_req.clone(),
                token.clone(),
                self.signer.clone()
            );

            let events = ta.process_command(cmd)?;
            let ta = self.ca_store.write().unwrap().update(parent, ta, events)?;

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
            self.ca_store_ro().list().into_iter()
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
    ) -> CaResult<(), S> {
        if self.ca_store_ro().has(handle) {
            Err(Error::DuplicateCa(handle.to_string()))
        } else {
            let init = CaIniDet::init(handle, token, repo_info, self.signer.clone())?;
            self.ca_store_rw().add(init)?;
            Ok(())
        }
    }

    /// Adds a parent to a ca
    pub fn ca_add_parent(
        &self,
        handle: Handle,
        parent: AddParentRequest
    ) -> CaResult<(), S> {
        let ca = self.get_ca(&handle)?;
        let (parent_handle, parent_contact) = parent.unwrap();

        let add = CaCmdDet::add_parent(
            &handle,
            parent_handle.as_str(),
            parent_contact
        );
        let events = ca.process_command(add)?;

        self.ca_store_rw().update(&handle, ca, events)?;

        Ok(())
    }

    /// Update entitlements for a CA
    pub fn update_entitlements(&self, handle: &Handle) -> CaResult<(), S> {

        // Note: we can bail out on serious server side errors, indicating
        // a bug or data corruption issue on our side. However, we should
        // treat error responses from remote parents more carefully, or
        // we would risk that such errors block all CAs from getting
        // updates.

        let ta_handle = ta_handle();

        let ca_store = self.ca_store_rw();

        let mut child = ca_store.get_latest(&handle)?;

        // If this is a TA, then just return.. there is not updating
        if child.is_ta() {
            return Ok(())
        }

        for (parent_handle, parent) in child.parents()? {

            let entitlements = match parent.contact() {
                ParentCaContact::RemoteKrill(_uri, _token) => {
                    unimplemented!()
                },
                ParentCaContact::Embedded(parent_handle, token) => {
                    if parent_handle != &ta_handle {
                        unimplemented!("Issue #25")
                    }

                    let ta = self.get_trust_anchor()?;
                    ta.list(handle, &token)?
                },
                ParentCaContact::Rfc6492(parent_res) => {
                    // create a list request
                    let sender = parent_res.child_handle().to_string();
                    let recepient = parent_res.parent_handle().to_string();
                    let list = rfc6492::Message::list(sender, recepient);

                    // wrap it up and sign it
                    let signed = {
                        SignedMessageBuilder::create(
                            child.id_key(),
                            self.signer.read().unwrap().deref(),
                            list.into_bytes()
                        )
//                    }.map_err(Error::custom)?;
                    }.unwrap();

                    // send to the server
                    let _res = httpclient::post_binary(
                        &parent_res.service_uri().to_string(),
                        &signed.into_bytes(),
                        rfc6492::CONTENT_TYPE
//                    ).map_err(Error::HttpClientError)?;
                    ).unwrap();
                    // unpack response


                    unimplemented!()
                }
            };

            let update_ent_cmd = CaCmdDet::upd_entitlements(
                handle,
                &parent_handle,
                entitlements,
                self.signer.clone()
            );

            let events = child.process_command(update_ent_cmd)?;

            if !events.is_empty() {

                let mut cert_reqs: Vec<IssuanceRequest> = vec![];
                for e in &events {
                    if let CaEvtDet::CertificateRequested(req) = e.details() {
                        cert_reqs.push(req.clone().into())
                    }
                }

                // TODO Deal with partial failure corner cases, where
                //      the list request is successful, but (some of the)
                //      subsequent certificate issuance requests are not
                //      for a single parent.
                //      Perhaps store outstanding requests on a child,
                //      and clear them when the issued certificate is
                //      received. Or.. even.. do things per resource
                //      class within a parent and only store the request
                //      events if there is a positive reply on the
                //      issuance.
                child = ca_store.update(handle, child, events)?;

                let mut issued_certs: Vec<(String, IssuedCert)> = vec![];

                match parent.contact() {
                    ParentCaContact::RemoteKrill(_uri, _token) => {
                        unimplemented!()
                    },
                    ParentCaContact::Embedded(parent_handle, token) => {
                        for cert_req in cert_reqs {
                            let class_name = cert_req.class_name().to_string();
                            let issue_res = self.issue(
                                parent_handle,
                                &handle,
                                cert_req,
                                token.clone()
                            )?;

                            let (_,_,_, issued) = issue_res.unwrap();

                            issued_certs.push((class_name, issued));
                        }
                    },
                    ParentCaContact::Rfc6492(_parent_res) => unimplemented!()
                }

                for (class_name, issued) in issued_certs {
                    let received = RcvdCert::from(issued);

                    let upd_rcvd_cmd = CaCmdDet::upd_received_cert(
                        handle,
                        &parent_handle,
                        &class_name,
                        received,
                        self.signer.clone()
                    );

                    let evts = child.process_command(upd_rcvd_cmd)?;
                    child = ca_store.update(handle, child, evts)?;
                }
            }
        }
        Ok(())
    }

    /// Update entitlements for all CAs
    pub fn update_all_entitlements(&self) -> CaResult<(), S> {
        for handle in self.ca_store_ro().list() {
            if let Err(e) = self.update_entitlements(&handle) {
                error!("{}", e)
            }
        }
        Ok(())
    }

}


type CaResult<R, S> = Result<R, Error<S>>;


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error<S: CaSigner> {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "TrustAnchor was already initialised")]
    TrustAnchorInitialisedError,

    #[display(fmt = "TrustAnchor was not initialised")]
    TrustAnchorNotInitialisedError,

    #[display(fmt = "{}", _0)]
    CaError(CaError),

    #[display(fmt = "CA {} was already initialised", _0)]
    DuplicateCa(String),

    #[display(fmt = "CA {} is unknown", _0)]
    UnknownCa(String),

    #[display(fmt = "{}", _0)]
    SignerError(S::Error),

    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),

    #[display(fmt = "{}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt = "{}", _0)]
    Custom(String),
}

impl<S: CaSigner> Error<S> {
    pub fn custom(e: impl fmt::Display) -> Self {
        Error::Custom(e.to_string())
    }
}

impl<S: CaSigner> From<io::Error> for Error<S> {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl<S: CaSigner> From<CaError> for Error<S> {
    fn from(e: CaError) -> Self { Error::CaError(e) }
}

impl<S: CaSigner> From<AggregateStoreError> for Error<S> {
    fn from(e: AggregateStoreError) -> Self { Error::AggregateStoreError(e) }
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

            let ta_handle = ta_handle();


            let ta_uri = https("https://localhost/tal/ta.cer");
            let ta_aia = rsync("rsync://localhost/repo/ta.cer");

            let signer = signer(&d);
            let signer = Arc::new(RwLock::new(signer));

            //
            // --- Create TA and publish
            //

            let ta_ini = CaIniDet::init_ta(
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

            let ca_ini = CaIniDet::init(
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

            let cmd = CaCmdDet::add_child(
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

            let add_parent = CaCmdDet::add_parent(
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

            let upd_ent = CaCmdDet::upd_entitlements(
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
                CaEvtDet::CertificateRequested(req) => req,
                _ => panic!("Expected Csr")
            };

            let (parent_info, issuance_req) = req.unwrap();
            let (class_name, limit, csr) = issuance_req.unwrap();
            assert_eq!("all", &class_name);
            assert!(limit.is_empty());
            if let ParentCaContact::Embedded(handle, token) = parent_info {
                assert_eq!(ta_handle, handle);
                assert_eq!(child_token, token);
            } else {
                panic!("Expected embedded contact")
            }

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

            let ta_cmd = CaCmdDet::certify_child(
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
                CaEvtDet::CertificateIssued(issued) => issued,
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

            let upd_rcvd = CaCmdDet::upd_received_cert(
                &child_handle, &ta_handle, DFLT_CLASS, rcvd_cert, signer.clone()
            );

            let events = child.process_command(upd_rcvd).unwrap();
            let _child = ca_store.update(&child_handle, child, events).unwrap();
        })
    }
}