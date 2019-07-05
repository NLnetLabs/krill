use std::io;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use rpki::crypto::PublicKeyFormat;
use rpki::uri;

use krill_commons::api::{
    DFLT_CLASS,
    Entitlements,
    IssuanceRequest,
};
use krill_commons::api::admin::{
    AddChildRequest,
    Handle,
    ParentCaContact,
    ParentCaInfo,
    Token,
};
use krill_commons::api::ca::{IssuedCert, RcvdCert, RepoInfo};
use krill_commons::eventsourcing::{
    Aggregate,
    AggregateStore,
    AggregateStoreError,
    DiskAggregateStore,
};

use crate::ca::{
    self,
    CA_NS,
    CertAuth,
    CaCmdDet,
    CaIniDet,
    CaEvtDet,
    ParentCa,
};
use crate::trustanchor::{
    self,
    TA_NS,
    ta_handle,
    CaSigner,
    TrustAnchor,
    TaCmdDet,
    TaIniDet,
};
use crate::PubClients;


//------------ CaServer ------------------------------------------------------

pub struct CaServer<S: CaSigner> {
    signer: Arc<RwLock<S>>,
    ta_store: Arc<DiskAggregateStore<TrustAnchor<S>>>,
    ca_store: Arc<DiskAggregateStore<CertAuth<S>>>
}


impl<S: CaSigner> CaServer<S> {

    /// Builds a new CaServer. Will return an error if the TA store cannot be
    /// initialised.
    pub fn build(
        work_dir: &PathBuf,
        pub_clients: Arc<PubClients>,
        signer: S
    ) -> CaResult<Self, S> {
        let mut ta_store = DiskAggregateStore::<TrustAnchor<S>>::new(work_dir, TA_NS)?;
        ta_store.add_listener(pub_clients.clone());

        let mut ca_store = DiskAggregateStore::<CertAuth<S>>::new(work_dir, CA_NS)?;
        ca_store.add_listener(pub_clients);

        Ok(CaServer {
            signer: Arc::new(RwLock::new(signer)),
            ta_store: Arc::new(ta_store),
            ca_store: Arc::new(ca_store)
        })
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub fn get_trust_anchor(&self) -> CaResult<Arc<TrustAnchor<S>>, S> {
        self.ta_store
            .get_latest(&ta_handle())
            .map_err(|_| Error::TrustAnchorNotInitialisedError)
    }

    /// Initialises an embedded trust anchor with all resources.
    pub fn init_ta(
        &mut self,
        info: RepoInfo,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>
    ) -> CaResult<(), S> {
        let handle = ta_handle();
        if self.ta_store.has(&handle) {
            Err(Error::TrustAnchorInitialisedError)
        } else {
            let key = {
                self.signer.write().unwrap()
                    .create_key(PublicKeyFormat::default())
                    .map_err(Error::SignerError)?
            };

            let init = TaIniDet::init_with_all_resources(
                &handle,
                info,
                ta_aia,
                ta_uris,
                key,
                self.signer.clone()
            )?;

            self.ta_store.add(init)?;

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

        if ! self.ta_store.has(&ta_handle) {
            debug!("No embedded TA present");
            return Ok(()) // bail out w/o error in case there is no embedded TA
        }

        if let Ok(ta) = self.ta_store.get_latest(&ta_handle) {
            debug!("Publishing TA");
            let ta_republish = TaCmdDet::republish(
                &ta_handle,
                self.signer.clone()
            );

            let events = ta.process_command(ta_republish)?;
            if ! events.is_empty() {
                self.ta_store.update(&ta_handle, ta, events)?;
            }
        } else {
            error!("TA present, but could not be loaded");
        }

        Ok(())
    }

    /// Adds a child under the embedded TA
    pub fn ta_add_child(
        &self,
        req: AddChildRequest
    ) -> CaResult<(), S> {
        let (handle, token, resources) = req.unwrap();

        debug!("Adding child {} to TA", &handle);

        let ta = self.get_trust_anchor()?;
        let ta_handle = ta_handle();

        let add_child = TaCmdDet::<S>::add_child(
            &ta_handle,
            handle,
            token.clone(),
            resources
        );

        let events = ta.process_command(add_child)?;
        self.ta_store.update(&ta_handle, ta, events)?;

        Ok(())
    }


    /// Generates a random token for embedded CAs
    pub fn random_token(&self) -> Token {
        use std::ops::Deref;
        Token::random(self.signer.read().unwrap().deref())
    }
}

/// # CA support
///
impl<S: CaSigner> CaServer<S> {

    fn get_ca(&self, handle: &Handle) -> CaResult<Arc<CertAuth<S>>, S> {
        self.ca_store.get_latest(handle)
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
    ) -> CaResult<IssuedCert, S> {
        if parent != & ta_handle() {
            unimplemented!("https://github.com/NLnetLabs/krill/issues/25");
        } else {
            let ta = self.get_trust_anchor()?;

            // class name can be ignored for TA, only uses one.
            let (class_name, limit, csr) = issue_req.unwrap();

            let pub_key = csr.public_key().clone();

            if class_name != DFLT_CLASS {
                unimplemented!("Issue for multiple classes from CAs, issue #25")
            }

            let cmd = TaCmdDet::certify_child(
                parent,
                child.clone(),
                csr,
                limit,
                token,
                self.signer.clone()
            );

            let events = ta.process_command(cmd)?;
            let ta = self.ta_store.update(parent, ta, events)?;

            // Get the newly issued cert for the child. Unwrap here is safe.
            let child = ta.get_child(child).unwrap();
            let resources = child.resources(&class_name).unwrap();
            let issued_cert = resources.cert(&pub_key).unwrap();

            Ok(issued_cert.clone())
        }
    }


    /// Initialises an embedded CA, without any parents (for now).
    pub fn init_ca(
        &mut self,
        handle: &Handle,
        token: Token,
        repo_info: RepoInfo
    ) -> CaResult<(), S> {
        if self.ca_store.has(handle) {
            Err(Error::DuplicateCa(handle.to_string()))
        } else {
            let init = CaIniDet::init(handle, token, repo_info);
            self.ca_store.add(init)?;
            Ok(())
        }
    }

    /// Adds a parent to a ca
    pub fn ca_add_parent(
        &self,
        handle: Handle,
        parent: ParentCaInfo
    ) -> CaResult<(), S> {
        let ca = self.get_ca(&handle)?;
        let (parent_handle, parent_contact) = parent.unwrap();

        let add = CaCmdDet::add_parent(
            &handle,
            parent_handle.as_str(),
            parent_contact
        );
        let events = ca.process_command(add)?;

        self.ca_store.update(&handle, ca, events)?;

        self.update_entitlements(&handle)?;

        Ok(())
    }

    fn update_entitlements(&self, handle: &Handle) -> CaResult<(), S> {

        // Note: we can bail out on serious server side errors, indicating
        // a bug or data corruption issue on our side. However, we should
        // treat error responses from remote parents more carefully, or
        // we would risk that such errors block all CAs from getting
        // updates.

        let ta_handle = ta_handle();

        let mut child = self.ca_store.get_latest(handle)?;

        let parents: Vec<(Handle, ParentCa)> = child.parents()
            .map(|e| (e.0.clone(), e.1.clone()))
            .collect();

        for (parent_handle, parent) in parents {

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
                child = self.ca_store.update(handle, child, events)?;

                let mut issued_certs: Vec<(String, IssuedCert)> = vec![];

                match parent.contact() {
                    ParentCaContact::RemoteKrill(_uri, _token) => {
                        unimplemented!()
                    },
                    ParentCaContact::Embedded(parent_handle, token) => {
                        for cert_req in cert_reqs {
                            let class_name = cert_req.class_name().to_string();
                            let issued = self.issue(
                                parent_handle,
                                &handle,
                                cert_req,
                                token.clone()
                            )?;
                            issued_certs.push((class_name, issued));
                        }
                    }
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
                    child = self.ca_store.update(handle, child, evts)?;
                }
            }
        }
        Ok(())
    }

    /// Update entitlements for all CAs
    pub fn update_all_entitlements(&self) -> CaResult<(), S> {
        for handle in self.ca_store.list() {
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

    #[display(fmt = "{}", _0)]
    TrustAnchorError(trustanchor::Error),

    #[display(fmt = "TrustAnchor was already initialised")]
    TrustAnchorInitialisedError,

    #[display(fmt = "TrustAnchor was not initialised")]
    TrustAnchorNotInitialisedError,

    #[display(fmt = "{}", _0)]
    CaError(ca::Error),

    #[display(fmt = "CA {} was already initialised", _0)]
    DuplicateCa(String),

    #[display(fmt = "CA {} is unknown", _0)]
    UnknownCa(String),

    #[display(fmt = "{}", _0)]
    SignerError(S::Error),

    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),
}

impl<S: CaSigner> From<io::Error> for Error<S> {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl<S: CaSigner> From<trustanchor::Error> for Error<S> {
    fn from(e: trustanchor::Error) -> Self { Error::TrustAnchorError(e) }
}

impl<S: CaSigner> From<ca::Error> for Error<S> {
    fn from(e: ca::Error) -> Self { Error::CaError(e) }
}

impl<S: CaSigner> From<AggregateStoreError> for Error<S> {
    fn from(e: AggregateStoreError) -> Self { Error::AggregateStoreError(e) }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use krill_commons::util::test;
    use krill_commons::util::softsigner::OpenSslSigner;

    #[test]
    fn add_ta() {
        test::test_under_tmp(|d| {
            let signer = OpenSslSigner::build(&d).unwrap();

            let pub_clients = Arc::new(PubClients::build(&d).unwrap());

            let mut server = CaServer::<OpenSslSigner>::build(&d, pub_clients, signer).unwrap();

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

}