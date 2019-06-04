use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use rpki::crypto::PublicKeyFormat;
use rpki::uri;

use krill_commons::api::admin::Token;
use krill_commons::api::ca::{
    IncomingCertificate,
    RepoInfo,
    TrustAnchorInfo,
};
use krill_commons::eventsourcing::{
    Aggregate,
    AggregateStore,
    AggregateStoreError,
    DiskAggregateStore,
};
use crate::trustanchor::{
    self,
    TA_NS,
    ta_handle,
    CaSigner,
    TrustAnchor,
    TrustAnchorCommandDetails,
    TrustAnchorInitDetails,
};
use crate::PubClients;


//------------ CaServer ------------------------------------------------------

pub struct CaServer<S: CaSigner> {
    signer: Arc<S>,
    ta_store: Arc<DiskAggregateStore<TrustAnchor<S>>>
}


impl<S: CaSigner> CaServer<S> {

    pub fn build(
        work_dir: &PathBuf,
        pub_clients: Arc<PubClients>,
        signer: S
    ) -> CaResult<Self, S> {
        let mut ta_store = DiskAggregateStore::<TrustAnchor<S>>::new(work_dir, TA_NS)?;
        ta_store.add_listener(pub_clients);
        Ok(CaServer { signer: Arc::new(signer), ta_store: Arc::new(ta_store) })
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is uninitialized.
    pub fn get_trust_anchor_info(&self) -> CaResult<TrustAnchorInfo, S> {
        self.ta_store
            .get_latest(&ta_handle())
            .map_err(|_| Error::TrustAnchorNotInitialisedError)?
            .as_info()
            .map_err(Error::TrustAnchorError)
    }

    /// Gets the TA certificate, if present. Returns an error if the TA is uninitialized.
    pub fn get_trust_anchor_cert(&self) -> CaResult<IncomingCertificate, S> {
        Ok(self.ta_store
            .get_latest(&ta_handle())
            .map_err(|_| Error::TrustAnchorNotInitialisedError)?
            .cert().clone())
    }

    pub fn init_ta(
        &mut self,
        info: RepoInfo,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>
    ) -> CaResult<(), S> {
        let handle = ta_handle();
        if self.ta_store.has(handle.as_ref()) {
            Err(Error::TrustAnchorInitialisedError)
        } else {
            let key = Arc::make_mut(&mut self.signer)
                .create_key(PublicKeyFormat::default())
                .map_err(Error::SignerError)?;


            let init = TrustAnchorInitDetails::init_with_all_resources(
                &handle,
                info,
                ta_aia,
                ta_uris,
                key,
                self.signer.clone()
            )?;

            self.ta_store.add(handle.as_ref(), init)?;

            Ok(())
        }
    }

    pub fn publish_ta(&self) -> CaResult<(), S> {
        let handle = ta_handle();
        let ta = self.ta_store.get_latest(&handle)?;
        let ta_publish_cmd = TrustAnchorCommandDetails::publish(&handle, self.signer.clone());
        let events = ta.process_command(ta_publish_cmd)?;
        self.ta_store.update(&handle, ta, events)?;

        Ok(())
    }

    /// Generates a random token for embedded CAs
    pub fn random_token(&self) -> Token {
        Token::random(self.signer.as_ref())
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
        test::test_with_tmp_dir(|d| {
            let signer = OpenSslSigner::build(&d).unwrap();

            let pub_clients = Arc::new(PubClients::build(&d).unwrap());

            let mut server = CaServer::<OpenSslSigner>::build(&d, pub_clients, signer).unwrap();

            let repo_info = {
                let base_uri = test::rsync_uri("rsync://localhost/repo/ta/");
                let rrdp_uri = test::https_uri("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ta_uri = test::https_uri("https://localhost/ta/ta.cer");
            let ta_aia = test::rsync_uri("rsync://localhost/repo/ta.cer");

            assert!(server.get_trust_anchor_info().is_err());

            server.init_ta(repo_info.clone(), ta_aia, vec![ta_uri]).unwrap();

            assert!(server.get_trust_anchor_info().is_ok());
        })
    }

}