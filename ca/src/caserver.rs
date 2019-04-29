use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use krill_commons::eventsourcing::{AggregateStore, DiskAggregateStore, AggregateStoreError, Aggregate};
use krill_commons::api::ca::{TrustAnchorInfo, RepoInfo};

use crate::trustanchor::TA_NS;
use crate::trustanchor::ta_handle;
use crate::trustanchor::{TrustAnchor, CaSigner};
use trustanchor;
use krill_commons::util::softsigner::{SignerError};
use trustanchor::{TrustAnchorInitDetails, TrustAnchorCommandDetails};


//------------ CaServer ------------------------------------------------------

pub struct CaServer<S: CaSigner> {
    #[allow(dead_code)]
    signer: S,
    ta_store: Arc<AggregateStore<TrustAnchor<S>>>
}


impl<S: CaSigner> CaServer<S> {

    pub fn build(work_dir: &PathBuf, signer: S) -> CaResult<Self> {
        let ta_store = DiskAggregateStore::<TrustAnchor<S>>::new(work_dir, TA_NS)?;
        Ok(CaServer { signer, ta_store: Arc::new(ta_store) })
    }

    /// Gets the TrustAnchor, if present. Returns an error if the TA is unitialized.
    pub fn get_trust_anchor(&self) -> CaResult<Option<TrustAnchorInfo>> {
        match self.ta_store.get_latest(ta_handle().as_ref()) {
            Ok(ta) => Ok(Some(ta.as_info()?)),
            Err(_) => Ok(None)
        }
    }

    pub fn init_ta(&self, info: RepoInfo) -> CaResult<()> {
        let handle = ta_handle();
        if self.ta_store.has(handle.as_ref()) {
            Err(Error::TrustAnchorInitialisedError)
        } else {
            let init = TrustAnchorInitDetails::init(&handle);
            self.ta_store.add(handle.as_ref(), init)?;

            let ta = self.ta_store.get_latest(&handle)?;

            let init_repo = TrustAnchorCommandDetails::init_repo_info(&handle, info);
            let events = ta.process_command(init_repo)?;

            self.ta_store.update(&handle, ta, events)?;
            Ok(())
        }
    }

}

type CaResult<R> = Result<R, Error>;


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    TrustAnchorError(trustanchor::Error),

    #[display(fmt = "TrustAnchor was already initialised")]
    TrustAnchorInitialisedError,

    #[display(fmt = "{}", _0)]
    SignerError(SignerError),

    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<trustanchor::Error> for Error {
    fn from(e: trustanchor::Error) -> Self { Error::TrustAnchorError(e) }
}

impl From<SignerError> for Error {
    fn from(e: SignerError) -> Self { Error::SignerError(e) }
}

impl From<AggregateStoreError> for Error {
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
            let server = CaServer::<OpenSslSigner>::build(&d, signer).unwrap();

            let repo_info = {
                let base_uri = test::rsync_uri("rsync://localhost/repo/ta/");
                let rrdp_uri = test::http_uri("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            assert_eq!(None, server.get_trust_anchor().unwrap());

            server.init_ta(repo_info.clone()).unwrap();

            assert!(server.get_trust_anchor().is_err()); // Still blows up, until we can compose
            // the actual certificates (in a day or two).
        })
    }

}