use std::marker::PhantomData;
use std::fmt::Debug;
use std::sync::Arc;

use serde::Serialize;

use rpki::cert::{CertBuilder, Validity};
use rpki::crypto::Signer;

use krill_commons::api::admin::CaHandle;
use krill_commons::api::ca::{RepoInfo, ResourceClass, ResourceSet, TrustAnchorInfo};
use krill_commons::eventsourcing::{StoredEvent, SentCommand, CommandDetails, Aggregate};

pub const TA_NS: &str = "trustanchors";
pub const TA_ID: &str = "ta";

pub fn ta_handle() -> CaHandle {
    CaHandle::from(TA_ID)
}

//------------ CaSigner ------------------------------------------------------

pub trait CaSigner: Signer + Clone + Debug + Serialize + Sized + Sync + Send +'static {}
impl<T: Signer + Clone + Debug + Serialize + Sized + Sync + Send + 'static > CaSigner for T {}

//------------ TrustAnchorInit -----------------------------------------------

pub type TrustAnchorInit = StoredEvent<TrustAnchorInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchorInitDetails;

impl TrustAnchorInitDetails {
    pub fn init(handle: &CaHandle) -> TrustAnchorInit {
        TrustAnchorInit::new(handle.as_ref(), 0, TrustAnchorInitDetails)
    }
}


//------------ TrustAnchorEvent ----------------------------------------------

pub type TrustAnchorEvent = StoredEvent<TrustAnchorEventDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum TrustAnchorEventDetails {
    RepoInfoInitialised(RepoInfo),
}


impl TrustAnchorEventDetails {
    pub fn repo_info_initialised(ta: &CaHandle, version: u64, info: RepoInfo) -> TrustAnchorEvent {
        Self::with_details(ta, version, TrustAnchorEventDetails::RepoInfoInitialised(info))
    }

    fn with_details(ta: &CaHandle, version: u64, details: TrustAnchorEventDetails) -> TrustAnchorEvent {
        TrustAnchorEvent::new(ta.as_ref(), version, details)
    }
}

//------------ TrustAnchorCommand --------------------------------------------

pub type TrustAnchorCommand<S> = SentCommand<TrustAnchorCommandDetails<S>>;

#[derive(Clone, Debug)]
pub enum TrustAnchorCommandDetails<S: CaSigner> {
    InitRepoInfo(RepoInfo),
    InitResourceClass(S::KeyId, ResourceSet, Arc<S>),
}

impl<S: CaSigner> CommandDetails for TrustAnchorCommandDetails<S> {
    type Event = TrustAnchorEvent;
}

impl<S: CaSigner> TrustAnchorCommandDetails<S> {
    pub fn init_repo_info(
        ta: &CaHandle,
        repo_info: RepoInfo
    ) -> TrustAnchorCommand<S> {
        let details = TrustAnchorCommandDetails::InitRepoInfo(repo_info);
        SentCommand::new(
            ta.as_ref(),
            None,
            details
        )
    }

    pub fn init_with_all_resources(
        ta: &CaHandle,
        key: S::KeyId,
        signer: Arc<S>
    ) -> TrustAnchorCommand<S> {

        let resources = {
            let asns = "AS0-AS4294967295";
            let v4 = "0.0.0.0/0";
            let v6 = "::/0";
            ResourceSet::from_strs(asns, v4, v6).unwrap()
        };

        let details = TrustAnchorCommandDetails::InitResourceClass(key, resources, signer);
        SentCommand::new(ta.as_ref(), None, details)
    }
}

//------------ TrustAnchor ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchor<S: CaSigner> {
    id: CaHandle,
    version: u64,

    resource_class: Option<ResourceClass>,
    repo_info: Option<RepoInfo>,

    phantom_signer: PhantomData<S>
}

impl<S: CaSigner> TrustAnchor<S> {
    pub fn as_info(&self) -> Result<TrustAnchorInfo, Error> {
        let resource_class = self.resource_class.as_ref()
            .ok_or_else(|| Error::ResourceClassMissing)?;
        let repo_info = self.repo_info.as_ref()
            .ok_or_else(|| Error::RepoInfoMissing)?;

        Ok(TrustAnchorInfo::new(resource_class.clone(), repo_info.clone()))
    }
}

impl<S: CaSigner> Aggregate for TrustAnchor<S> {
    type Command = TrustAnchorCommand<S>;
    type Event = TrustAnchorEvent;
    type InitEvent = TrustAnchorInit;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (id, _version, _init) = event.unwrap();
        let id = CaHandle::from(id);
        let version = 1; // after applying init

        Ok(
            TrustAnchor {
                id,
                version,
                resource_class: None,
                repo_info: None,
                phantom_signer: PhantomData
            }
        )
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        match event.details() {
            TrustAnchorEventDetails::RepoInfoInitialised(info) => {
                self.repo_info = Some(info.clone())
            }
        }
        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        match command.into_details() {
            TrustAnchorCommandDetails::InitRepoInfo(repo_info) => {
                if self.repo_info.is_some() {
                    Err(Error::RepoInfoAlreadyInitialised)
                } else {
                    Ok(vec![TrustAnchorEventDetails::repo_info_initialised(
                        &self.id,
                        self.version,
                        repo_info
                    )])
                }
            },
            TrustAnchorCommandDetails::InitResourceClass(key, _resources, signer) => {
                let _repo_info = self.repo_info.as_ref().ok_or_else(|| Error::RepoInfoMissing)?;

                let pub_key = signer.get_key_info(&key).map_err(|_| Error::MissingKey)?;

                let mut _builder = CertBuilder::new(
                    1, // Self-signed TA cert can always use serial 1 - never revoked
                    pub_key.to_subject_name(),
                    Validity::from_secs(100 * 365 * 24 * 60 * 60), // slightly less than 100 years
                    true
                );



//                builder.rpki_manifest(repo_info.rpki_manifest(&pub_key))
//                    .signed_object(repo_info.signed_object())
//                    .rpki_notify(repo_info.rpki_notify());





                unimplemented!()
            }
        }
    }
}



#[derive(Clone, Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot find key.")]
    MissingKey,

    #[display(fmt = "Error while signing.")]
    SignerError,

    #[display(fmt = "RepoInfo already was initialised.")]
    RepoInfoAlreadyInitialised,

    #[display(fmt = "Repository information was not configured.")]
    RepoInfoMissing,

    #[display(fmt = "TrustAnchor key and resources were not initialised.")]
    ResourceClassMissing,
}

impl std::error::Error for Error {}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::path::PathBuf;
    use krill_commons::util::test;
    use krill_commons::eventsourcing::Aggregate;
    use krill_commons::eventsourcing::AggregateStore;
    use krill_commons::eventsourcing::DiskAggregateStore;
    use krill_commons::util::softsigner::OpenSslSigner;
    use rpki::crypto::signer::Signer;
    use rpki::crypto::PublicKeyFormat;

    fn signer(temp_dir: &PathBuf) -> OpenSslSigner {
        let signer_dir = test::create_sub_dir(temp_dir);
        OpenSslSigner::build(&signer_dir).unwrap()
    }

    #[test]
    fn init_ta_with_repo_and_resources() {
        test::test_with_tmp_dir(|d| {
            let store = DiskAggregateStore::<TrustAnchor<OpenSslSigner>>::new(&d, TA_NS).unwrap();
            let handle = ta_handle();

            let init = TrustAnchorInitDetails::init(&handle);
            store.add(handle.as_ref(), init).unwrap();
            let ta = store.get_latest(handle.as_ref()).unwrap();

            let repo_info = {
                let base_uri = test::rsync_uri("rsync://localhost/repo/ta/");
                let rrdp_uri = test::http_uri("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let init_repo_cmd = TrustAnchorCommandDetails::init_repo_info(&handle, repo_info);
            let events = ta.process_command(init_repo_cmd).unwrap();
            let _ta = store.update(handle.as_ref(), ta, events).unwrap();

            let mut signer = signer(&d);
            let key = signer.create_key(PublicKeyFormat).unwrap();
            let signer_arc = Arc::new(signer);

            let _init_ta_cert_cmd = TrustAnchorCommandDetails::init_with_all_resources(
                &handle, key, signer_arc
            );

//            let events = ta.process_command(init_ta_cert_cmd).unwrap();
//
//            let sign_command = TrustAnchorCommandDetails::sign_ta_cert(&handle, signer_arc.clone());
//
//            let _events = ta.process_command(sign_command).unwrap();

        })
    }


}