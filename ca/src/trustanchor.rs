use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use serde::Serialize;
use rand::Rng;

use rpki::cert::{
    Cert,
    KeyUsage,
    Overclaim,
    TbsCert,
};
use rpki::crypto::Signer;
use rpki::uri;
use rpki::x509::{
    Serial,
    Time,
    Validity,
};
use krill_commons::api::admin::Handle;
use krill_commons::api::ca::{
    CaKey,
    CurrentObjects,
    IncomingCertificate,
    PublicationDelta,
    RepoInfo,
    ResourceSet,
    TrustAnchorInfo,
    TrustAnchorLocator,
};
use krill_commons::eventsourcing::{
    Aggregate,
    CommandDetails,
    SentCommand,
    StoredEvent,
};
use krill_commons::util::softsigner::SignerKeyId;

use crate::signing::CaSignSupport;

pub const TA_NS: &str = "trustanchors";
pub const TA_ID: &str = "ta";

pub fn ta_handle() -> Handle {
    Handle::from(TA_ID)
}

//------------ CaSigner ------------------------------------------------------

pub trait CaSigner: Signer<KeyId=SignerKeyId> + Clone + Debug + Serialize + Sized + Sync + Send +'static {}
impl<T: Signer<KeyId=SignerKeyId> + Clone + Debug + Serialize + Sized + Sync + Send + 'static > CaSigner for T {}


//------------ TrustAnchorInit -----------------------------------------------

pub type TrustAnchorInit = StoredEvent<TrustAnchorInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchorInitDetails {
    repo_info: RepoInfo,
    current_key: CaKey,
    tal: TrustAnchorLocator,
}

impl TrustAnchorInitDetails {

    /// Generates all the details for a Trust Anchor with all resources.
    pub fn init_with_all_resources<S: CaSigner>(
        handle: &Handle,
        repo_info: RepoInfo,

        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,

        key: SignerKeyId,
        signer: Arc<S>,
    ) -> TaResult<TrustAnchorInit> {
        let resources = ResourceSet::all_resources();
        let ta_cert = Self::create_ta_cert(&repo_info, &resources, &key, signer)?;
        let tal = TrustAnchorLocator::new(ta_uris, &ta_cert);
        let current_key = CaKey::new(key, IncomingCertificate::new(ta_cert, ta_aia));

        Ok(StoredEvent::new(
            &handle,
            0,
            TrustAnchorInitDetails { repo_info, current_key, tal}
        ))
    }

    fn create_ta_cert<S: CaSigner>(
        repo_info: &RepoInfo,
        resources: &ResourceSet,
        key: &S::KeyId,
        signer: Arc<S>
    ) -> TaResult<Cert> {
        let serial: Serial = rand::thread_rng().gen::<u128>().into();
        let pub_key = signer.get_key_info(&key).map_err(|_| Error::MissingKey)?;
        let name = pub_key.to_subject_name();

        let mut cert = TbsCert::new(
            serial,
            name.clone(),
            Validity::new(Time::now(), Time::years_from_now(100)),
            Some(name),
            pub_key.clone(),
            KeyUsage::Ca,
            Overclaim::Refuse
        );

        cert.set_basic_ca(Some(true));

        cert.set_ca_repository(Some(repo_info.signed_object("")));
        cert.set_rpki_manifest(Some(repo_info.mft_uri("", &pub_key)));
        cert.set_rpki_notify(Some(repo_info.rpki_notify()));

        cert.set_as_resources(Some(resources.asn().clone()));
        cert.set_v4_resources(Some(resources.v4().deref().clone()));
        cert.set_v6_resources(Some(resources.v6().deref().clone()));

        cert.into_cert(signer.as_ref(), key).map_err(|e| Error::signer_error(e))
    }
}


//------------ TrustAnchorEvent ----------------------------------------------

pub type TrustAnchorEvent = StoredEvent<TrustAnchorEventDetails>;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorEventDetails {
    Published(PublicationDelta)
}


impl TrustAnchorEventDetails {
    pub fn published(
        handle: &Handle,
        version: u64,
        delta: PublicationDelta
    ) -> TrustAnchorEvent {
        Self::with_details(
            handle,
            version,
            TrustAnchorEventDetails::Published(delta)
        )
    }

    fn with_details(
        handle: &Handle,
        version: u64,
        details: TrustAnchorEventDetails
    ) -> TrustAnchorEvent {
        TrustAnchorEvent::new(&handle, version, details)
    }
}

//------------ TrustAnchorCommand --------------------------------------------

pub type TrustAnchorCommand<S> = SentCommand<TrustAnchorCommandDetails<S>>;

#[derive(Clone, Debug)]
pub enum TrustAnchorCommandDetails<S: CaSigner> {
    Publish(Arc<S>)
}

impl<S: CaSigner> CommandDetails for TrustAnchorCommandDetails<S> {
    type Event = TrustAnchorEvent;
}

impl<S: CaSigner> TrustAnchorCommandDetails<S> {
    pub fn publish(handle: &Handle, signer: Arc<S>) -> TrustAnchorCommand<S> {
        SentCommand::new(
            &handle,
            None,
            TrustAnchorCommandDetails::Publish(signer)
        )
    }
}


//------------ TrustResult ---------------------------------------------------

/// Helper type for TrustAnchor results
type TaResult<R> = Result<R, Error>;

//------------ TrustAnchor ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchor<S: CaSigner> {
    id: Handle,
    version: u64,

    repo_info: RepoInfo,
    current_key: CaKey,
    tal: TrustAnchorLocator,

    phantom_signer: PhantomData<S>
}

impl<S: CaSigner> TrustAnchor<S> {
    pub fn as_info(&self) -> TaResult<TrustAnchorInfo> {
        let resources = self.resources();
        let repo_info = self.repo_info();
        let tal = self.tal();

        Ok(TrustAnchorInfo::new(resources.clone(), repo_info.clone(), tal.clone()))
    }

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
    }

    pub fn cert(&self) -> &IncomingCertificate {
        self.current_key.incoming_cert()
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.current_key.incoming_cert().resources()
    }

    pub fn repo_info(&self) -> &RepoInfo {
        &self.repo_info
    }

    pub fn current_objects(&self) -> &CurrentObjects {
        &self.current_key.current_set().objects()
    }

}


impl<S: CaSigner> TrustAnchor<S> {
    fn publish(&self, signer: Arc<S>) -> TaResult<Vec<TrustAnchorEvent>> {
        let delta = CaSignSupport::publish(
            signer,
            &self.current_key,
            self.repo_info(),
            ""
        ).map_err(|e| Error::signer_error(e))?;

        Ok(vec![TrustAnchorEventDetails::published(&self.id, self.version, delta)])
    }
}

impl<S: CaSigner> Aggregate for TrustAnchor<S> {
    type Command = TrustAnchorCommand<S>;
    type Event = TrustAnchorEvent;
    type InitEvent = TrustAnchorInit;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (id, _version, init) = event.unwrap();
        let id = Handle::from(id);
        let version = 1; // after applying init

        let repo_info = init.repo_info;
        let current_key = init.current_key;
        let tal = init.tal;

        Ok(
            TrustAnchor {
                id,
                version,
                repo_info,
                current_key,
                tal,
                phantom_signer: PhantomData
            }
        )
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        self.version += 1;
        match event.into_details() {
            TrustAnchorEventDetails::Published(delta) => {
                self.current_key.apply_delta(delta)
            }
        }
    }

    fn process_command(&self, command: Self::Command) -> TaResult<Vec<TrustAnchorEvent>> {
        match command.into_details() {
            TrustAnchorCommandDetails::Publish(signer) => self.publish(signer)
        }
    }
}



//------------ Error ---------------------------------------------------------

/// Trust Anchor Errors
#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot find key.")]
    MissingKey,

    #[display(fmt = "Error while signing: {}", _0)]
    SignerError(String),

    #[display(fmt = "Resource Authority was not initialised.")]
    NotInitialised,
}

impl Error {
    pub fn signer_error(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }
}


impl std::error::Error for Error {}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::path::PathBuf;
    use krill_commons::util::test;
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

            let repo_info = {
                let base_uri = test::rsync_uri("rsync://localhost/repo/ta/");
                let rrdp_uri = test::https_uri("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let ta_uri = test::https_uri("https://localhost/tal/ta.cer");
            let ta_aia = test::rsync_uri("rsync://localhost/repo/ta.cer");

            let mut signer = signer(&d);
            let key = signer.create_key(PublicKeyFormat::default()).unwrap();
            let signer = Arc::new(signer);

            let init = TrustAnchorInitDetails::init_with_all_resources(
                &handle,
                repo_info,
                ta_aia,
                vec![ta_uri],
                key,
                signer.clone()
            ).unwrap();

            store.add(init).unwrap();
            let ta = store.get_latest(&handle).unwrap();

            let publish_cmd = TrustAnchorCommandDetails::publish(&handle, signer);
            let events = ta.process_command(publish_cmd).unwrap();
            let _ta = store.update(&handle, ta, events).unwrap();


        })
    }

    #[test]
    fn should_deserialize_ta_publish_event() {
        let string = include_str!("../test-resources/delta-1.json");
        let _event: TrustAnchorEvent = serde_json::from_str(string).unwrap();
    }


}