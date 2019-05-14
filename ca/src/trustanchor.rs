use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use bytes::Bytes;
use serde::Serialize;
use rand::Rng;

use rpki::cert::{TbsCert, KeyUsage, Overclaim, Cert};
use rpki::crypto::Signer;
use rpki::uri;
use rpki::x509::{Validity, Serial, Time};

use krill_commons::api::admin::CaHandle;
use krill_commons::api::ca::{
    ActiveKey,
    RepoInfo,
    ResourceSet,
    TrustAnchorInfo,
    TrustAnchorLocator
};
use krill_commons::eventsourcing::{StoredEvent, SentCommand, CommandDetails, Aggregate};
use krill_commons::util::softsigner::SignerKeyId;
use ::{CurrentObjectSet, PublicationDelta};
use common::{SigningCertificate, PublicationError};

pub const TA_NS: &str = "trustanchors";
pub const TA_ID: &str = "ta";

pub fn ta_handle() -> CaHandle {
    CaHandle::from(TA_ID)
}

//------------ CaSigner ------------------------------------------------------

pub trait CaSigner: Signer<KeyId=SignerKeyId> + Clone + Debug + Serialize + Sized + Sync + Send +'static {}
impl<T: Signer<KeyId=SignerKeyId> + Clone + Debug + Serialize + Sized + Sync + Send + 'static > CaSigner for T {}


//------------ TaCertificate -------------------------------------------------

/// Contains the Trust Anchor certificate. This certificate is created when the TA is
/// initialised, and can live for a 100 years.
///
/// It needs to be published on a https URI, and a TAL needs to be generated for RPs
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TaCertificate {
    cert: Cert,
    uri: uri::Rsync
}

impl TaCertificate {

    pub fn new(cert: Cert, uri: uri::Rsync) -> Self {
        TaCertificate { cert, uri }
    }

    pub fn cert(&self) -> &Cert { &self.cert }
    pub fn uri(&self) -> &uri::Rsync { &self.uri }

    /// Create a TAL file for this TA certificate
    pub fn to_tal(&self, uris: Vec<uri::Https>) -> TrustAnchorLocator {
        TrustAnchorLocator::new(uris, &self.cert)
    }

    pub fn der_encoded(&self) -> Bytes {
        self.cert.to_captured().into_bytes()
    }
}

impl AsRef<Cert> for TaCertificate {
    fn as_ref(&self) -> &Cert {
        &self.cert
    }
}

impl PartialEq for TaCertificate {
    fn eq(&self, other: &TaCertificate) -> bool {
        self.cert.to_captured().into_bytes() == other.cert.to_captured().into_bytes() &&
        self.uri == other.uri
    }
}

impl Eq for TaCertificate {}


//------------ TaResourceAuthority -------------------------------------------

/// This type describes the resources and authority for a Trust Anchor,
/// i.e. all that's needed for a Trust Anchor to sign its own self-signed
/// CA certificate, publish the TAL, and sign products (CA certs) for
/// subsidiary CAs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaResourceAuthority {
    resources: ResourceSet,
    key: ActiveKey,
    ta_cert: TaCertificate,
    tal: TrustAnchorLocator,
    current_objects: Option<CurrentObjectSet>
}

/// # Create / Update
impl TaResourceAuthority {
    pub fn new(
        resources: ResourceSet,
        key: ActiveKey,
        ta_cert: TaCertificate,
        tal: TrustAnchorLocator,
        current_objects: Option<CurrentObjectSet>
    ) -> Self {
        TaResourceAuthority {
            resources, key, ta_cert, tal, current_objects
        }
    }

    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        match self.current_objects.take() {
            None => self.current_objects = Some(CurrentObjectSet::from(delta)),
            Some(mut set) => {
                set.apply_delta(delta);
                self.current_objects = Some(set)
            }
        }
    }

    pub fn set_current_objects(&mut self, current_objects: CurrentObjectSet) {
        self.current_objects = Some(current_objects)
    }
}

/// # Accessors
impl TaResourceAuthority {
    pub fn resources(&self) -> &ResourceSet { &self.resources }
    pub fn key(&self) -> &ActiveKey { &self.key }
    pub fn ta_cert(&self) -> &TaCertificate { &self.ta_cert }
    pub fn tal(&self) -> &TrustAnchorLocator { &self.tal }
    pub fn current_objects(&self) -> Option<&CurrentObjectSet> {
        self.current_objects.as_ref()
    }
}

//------------ TrustAnchorInit -----------------------------------------------

pub type TrustAnchorInit = StoredEvent<TrustAnchorInitDetails>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchorInitDetails(());

impl TrustAnchorInitDetails {
    pub fn init(handle: &CaHandle) -> TrustAnchorInit {
        TrustAnchorInit::new(handle.as_ref(), 0, TrustAnchorInitDetails(()))
    }
}


//------------ TrustAnchorEvent ----------------------------------------------

pub type TrustAnchorEvent = StoredEvent<TrustAnchorEventDetails>;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorEventDetails {
    RepoInfoAdded(RepoInfo),
    AuthAdded(TaResourceAuthority),
    Published(PublicationDelta)
}


impl TrustAnchorEventDetails {
    pub fn repo_info_added(ta: &CaHandle, v: u64, info: RepoInfo) -> TrustAnchorEvent {
        Self::with_details(ta, v, TrustAnchorEventDetails::RepoInfoAdded(info))
    }

    pub fn auth_added(ta: &CaHandle, v: u64, auth: TaResourceAuthority) -> TrustAnchorEvent {
        Self::with_details(ta, v, TrustAnchorEventDetails::AuthAdded(auth))
    }

    pub fn published(ta: &CaHandle, v: u64, delta: PublicationDelta) -> TrustAnchorEvent {
        Self::with_details(ta, v, TrustAnchorEventDetails::Published(delta))
    }

    fn with_details(ta: &CaHandle, version: u64, details: TrustAnchorEventDetails) -> TrustAnchorEvent {
        TrustAnchorEvent::new(ta.as_ref(), version, details)
    }
}

//------------ TrustAnchorCommand --------------------------------------------

pub type TrustAnchorCommand<S> = SentCommand<TrustAnchorCommandDetails<S>>;

#[derive(Clone, Debug)]
pub enum TrustAnchorCommandDetails<S: CaSigner> {
    AddRepoInfo(RepoInfo),
    AddAuth(ResourceSet, uri::Rsync, Vec<uri::Https>, S::KeyId, Arc<S>),
    Publish(Arc<S>)
}

impl<S: CaSigner> CommandDetails for TrustAnchorCommandDetails<S> {
    type Event = TrustAnchorEvent;
}

impl<S: CaSigner> TrustAnchorCommandDetails<S> {
    pub fn add_repo_info(
        ta: &CaHandle,
        repo_info: RepoInfo
    ) -> TrustAnchorCommand<S> {
        let details = TrustAnchorCommandDetails::AddRepoInfo(repo_info);
        SentCommand::new(
            ta.as_ref(),
            None,
            details
        )
    }

    pub fn init_with_all_resources(
        ta: &CaHandle,
        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,
        key: S::KeyId,
        signer: Arc<S>,
    ) -> TrustAnchorCommand<S> {

        let resources = {
            let asns = "AS0-AS4294967295";
            let v4 = "0.0.0.0/0";
            let v6 = "::/0";
            ResourceSet::from_strs(asns, v4, v6).unwrap()
        };

        let details = TrustAnchorCommandDetails::AddAuth(resources, ta_aia, ta_uris, key, signer);
        SentCommand::new(ta.as_ref(), None, details)
    }

    pub fn publish(ta: &CaHandle, signer: Arc<S>) -> TrustAnchorCommand<S> {
        SentCommand::new(ta.as_ref(), None, TrustAnchorCommandDetails::Publish(signer))
    }
}


//------------ TrustResult ---------------------------------------------------

/// Helper type for TrustAnchor results
type TaResult<R, S> = Result<R, Error<S>>;

//------------ TrustAnchor ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchor<S: CaSigner> {
    id: CaHandle,
    version: u64,

    authority: Option<TaResourceAuthority>,
    repo_info: Option<RepoInfo>,

    phantom_signer: PhantomData<S>
}

impl<S: CaSigner> TrustAnchor<S> {
    pub fn as_info(&self) -> TaResult<TrustAnchorInfo, S> {
        let resources = self.resources()?;
        let repo_info = self.repo_info()?;
        let tal = self.tal()?;

        Ok(TrustAnchorInfo::new(resources.clone(), repo_info.clone(), tal.clone()))
    }

    fn authority(&self) -> TaResult<&TaResourceAuthority, S> {
        self.authority.as_ref().ok_or_else(|| Error::NotInitialised)
    }

    pub fn tal(&self) -> TaResult<&TrustAnchorLocator, S> {
        Ok(&self.authority()?.tal)
    }

    pub fn cert(&self) -> TaResult<&TaCertificate, S> {
        Ok(&self.authority()?.ta_cert)
    }

    pub fn resources(&self) -> TaResult<&ResourceSet, S> {
        Ok(&self.authority()?.resources)
    }

    pub fn repo_info(&self) -> TaResult<&RepoInfo, S> {
        self.repo_info.as_ref().ok_or_else(|| Error::RepoInfoMissing)
    }

    fn create_ta_cert(
        &self,
        key: &S::KeyId,
        resources: &ResourceSet,
        signer: Arc<S>
    ) -> TaResult<Cert, S> {
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

        let repo_info = self.repo_info.as_ref().ok_or_else(|| Error::RepoInfoMissing)?;
        cert.set_ca_repository(Some(repo_info.signed_object()));
        cert.set_rpki_manifest(Some(repo_info.rpki_manifest(&pub_key)));
        cert.set_rpki_notify(Some(repo_info.rpki_notify()));

        cert.set_as_resources(Some(resources.asn().clone()));
        cert.set_v4_resources(Some(resources.v4().deref().clone()));
        cert.set_v6_resources(Some(resources.v6().deref().clone()));

        let cert = cert
            .into_cert(signer.as_ref(), key)
            .map_err(|_| Error::SignerError)?.to_captured();
        let cert_slice = cert.as_slice();

        Ok(Cert::decode(cert_slice).map_err(|_| Error::malformed(cert_slice))?)
    }

}

impl<S: CaSigner> Aggregate for TrustAnchor<S> {
    type Command = TrustAnchorCommand<S>;
    type Event = TrustAnchorEvent;
    type InitEvent = TrustAnchorInit;
    type Error = Error<S>;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (id, _version, _init) = event.unwrap();
        let id = CaHandle::from(id);
        let version = 1; // after applying init

        Ok(
            TrustAnchor {
                id,
                version,
                authority: None,
                repo_info: None,
                phantom_signer: PhantomData
            }
        )
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        match event.into_details() {
            TrustAnchorEventDetails::RepoInfoAdded(info) => {
                self.repo_info = Some(info);
            },
            TrustAnchorEventDetails::AuthAdded(auth) => {
                self.authority = Some(auth);
            },
            TrustAnchorEventDetails::Published(delta) => {
                // Event can only occur if authority was initialised
                match self.authority.take() {
                    None => panic!("Received publish event before authority was added"),
                    Some(mut auth) => auth.apply_delta(delta)
                }
            }
        }
        self.version += 1;
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        match command.into_details() {
            TrustAnchorCommandDetails::AddRepoInfo(repo_info) => {
                if self.repo_info.is_some() {
                    Err(Error::RepoInfoAlreadyInitialised)
                } else {
                    Ok(vec![TrustAnchorEventDetails::repo_info_added(
                        &self.id,
                        self.version,
                        repo_info
                    )])
                }
            },
            TrustAnchorCommandDetails::AddAuth(resources, ta_aia, ta_uris, key, signer) => {
                let cert = self.create_ta_cert(&key, &resources, signer)?;
                let tal = TrustAnchorLocator::new(ta_uris, &cert);

                let cert = TaCertificate::new(cert, ta_aia);
                let key = ActiveKey::new(key);

                let authority = TaResourceAuthority::new(
                    resources, key, cert, tal, None
                );

                Ok(vec![TrustAnchorEventDetails::auth_added(
                    &self.id,
                    self.version,
                    authority
                )])
            },
            TrustAnchorCommandDetails::Publish(signer) => {
                let auth = self.authority.as_ref().ok_or_else(|| Error::NotInitialised)?;
                let repo_info = self.repo_info.as_ref().ok_or_else(|| Error::RepoInfoMissing)?;

                let aia = auth.ta_cert().uri();

                let signing_cert = SigningCertificate::new(
                    auth.key().key_id(),
                    auth.ta_cert().cert(),
                    aia
                );

                let delta = PublicationDelta::publish(
                    signer,
                    signing_cert,
                    auth.current_objects(),
                    repo_info
                )?;

                Ok(vec![TrustAnchorEventDetails::published(
                    &self.id,
                    self.version,
                    delta
                )])
            }
        }
    }
}



//------------ Error ---------------------------------------------------------

/// Trust Anchor Errors
#[derive(Debug, Display)]
pub enum Error<S: CaSigner> {
    #[display(fmt = "Cannot find key.")]
    MissingKey,

    #[display(fmt = "Error while signing.")]
    SignerError,

    #[display(fmt = "Generated a malformed object: {}", _0)]
    GeneratedMalformedObject(String),

    #[display(fmt = "RepoInfo already was initialised.")]
    RepoInfoAlreadyInitialised,

    #[display(fmt = "Repository information was not configured.")]
    RepoInfoMissing,

    #[display(fmt = "Resource Authority was not initialised.")]
    NotInitialised,

    #[display(fmt = "{}", _0)]
    PublicationError(PublicationError<S>),
}

impl<S: CaSigner> Error<S> {
    pub fn malformed(object: &[u8]) -> Error<S> {
        let string = base64::encode(object);
        Error::GeneratedMalformedObject(string)
    }
}

impl<S: CaSigner> std::error::Error for Error<S> {}

impl<S: CaSigner> From<PublicationError<S>> for Error<S> {
    fn from(e: PublicationError<S>) -> Self { Error::PublicationError(e) }
}


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
    fn serde_repo_event() {
        let repo_info = {
            let base_uri = test::rsync_uri("rsync://localhost/repo/ta/");
            let rrdp_uri = test::https_uri("https://localhost/repo/notifcation.xml");
            RepoInfo::new(base_uri, rrdp_uri)
        };
        let handle = ta_handle();
        let event = TrustAnchorEventDetails::repo_info_added(&handle, 1, repo_info);

        let json = serde_json::to_string(&event).unwrap();
        let deser_event: StoredEvent<TrustAnchorEventDetails> = serde_json::from_str(&json).unwrap();

        assert_eq!(event.into_details(), deser_event.into_details());
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
                let rrdp_uri = test::https_uri("https://localhost/repo/notifcation.xml");
                RepoInfo::new(base_uri, rrdp_uri)
            };

            let init_repo_cmd = TrustAnchorCommandDetails::add_repo_info(&handle, repo_info);
            let events = ta.process_command(init_repo_cmd).unwrap();
            let ta = store.update(handle.as_ref(), ta, events).unwrap();

            let mut signer = signer(&d);
            let key = signer.create_key(PublicKeyFormat::default()).unwrap();
            let signer = Arc::new(signer);

            let ta_uri = test::https_uri("https://localhost/tal/ta.cer");
            let ta_aia = test::rsync_uri("rsync://localhost/repo/ta.cer");

            let init_ta_cert_cmd = TrustAnchorCommandDetails::init_with_all_resources(
                &handle, ta_aia, vec![ta_uri], key, signer.clone()
            );

            let events = ta.process_command(init_ta_cert_cmd).unwrap();
            let ta = store.update(handle.as_ref(), ta, events).unwrap();
            assert!(ta.tal().is_ok());

            let publish_cmd = TrustAnchorCommandDetails::publish(&handle, signer);
            let events = ta.process_command(publish_cmd).unwrap();
            let _ta = store.update(handle.as_ref(), ta, events).unwrap();


        })
    }


}