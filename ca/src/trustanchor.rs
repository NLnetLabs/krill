use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use chrono::Duration;
use serde::Serialize;
use rand::Rng;

use rpki::cert::{
    Cert,
    KeyUsage,
    Overclaim,
    TbsCert,
};
use rpki::crypto::Signer;
use rpki::csr::Csr;
use rpki::uri;
use rpki::x509::{Serial, Time, Validity, Name};

use krill_commons::api;
use krill_commons::api::{
    DFLT_CLASS,
    EncodedHash,
    Entitlements,
    SigningCert,
};
use krill_commons::api::admin::{
    Handle,
    Token
};
use krill_commons::api::ca::{
    AddedObject,
    AllCurrentObjects,
    CertifiedKey,
    ChildCa,
    ChildCaDetails,
    CurrentObject,
    IssuedCert,
    ObjectName,
    ObjectsDelta,
    PublicationDelta,
    RcvdCert,
    RepoInfo,
    ResourceSet,
    TrustAnchorInfo,
    TrustAnchorLocator,
    UpdatedObject,
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

pub type TaIni = StoredEvent<TaIniDet>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TaIniDet {
    repo_info: RepoInfo,

    children: Vec<ChildCa>,

    current_key: CertifiedKey,
    tal: TrustAnchorLocator,
}

impl TaIniDet {

    /// Generates all the details for a Trust Anchor with all resources.
    pub fn init_with_all_resources<S: CaSigner>(
        handle: &Handle,
        repo_info: RepoInfo,

        ta_aia: uri::Rsync,
        ta_uris: Vec<uri::Https>,

        key: SignerKeyId,
        signer: Arc<RwLock<S>>,
    ) -> TaResult<TaIni> {
        let resources = ResourceSet::all_resources();
        let ta_cert = Self::mk_ta_cer(&repo_info, &resources, &key, signer)?;
        let tal = TrustAnchorLocator::new(ta_uris, &ta_cert);
        let current_key = CertifiedKey::new(key, RcvdCert::new(ta_cert, ta_aia));

        Ok(StoredEvent::new(
            &handle,
            0,
            TaIniDet {
                repo_info,
                children: vec![],
                current_key,
                tal
            }
        ))
    }

    fn mk_ta_cer<S: CaSigner>(
        repo_info: &RepoInfo,
        resources: &ResourceSet,
        key: &S::KeyId,
        signer: Arc<RwLock<S>>
    ) -> TaResult<Cert> {
        let serial: Serial = rand::thread_rng().gen::<u128>().into();

        let signer = signer.read().unwrap();

        let pub_key = signer.get_key_info(&key)
            .map_err(|_| Error::MissingKey)?;
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

        cert.set_ca_repository(Some(repo_info.ca_repository("")));
        cert.set_rpki_manifest(Some(repo_info.rpki_manifest("", &pub_key.key_identifier())));
        cert.set_rpki_notify(Some(repo_info.rpki_notify()));

        cert.set_as_resources(Some(resources.asn().clone()));
        cert.set_v4_resources(Some(resources.v4().deref().clone()));
        cert.set_v6_resources(Some(resources.v6().deref().clone()));

        cert.into_cert(
            signer.deref(),
            key
        ).map_err(Error::signer)
    }
}


//------------ TrustAnchorEvent ----------------------------------------------

pub type TaEvt = StoredEvent<TaEvtDet>;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaEvtDet {
    Published(PublicationDelta),
    ChildAdded(ChildCa),
    CertificateIssued(Handle, String, IssuedCert)
}


impl TaEvtDet {
    fn published(
        handle: &Handle,
        version: u64,
        delta: PublicationDelta
    ) -> TaEvt {
        Self::with_details(handle, version, TaEvtDet::Published(delta))
    }

    fn child_added(handle: &Handle, version: u64, child: ChildCa) -> TaEvt {
        Self::with_details(handle, version, TaEvtDet::ChildAdded(child))
    }

    fn certificate_issued(
        handle: &Handle,
        version: u64,
        child_handle: Handle,
        class_name: &str,
        cert: IssuedCert
    ) -> TaEvt {
        Self::with_details(
            handle,
            version,
            TaEvtDet::CertificateIssued(
                child_handle,
                class_name.to_string(),
                cert
            )
        )
    }

    fn with_details(
        handle: &Handle,
        version: u64,
        details: TaEvtDet
    ) -> TaEvt {
        TaEvt::new(&handle, version, details)
    }
}

//------------ TrustAnchorCommand --------------------------------------------

pub type TaCmd<S> = SentCommand<TaCmdDet<S>>;

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TaCmdDet<S: CaSigner> {
    Republish(Arc<RwLock<S>>),
    AddChild(ChildCa),
    CertifyChild(Handle, Csr, Option<ResourceSet>, Token, Arc<RwLock<S>>)
}

impl<S: CaSigner> CommandDetails for TaCmdDet<S> {
    type Event = TaEvt;
}

impl<S: CaSigner> TaCmdDet<S> {
    pub fn republish(handle: &Handle, signer: Arc<RwLock<S>>) -> TaCmd<S> {
        SentCommand::new(
            handle,
            None,
            TaCmdDet::Republish(signer)
        )
    }

    pub fn add_child(
        handle: &Handle,
        child_handle: Handle,
        child_token: Token,
        child_resources: ResourceSet,
    ) -> TaCmd<S> {
        let mut child = ChildCa::without_resources(child_handle, child_token);
        child.add_resources(DFLT_CLASS, child_resources);

        SentCommand::new(
            handle,
            None,
            TaCmdDet::AddChild(child)
        )
    }

    pub fn certify_child(
        handle: &Handle,
        child_handle: Handle,
        csr: Csr,
        limit: Option<ResourceSet>,
        token: Token,
        signer: Arc<RwLock<S>>
    ) -> TaCmd<S> {
        SentCommand::new(
            handle,
            None,
            TaCmdDet::CertifyChild(child_handle, csr, limit, token, signer)
        )
    }
}


//------------ TrustResult ---------------------------------------------------

/// Helper type for TrustAnchor results
type TaResult<R> = Result<R, Error>;
type TaEvtsRes = TaResult<Vec<TaEvt>>;

//------------ TrustAnchor ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchor<S: CaSigner> {
    handle: Handle,
    version: u64,

    repo_info: RepoInfo,
    current_key: CertifiedKey,
    tal: TrustAnchorLocator,

    children: HashMap<Handle, ChildCaDetails>,

    phantom_signer: PhantomData<S>
}

impl<S: CaSigner> TrustAnchor<S> {
    pub fn as_info(&self) -> TrustAnchorInfo {
        TrustAnchorInfo::new(
            self.resources().clone(),
            self.repo_info.clone(),
            self.children.clone(),
            self.tal.clone()
        )
    }

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
    }

    pub fn cert(&self) -> &RcvdCert {
        self.current_key.incoming_cert()
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.current_key.incoming_cert().resources()
    }

    pub fn repo_info(&self) -> &RepoInfo {
        &self.repo_info
    }

    pub fn current_objects(&self) -> AllCurrentObjects {
        AllCurrentObjects::for_name_space(
            "",
            self.current_key.current_set().objects()
        )
    }

    fn republish(&self, signer: Arc<RwLock<S>>) -> TaEvtsRes {
        if !self.current_key.needs_publication() {
            debug!("TA does not need to be republished");
            return Ok(vec![])
        }

        let ca_repo = self.repo_info.ca_repository("");
        let delta = ObjectsDelta::new(ca_repo);

        let delta = CaSignSupport::publish(
            signer,
            &self.current_key,
            self.repo_info(),
            "",
            delta
        ).map_err(Error::signer)?;

        Ok(vec![TaEvtDet::published(&self.handle, self.version, delta)])
    }

}

/// # Child CA Support
impl<S: CaSigner> TrustAnchor<S> {

    /// Returns an authorized child, or an error if the child is not
    /// authorized or unknown.
    pub fn get_authorised_child(
        &self,
        child: &Handle,
        token: &Token
    ) -> TaResult<&ChildCaDetails> {
        let child = self.get_child(child)?;

        if token != child.token() {
            Err(Error::Unauthorized)
        } else {
            Ok(child)
        }
    }

    pub fn get_child(&self, child: &Handle) -> TaResult<&ChildCaDetails> {
        match self.children.get(child) {
            None => Err(Error::UnknownChild(child.clone())),
            Some(child) => Ok(child)
        }
    }

    fn has_child(&self, handle: &Handle) -> bool {
        self.children.contains_key(handle)
    }


    fn add_child(&self, child: ChildCa) -> TaEvtsRes {
        // check that
        // 1) the resources are held by the TA
        // 2) there is no existing child by this name
        let my_res = self.current_key.incoming_cert().resources();
        for res in child.details().resource_sets() {
            if ! my_res.contains(res) {
                return Err(Error::MissingResources)
            }
        }

        if self.has_child(child.handle()) {
            return Err(Error::DuplicateChild(child.handle().clone()))
        }

        Ok(vec![TaEvtDet::child_added(&self.handle, self.version, child)])
    }

    /// List entitlements (section 3.3.2 of RFC6492). Return an error if
    /// the child is not authorized -- or unknown etc.
    pub fn list(
        &self,
        child_handle: &Handle,
        token: &Token
    ) -> TaResult<api::Entitlements> {
        let child = self.get_authorised_child(child_handle, token)?;

        let child_resources = child.resources(DFLT_CLASS)
            .ok_or_else(|| Error::ChildLacksResources(child_handle.clone()))?;

        let until = child_resources.not_after();
        let issued = child_resources.certs().cloned().collect();

        let cert = self.current_key.incoming_cert();
        let resources = cert.resources().clone();
        let cert = SigningCert::new(cert.uri().clone(), cert.cert().clone());


        Ok(Entitlements::with_default_class(
            cert, resources, until, issued
        ))
    }


    /// Certify a child CA. Returns the events that should be applied to this
    /// CA. Meant to be called by issuing a 'CertifyChild' command.
    fn certify_child(
        &self,
        child: Handle,
        csr: Csr,
        limit: Option<ResourceSet>,
        token: Token,
        signer: Arc<RwLock<S>>
    ) -> TaEvtsRes {
        // verify child and resources
        let child_resources = self.get_authorised_child(&child, &token)?
            .resources(DFLT_CLASS)
            .ok_or_else(|| Error::ChildLacksResources(child.clone()))?;

        let resources = match limit.as_ref() {
            Some(limit) => {
                if child_resources.resources().contains(limit) {
                    limit
                } else {
                    return Err(Error::ChildOverclaims(child.clone()))
                }
            },
            None => child_resources.resources()
        };
        csr.validate()
            .map_err(|_| Error::invalid_csr(&child, "invalid signature"))?;

        // TODO: Check for key-re-use, ultimately return 1204 (RFC6492 3.4.1)
        let current_cert = child_resources.cert(csr.public_key());

        // create new cert
        let issued_cert = {
            let issuing_cert = self.current_key.incoming_cert();

            let serial = {
                Serial::random(signer.read().unwrap().deref())
                    .map_err(Error::signer)?
            };
            let issuer = issuing_cert.cert().subject().clone();

            let validity = Validity::new(
                Time::now() - Duration::minutes(3),
                child_resources.not_after()
            );

            let subject = Some(Name::from_pub_key(csr.public_key()));
            let pub_key = csr.public_key().clone();

            let key_usage = KeyUsage::Ca;
            let overclaim = Overclaim::Refuse;

            let mut cert = TbsCert::new(
                serial, issuer, validity, subject, pub_key, key_usage, overclaim
            );
            cert.set_basic_ca(Some(true));

            // Note! The issuing CA is not authoritative over *where* the child CA
            // may publish. I.e. it will sign over any claimed URIs by the child,
            // and assume that they will not be able to do anything malicious,
            // because the publication server for those URIs should verify the
            // identity of the publisher, and that RPs will not invalidate the
            // content of another CA's repo, if they it is wrongfully claimed.
            let ca_repository = csr.ca_repository()
                .ok_or_else(|| Error::invalid_csr(&child, "missing ca repo"))?;
            let rpki_manifest = csr.rpki_manifest()
                .ok_or_else(|| Error::invalid_csr(&child, "missing mft uri"))?;
            let rpki_notify = csr.rpki_notify();

            cert.set_ca_issuer(Some(issuing_cert.uri().clone()));
            cert.set_crl_uri(Some(issuing_cert.crl_uri()));

            cert.set_ca_repository(Some(ca_repository.clone()));
            cert.set_rpki_manifest(Some(rpki_manifest.clone()));
            cert.set_rpki_notify(rpki_notify.cloned());

            cert.set_as_resources(Some(resources.asn().clone()));
            cert.set_v4_resources(Some(resources.v4().deref().clone()));
            cert.set_v6_resources(Some(resources.v6().deref().clone()));

            cert.set_authority_key_identifier(
                Some(issuing_cert.cert().subject_key_identifier())
            );

            let cert = {
                cert.into_cert(
                    signer.read().unwrap().deref(),
                    self.current_key.key_id()
                ).map_err(Error::signer)?
            };

            let cert_uri = issuing_cert.uri_for_object(&cert);

            IssuedCert::new(cert_uri, resources.clone(), cert)
        };

        let version = self.version;
        let cert_object = CurrentObject::from(issued_cert.cert());

        let issued_event = TaEvtDet::certificate_issued(
            &self.handle,
            version,
            child,
            DFLT_CLASS,
            issued_cert.clone()
        );

        let delta = {
            let ca_repo = self.repo_info.ca_repository("");
            let mut delta = ObjectsDelta::new(ca_repo);
            let cert_name = ObjectName::from(issued_cert.cert());

            match current_cert {
                None => {
                    delta.add(AddedObject::new(cert_name,cert_object))
                },
                Some(old) => {
                    let old_hash = EncodedHash::from_content(
                        old.cert().to_captured().as_slice()
                    );
                    delta.update(UpdatedObject::new(
                        cert_name, cert_object, old_hash
                    ))
                }
            }
            delta
        };

        let publish_event = TaEvtDet::published(
            &self.handle,
            version + 1,
            CaSignSupport::publish(
                signer,
                &self.current_key,
                &self.repo_info,
                "",
                delta
            ).map_err(Error::signer)?
        );

        Ok(vec![issued_event, publish_event])
    }
}

impl<S: CaSigner> Aggregate for TrustAnchor<S> {
    type Command = TaCmd<S>;
    type Event = TaEvt;
    type InitEvent = TaIni;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, init) = event.unwrap();
        let version = 1; // after applying init

        let repo_info = init.repo_info;
        let current_key = init.current_key;
        let tal = init.tal;

        let children = HashMap::new();

        Ok(
            TrustAnchor {
                handle,
                version,
                repo_info,
                current_key,
                tal,
                children,
                phantom_signer: PhantomData
            }
        )
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: TaEvt) {
        self.version += 1;
        match event.into_details() {

            TaEvtDet::Published(delta) => {
                self.current_key.apply_delta(delta);
            },

            TaEvtDet::ChildAdded(child) => {
                let (handle, details) = child.unwrap();
                self.children.insert(handle, details);
            },

            TaEvtDet::CertificateIssued(child, class_name, issued_cert) => {
                let child = self.children.get_mut(&child).unwrap();
                child.add_cert(&class_name, issued_cert)
            }
        }
    }

    fn process_command(&self, cmd: TaCmd<S>) -> TaEvtsRes {
        match cmd.into_details() {

            TaCmdDet::Republish(signer) => {
                self.republish(signer)
            },

            TaCmdDet::AddChild(child) => {
                self.add_child(child)
            },

            TaCmdDet::CertifyChild(child, csr, limit, token, signer) => {
                self.certify_child(child, csr, limit, token, signer)
            }
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

    #[display(fmt = "Not all child resources are held by TA")]
    MissingResources,

    #[display(fmt = "Child {} already exists.", _0)]
    DuplicateChild(Handle),

    #[display(fmt = "Unknown child {}.", _0)]
    UnknownChild(Handle),

    #[display(fmt = "Child {} has no default resource class.", _0)]
    ChildLacksResources(Handle),

    #[display(fmt = "Child {} asks resources beyond entitlement.", _0)]
    ChildOverclaims(Handle),

    #[display(fmt = "Invalidly CSR for child {}: {}.", _0, _1)]
    InvalidCsr(Handle, String),

    #[display(fmt = "Unauthorized request")]
    Unauthorized,
}

impl Error {
    pub fn signer(e: impl Display) -> Self {
        Error::SignerError(e.to_string())
    }

    pub fn invalid_csr(handle: &Handle, msg: &str) -> Self {
        Error::InvalidCsr(handle.clone(), msg.to_string())
    }
}


impl std::error::Error for Error {}
