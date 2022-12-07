//! Support for operating a Trust Anchor in Krill.
//!
use std::{collections::HashMap, convert::TryInto, fmt, sync::Arc};

use rpki::{
    ca::{
        idexchange::{CaHandle, ChildHandle, RepoInfo},
        provisioning::{self, RequestResourceLimit},
    },
    crypto::KeyIdentifier,
    repository::{
        cert::{KeyUsage, Overclaim, TbsCert},
        resources::ResourceSet,
        x509::{Serial, Time, Validity},
    },
    uri,
};
use uuid::Uuid;

use crate::{
    commons::{
        actor::Actor,
        api::{
            IdCertInfo, IssuedCertificate, ObjectName, ReceivedCert, RepositoryContact, Revocations, TaCertDetails,
            TrustAnchorLocator,
        },
        crypto::{KrillSigner, SignSupport},
        error::Error,
        eventsourcing, KrillResult,
    },
    daemon::ca::{ObjectSetRevision, PublishedCrl, PublishedManifest, UsedKeyState},
};

use super::{CrlBuilder, ManifestBuilder, Rfc8183Id};

//------------ TrustAnchor Handle Types ------------------------------------

pub type TrustAnchorHandle = CaHandle;

//------------ TrustAnchorProxy --------------------------------------------

/// Krill Trust Anchors are split into the following two components:
///   - Trust Anchor Proxy
///   - Trust Anchor Signer
///
/// The Trust Anchor Proxy performs all Trust Anchor responsibilities
/// *except* for signing using the Trust Anchor private key. That function
/// is handled by the Trust Anchor Signer instead. The reason for this
/// division is that it allows for operations where the signer is kept
/// on a separate offline system. The proxy on the other hand can maintain
/// the communication with child CAs and take care of publication.
///
/// Note however, that the signer can also be be embedded to support test
/// systems as well as functional and regression testing of the proxy-signer
/// communication.
///
/// Another (unrelated) thing to note is that Krill Trust Anchors are, for
/// the moment, set up to always claim all IPv4, IPv6 and ASN resources. This
/// is inline with how the current RIR Trust Anchors are being managed at the
/// moment. That said, we may add support for claiming (and changing) a
/// specific set of resources in future.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchorProxy {
    // event-sourcing support
    handle: TrustAnchorHandle,
    version: u64,

    // ID certificate used by this proxy
    id: IdCertInfo,

    // The associated signer. Needs to be added after initialisation.
    signer: Option<TrustAnchorProxySignerInfo>,

    // The proxy is responsible for publishing all objects.
    repository: Option<RepositoryContact>,

    // Typically the Trust Anchor would be set up with a single child, that
    // gets a certificate with all resources. This child can then be the
    // de-facto *online* trust anchor in setups where the Trust Anchor Signer
    // is kept offline. This is useful because signing certificates to many
    // children - and especially updating their resources - directly under
    // an offline signer would be cumbersome, or at the very least add significant
    // delays in operation.
    //
    // But, there may be use cases for multiple children under the Trust Anchor.
    // In particular for testing purposes where the signer is not offline.
    //
    // For this reason we support any number of child CAs to exist under
    // the TA.
    child_details: HashMap<ChildHandle, TrustAnchorChild>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxySignerInfo {
    // The ide of the associated signer.
    id: IdCertInfo,
    // Trust Anchor objects to be published
    objects: TrustAnchorObjects,
    // The TA certificate and TAL
    ta_cert_details: TaCertDetails,
}

/// Contains all Trust Anchor objects, including the the TA certificate
/// and TAL.
///
/// This is kept by the Trust Anchor Proxy as read-only, so that it can
/// publish these objects.
///
/// The Trust Anchor Signer can make changes to this set based on the
/// requests it gets from the proxy. It can then return a response to the
/// proxy that allow it to update the state with that same change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorObjects {
    // The revision of the set, meaning its number and the
    // "this update" and "next update" values used on the
    // manifest and CRL.
    revision: ObjectSetRevision,

    // Track revocations and the last issued CRL.
    revocations: Revocations,
    crl: PublishedCrl,

    // The last issued manifest.
    manifest: PublishedManifest,

    // Certificates issued to children. We use a map to avoid having
    // to loop. (yes, even if typically the list would be very short)
    issued: HashMap<KeyIdentifier, IssuedCertificate>,
}

impl TrustAnchorObjects {
    /// Creates a new TrustAnchorObjects for the signing certificate.
    fn create(ta_cert_details: &TaCertDetails, signer: &KrillSigner) -> KrillResult<Self> {
        let revision = ObjectSetRevision::new(1, Self::this_update(), Self::next_update());
        let revocations = Revocations::default();

        let signing_cert = ta_cert_details.cert();
        let signing_key = signing_cert.key_identifier();
        let issuer = signing_cert.subject().clone();

        let crl = CrlBuilder::build(signing_key, issuer, &revocations, revision, signer)?;

        let manifest = ManifestBuilder::new(revision)
            .with_objects(&crl, &HashMap::new())
            .build_new_mft(signing_cert, signer)
            .map(|m| m.into())?;

        Ok(TrustAnchorObjects {
            revision,
            revocations,
            crl,
            manifest,
            issued: HashMap::new(),
        })
    }

    fn increment_revision(&mut self) {
        self.revision.next(Self::next_update());
    }

    fn this_update() -> Time {
        Time::five_minutes_ago()
    }

    fn next_update() -> Time {
        Time::now() + chrono::Duration::weeks(12)
    }
}

//------------ TrustAnchorProxy: Commands and Events -----------------------

pub type TrustAnchorProxyCommand = eventsourcing::SentCommand<TrustAnchorProxyCommandDetails>;
pub type TrustAnchorProxyInitEvent = eventsourcing::StoredEvent<TrustAnchorProxyInitDetails>;
pub type TrustAnchorProxyEvent = eventsourcing::StoredEvent<TrustAnchorProxyEventDetails>;

// Initialisation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxyInitDetails {
    id: IdCertInfo,
}

impl fmt::Display for TrustAnchorProxyInitDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the init event.
        write!(f, "Trust Anchor Proxy was initialised.")
    }
}

// Events
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorProxyEventDetails {
    RepositoryAdded(RepositoryContact),
    SignerAdded(TrustAnchorProxySignerInfo),
    ChildAdded(TrustAnchorProxyChildAdded),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxyChildAdded {
    handle: ChildHandle,
    resources: ResourceSet,
    id: IdCertInfo,
}

impl fmt::Display for TrustAnchorProxyEventDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        match self {
            TrustAnchorProxyEventDetails::RepositoryAdded(repository) => {
                write!(
                    f,
                    "Added repository with service uri: {}",
                    repository.server_info().service_uri()
                )
            }
            TrustAnchorProxyEventDetails::SignerAdded(signer) => {
                write!(f, "Added signer with ID certificate hash: {}", signer.id.hash())
            }
            TrustAnchorProxyEventDetails::ChildAdded(child_added) => {
                write!(
                    f,
                    "Added child: {}, with resources: {}",
                    child_added.handle, child_added.resources
                )
            }
        }
    }
}

// Commands

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorProxyCommandDetails {
    AddRepository(RepositoryContact),
    AddSigner(TrustAnchorProxySignerInfo),
    AddChild(TrustAnchorProxyAddChild),
    MakeRepublishRequest,
    ProcessRepublishResponse(TrustAnchorObjects),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxyAddChild {
    handle: ChildHandle,
    resources: ResourceSet,
    id: IdCertInfo,
}

impl fmt::Display for TrustAnchorProxyCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        match self {
            TrustAnchorProxyCommandDetails::AddRepository(repository) => {
                write!(f, "Add repository at: {}", repository.server_info().service_uri())
            }
            TrustAnchorProxyCommandDetails::AddSigner(signer) => {
                write!(f, "Add signer with id certificate hash: {}", signer.id.hash())
            }
            TrustAnchorProxyCommandDetails::AddChild(add_child) => {
                write!(
                    f,
                    "Add child: {}, with resources: {}",
                    add_child.handle, add_child.resources
                )
            }
            TrustAnchorProxyCommandDetails::MakeRepublishRequest => {
                write!(f, "Create new publish request for signer")
            }
            TrustAnchorProxyCommandDetails::ProcessRepublishResponse(objects) => {
                write!(
                    f,
                    "Process publish response from signer. Number: {}. Next Update (before): {}",
                    objects.revision.number(),
                    objects.revision.next_update().to_rfc3339()
                )
            }
        }
    }
}

impl eventsourcing::WithStorableDetails for TrustAnchorProxyCommandDetails {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        match self {
            TrustAnchorProxyCommandDetails::AddRepository(repository) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-repo-add", &self)
                    .with_service_uri(repository.server_info().service_uri())
            }
            TrustAnchorProxyCommandDetails::AddSigner(signer) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-signer-add", &self)
                    .with_id_cert_hash(signer.id.hash())
            }
            TrustAnchorProxyCommandDetails::AddChild(add_child) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-child-add", &self).with_child(&add_child.handle)
            }
            TrustAnchorProxyCommandDetails::MakeRepublishRequest => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-pub-req", &self)
            }
            TrustAnchorProxyCommandDetails::ProcessRepublishResponse(objects) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-pub-res", &self)
                    .with_arg("number", objects.revision.number())
                    .with_arg("this update", objects.revision.this_update().to_rfc3339())
                    .with_arg("next update", objects.revision.next_update().to_rfc3339())
            }
        }
    }
}

impl TrustAnchorProxyCommand {
    pub fn add_repo(id: &TrustAnchorHandle, repository: RepositoryContact, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(
            id,
            None,
            TrustAnchorProxyCommandDetails::AddRepository(repository),
            actor,
        )
    }

    pub fn add_signer(id: &TrustAnchorHandle, signer: TrustAnchorProxySignerInfo, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(id, None, TrustAnchorProxyCommandDetails::AddSigner(signer), actor)
    }

    pub fn make_publish_request(id: &TrustAnchorHandle, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(id, None, TrustAnchorProxyCommandDetails::MakeRepublishRequest, actor)
    }
}

impl eventsourcing::CommandDetails for TrustAnchorProxyCommandDetails {
    type Event = TrustAnchorProxyEvent;
    type StorableDetails = Self;

    fn store(&self) -> Self::StorableDetails {
        self.clone()
    }
}

impl eventsourcing::Aggregate for TrustAnchorProxy {
    type Command = TrustAnchorProxyCommand;
    type StorableCommandDetails = TrustAnchorProxyCommandDetails;
    type Event = TrustAnchorProxyEvent;
    type InitEvent = TrustAnchorProxyInitEvent;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();

        Ok(TrustAnchorProxy {
            handle,
            version: 1,
            id: details.id,
            repository: None,
            signer: None,
            child_details: HashMap::new(),
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        let (handle, _version, details) = event.unpack();
        self.version += 1;

        if log_enabled!(log::Level::Trace) {
            trace!(
                "Applying event to Trust Anchor Proxy '{}', version: {}: {}",
                handle,
                self.version,
                details
            );
        }
        match details {
            TrustAnchorProxyEventDetails::RepositoryAdded(repository) => self.repository = Some(repository),
            TrustAnchorProxyEventDetails::SignerAdded(signer) => self.signer = Some(signer),
            TrustAnchorProxyEventDetails::ChildAdded(_child_added) => todo!(),
        }
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Sending command to Trust Anchor Proxy '{}', version: {}: {}",
                self.handle,
                self.version,
                command
            );
        }
        match command.into_details() {
            TrustAnchorProxyCommandDetails::AddRepository(repository) => {
                if self.repository.is_none() {
                    Ok(vec![TrustAnchorProxyEvent::new(
                        &self.handle,
                        self.version,
                        TrustAnchorProxyEventDetails::RepositoryAdded(repository),
                    )])
                } else {
                    Err(Error::TaProxyAlreadyHasRepository)
                }
            }
            TrustAnchorProxyCommandDetails::AddSigner(signer) => {
                if self.signer.is_none() {
                    Ok(vec![TrustAnchorProxyEvent::new(
                        &self.handle,
                        self.version,
                        TrustAnchorProxyEventDetails::SignerAdded(signer),
                    )])
                } else {
                    Err(Error::TaProxyAlreadyHasSigner)
                }
            }
            TrustAnchorProxyCommandDetails::AddChild(_add_child) => todo!("add child"),
            TrustAnchorProxyCommandDetails::MakeRepublishRequest => todo!("make publish request"),
            TrustAnchorProxyCommandDetails::ProcessRepublishResponse(_objects) => todo!("process published objects"),
        }
    }
}

impl TrustAnchorProxy {
    /// Creates an initialisation event that can be used to create
    /// a new TrustAnchorProxy.
    //
    // Perhaps we should refactor the eventsourcing support to have
    // a create command instead, and let the init event become a
    // normal event. But, not changing that now..
    pub fn create_init(handle: TrustAnchorHandle, signer: &KrillSigner) -> KrillResult<TrustAnchorProxyInitEvent> {
        let id = Rfc8183Id::generate(signer)?;
        Ok(TrustAnchorProxyInitEvent::new(
            &handle.into_converted(),
            0,
            TrustAnchorProxyInitDetails { id: id.into() },
        ))
    }

    /// Create an init command for the associated signer. This uses
    /// information from this proxy: its id certificate and the
    /// configured repository. This function will fail if the repository
    /// had not yet been configured.
    ///
    /// Furthermore, it takes some additional information that the signer
    /// will need for initialisation and passes it into the command. This
    /// is just a convenience so that the caller does not have to put all
    /// the information together.
    ///
    /// Note that the proxy is not modified by this function. The idea is
    /// that the command can be used to initialise the signer, and then
    /// the initialised signer details can be added to this proxy.
    pub fn create_signer_init_cmd(
        &self,
        signer_handle: TrustAnchorHandle,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        signer: Arc<KrillSigner>,
    ) -> KrillResult<TrustAnchorSignerInitCommand> {
        let repo = self.get_repo()?;

        Ok(TrustAnchorSignerInitCommand {
            handle: signer_handle,
            proxy_id: self.id.clone(),
            repo_info: repo.repo_info().clone(),
            tal_https,
            tal_rsync,
            signer,
        })
    }

    fn get_repo(&self) -> KrillResult<&RepositoryContact> {
        self.repository
            .as_ref()
            .ok_or_else(|| Error::CaRepoIssue(self.handle.clone(), "No repository configured".to_string()))
    }
}

//------------ TrustAnchorSigner -------------------------------------------

/// The Trust Anchor Signer signs requests sent to it by its associated
/// proxy, as long as it can verify that the proxy signed that request.

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchorSigner {
    // event-sourcing support
    handle: TrustAnchorHandle,
    version: u64,

    // ID certificate used by this signer
    id: IdCertInfo,

    // ID of the associated proxy
    proxy_id: IdCertInfo,

    // TA certificate and TAL
    ta_cert_details: TaCertDetails,

    // Objects to be published under the TA certificate
    objects: TrustAnchorObjects,
}

//------------ TrustAnchorSigner: Commands and Events ----------------------
pub type TrustAnchorSignerCommand = eventsourcing::SentCommand<TrustAnchorSignerCommandDetails>;
pub type TrustAnchorSignerInitEvent = eventsourcing::StoredEvent<TrustAnchorSignerInitDetails>;
pub type TrustAnchorSignerEvent = eventsourcing::StoredEvent<TrustAnchorSignerEventDetails>;

// Initialisation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignerInitDetails {
    id: IdCertInfo,
    proxy_id: IdCertInfo,
    ta_cert_details: TaCertDetails,
    objects: TrustAnchorObjects,
}

impl fmt::Display for TrustAnchorSignerInitDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the init event.
        write!(f, "Trust Anchor Signer was initialised.")
    }
}

// Events
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorSignerEventDetails {}

impl fmt::Display for TrustAnchorSignerEventDetails {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        todo!()
    }
}

// Commands
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorSignerCommandDetails {}

impl fmt::Display for TrustAnchorSignerCommandDetails {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        todo!()
    }
}

impl eventsourcing::WithStorableDetails for TrustAnchorSignerCommandDetails {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        todo!()
    }
}

impl eventsourcing::CommandDetails for TrustAnchorSignerCommandDetails {
    type Event = TrustAnchorSignerEvent;
    type StorableDetails = Self;

    fn store(&self) -> Self::StorableDetails {
        self.clone()
    }
}

impl eventsourcing::Aggregate for TrustAnchorSigner {
    type Command = TrustAnchorSignerCommand;
    type StorableCommandDetails = TrustAnchorSignerCommandDetails;
    type Event = TrustAnchorSignerEvent;
    type InitEvent = TrustAnchorSignerInitEvent;
    type Error = Error;

    fn init(event: Self::InitEvent) -> Result<Self, Self::Error> {
        let (handle, _version, details) = event.unpack();

        Ok(TrustAnchorSigner {
            handle,
            version: 1,
            id: details.id,
            proxy_id: details.proxy_id,
            ta_cert_details: details.ta_cert_details,
            objects: details.objects,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, _event: Self::Event) {
        todo!()
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        todo!()
    }
}

impl TrustAnchorSigner {
    pub fn get_signer_info(&self) -> TrustAnchorProxySignerInfo {
        TrustAnchorProxySignerInfo {
            id: self.id.clone(),
            objects: self.objects.clone(),
            ta_cert_details: self.ta_cert_details.clone(),
        }
    }
}

pub struct TrustAnchorSignerInitCommand {
    handle: TrustAnchorHandle,
    proxy_id: IdCertInfo,
    repo_info: RepoInfo,
    tal_https: Vec<uri::Https>,
    tal_rsync: uri::Rsync,
    // todo: support importing existing key
    signer: Arc<KrillSigner>,
}

// Date types used to requests and responses between the proxy and signer

/// Request for the Trust Anchor Signer to update the signed
/// objects (new mft, crl). Can contain requests for one or
/// more children to either issue a new certificate, or revoke
/// a key. If there are no requests for a child, then it is
/// assumed that the current issued certificate(s) to the child
/// should not change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorRequest {
    nonce: String, // should be matched in response (replay protection)
    child_requests: HashMap<ChildHandle, TrustAnchorChildRequests>,
}

/// Requests for Trust Anchor Child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorChildRequests {
    child: ChildHandle,
    resources: ResourceSet,
    requests: Vec<ProvisioningRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorResponse {
    nonce: String, // should match the request (replay protection)
    objects: TrustAnchorObjects,
    child_responses: HashMap<ChildHandle, Vec<ProvisioningResponse>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorChild {
    handle: ChildHandle,
    id: IdCertInfo,
    resources: ResourceSet,
    used_keys: HashMap<KeyIdentifier, UsedKeyState>,
    open_request: Option<ProvisioningRequest>,
    open_response: Option<ProvisioningResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
enum ProvisioningRequest {
    Issuance(provisioning::IssuanceRequest),
    Revocation(provisioning::RevocationRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
enum ProvisioningResponse {
    Issuance(provisioning::IssuanceResponse),
    Revocation(provisioning::RevocationResponse),
    Error(String),
}

impl TrustAnchorSigner {
    /// Creates an initialisation event that can be used to create a new Trust Anchor Signer.
    pub fn create_init(cmd: TrustAnchorSignerInitCommand) -> KrillResult<TrustAnchorSignerInitEvent> {
        let signer = cmd.signer;

        let id = Rfc8183Id::generate(&signer)?.into();
        let proxy_id = cmd.proxy_id;
        let ta_cert_details = Self::create_ta_cert_details(cmd.repo_info, cmd.tal_https, cmd.tal_rsync, &signer)?;
        let objects = TrustAnchorObjects::create(&ta_cert_details, &signer)?;

        Ok(TrustAnchorSignerInitEvent::new(
            &cmd.handle,
            0,
            TrustAnchorSignerInitDetails {
                id,
                proxy_id,
                ta_cert_details,
                objects,
            },
        ))
    }

    fn create_ta_cert_details(
        repo_info: RepoInfo,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        // todo: support importing existing key
        signer: &KrillSigner,
    ) -> KrillResult<TaCertDetails> {
        // todo: support importing existing key
        let key = signer.create_key()?;

        let resources = ResourceSet::all();

        let cert = {
            let serial: Serial = signer.random_serial()?;

            let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
            let name = pub_key.to_subject_name();

            let mut cert = TbsCert::new(
                serial,
                name.clone(),
                Validity::new(Time::five_minutes_ago(), Time::years_from_now(100)),
                Some(name),
                pub_key.clone(),
                KeyUsage::Ca,
                Overclaim::Refuse,
            );

            cert.set_basic_ca(Some(true));

            // The TA will publish directly in its root. It only has 1 resource class
            // so it does not use namespaces (sub-folders). Furthermore, this should
            // facilitate a structure where the TA can publish to the root of the
            // rsync repository, and other CAs get their own folders under it. This
            // will help recursive rsync fetches.
            let ns = "";

            cert.set_ca_repository(Some(repo_info.ca_repository(ns)));
            cert.set_rpki_manifest(Some(
                repo_info.resolve(ns, ObjectName::mft_for_key(&pub_key.key_identifier()).as_ref()),
            ));
            cert.set_rpki_notify(repo_info.rpki_notify().cloned());

            cert.set_as_resources(resources.to_as_resources());
            cert.set_v4_resources(resources.to_ip_resources_v4());
            cert.set_v6_resources(resources.to_ip_resources_v6());

            signer.sign_cert(cert, &key)?
        };

        let tal = TrustAnchorLocator::new(tal_https, tal_rsync.clone(), cert.subject_public_key_info());

        let rcvd_cert =
            ReceivedCert::create(cert, tal_rsync, resources, RequestResourceLimit::default()).map_err(Error::custom)?;

        Ok(TaCertDetails::new(rcvd_cert, tal))
    }

    /// Process a request.
    fn process_signer_request(
        &self,
        request: TrustAnchorRequest,
        signer: &KrillSigner,
    ) -> KrillResult<TrustAnchorResponse> {
        let mut objects = self.objects.clone();

        let mut child_responses: HashMap<ChildHandle, Vec<ProvisioningResponse>> = HashMap::new();

        objects.increment_revision();
        for (child, child_requests) in request.child_requests {
            child_responses.insert(child, vec![]);
            let resources = child_requests.resources;
            for provisioning_request in child_requests.requests {
                match provisioning_request {
                    ProvisioningRequest::Issuance(issuance_req) => {
                        let (_rcn, limit, csr) = issuance_req.unpack();

                        let issued = SignSupport::make_issued_cert(
                            csr.try_into()?,
                            &resources,
                            limit,
                            signing_key,
                            validity,
                            signer,
                        )?;

                        todo!()
                    }
                    ProvisioningRequest::Revocation(revocation_req) => todo!(),
                }
            }
        }

        todo!()
    }
}

//----------------- TESTS --------------------------------------------------------------
#[cfg(test)]
mod tests {
    use rpki::ca::idexchange::ServiceUri;

    use super::*;

    use std::{sync::Arc, time::Duration};

    use crate::{
        commons::{api::PublicationServerInfo, crypto::KrillSignerBuilder, eventsourcing::AggregateStore},
        daemon::{config::ConfigDefaults, http},
        test::*,
    };

    #[test]
    fn init_ta() {
        test_under_tmp(|d| {
            init_logging();

            let ta_signer_store: AggregateStore<TrustAnchorSigner> = AggregateStore::disk(&d, "ta_signer").unwrap();
            let ta_proxy_store: AggregateStore<TrustAnchorProxy> = AggregateStore::disk(&d, "ta_proxy").unwrap();

            let signers = ConfigDefaults::signers();
            let signer = Arc::new(
                KrillSignerBuilder::new(&d, Duration::from_secs(1), &signers)
                    .build()
                    .unwrap(),
            );

            let actor = test_actor();

            let proxy_handle = TrustAnchorHandle::new("proxy".into());

            let init = TrustAnchorProxy::create_init(proxy_handle.clone(), &signer).unwrap();

            let mut proxy = ta_proxy_store.add(init).unwrap();

            let repository = {
                let repo_info = RepoInfo::new(
                    rsync("rsync://example.krill.cloud/repo/"),
                    Some(https("https://exmple.krill.cloud/repo/notification.xml")),
                );
                let repo_key_id = signer.create_key().unwrap();
                let repo_key = signer.get_key_info(&repo_key_id).unwrap();

                let service_uri = ServiceUri::Https(https("https://example.krill.cloud/rfc8181/ta"));
                let server_info = PublicationServerInfo::new(repo_key, service_uri);

                RepositoryContact::new(repo_info, server_info)
            };

            let add_repo_cmd = TrustAnchorProxyCommand::add_repo(&proxy_handle, repository, &actor);
            proxy = ta_proxy_store.command(add_repo_cmd).unwrap();

            let signer_handle = TrustAnchorHandle::new("signer".into());
            let tal_https = vec![https("https://example.krill.cloud/ta/ta.cer")];
            let tal_rsync = rsync("rsync://example.krill.cloud/ta/ta.cer");

            let signer_init_cmd = proxy
                .create_signer_init_cmd(signer_handle, tal_https, tal_rsync, signer)
                .unwrap();

            let signer_init = TrustAnchorSigner::create_init(signer_init_cmd).unwrap();

            let signer = ta_signer_store.add(signer_init).unwrap();

            let signer_info = signer.get_signer_info();
            let add_signer_cmd = TrustAnchorProxyCommand::add_signer(&proxy_handle, signer_info, &actor);

            ta_proxy_store.command(add_signer_cmd).unwrap();

            let make_publish_request_cmd = TrustAnchorProxyCommand::make_publish_request(&proxy_handle, &actor);
            ta_proxy_store.command(make_publish_request_cmd).unwrap();

            // // First we need to set up the online TA
            // // The offline TA can only be set up when its online counterpart
            // // is initialised.
            // let online_cmd_init = OnlineTrustAnchorInitCommand {
            //     handle: OnlineTrustAnchorHandle::new("sub-ta".into()),
            //     signer: signer.clone(),
            // };
            // let online_ta = online_store
            //     .add(OnlineTrustAnchor::init(online_cmd_init).unwrap())
            //     .unwrap();

            // let repo_info = RepoInfo::new(
            //     rsync("rsync://example.krill.cloud/repo/"),
            //     Some(https("https://example.krill.cloud/repo/notification.xml")),
            // );

            // let tal_https = vec![https("https://example.krill.cloud/ta/ta.cer")];
            // let tal_rsync = rsync("rsync://example.krill.cloud/ta/ta.cer");

            // // todo: create online ta first
            // let counterpart = online_ta.as_counterpart();

            // let init_cmd = OfflineTrustAnchorInitCommand {
            //     handle: OfflineTrustAnchorHandle::new("ta".into()),
            //     repo_info,
            //     tal_https,
            //     tal_rsync,
            //     counterpart,
            //     signer,
            // };

            // let init_event = OfflineTrustAnchor::init(init_cmd).unwrap();

            // offline_store.add(init_event).unwrap();
        })
    }
}
