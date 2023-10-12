//! Trust Anchor Proxy
//!
//! The Trust Anchor Proxy performs all Trust Anchor responsibilities
/// *except* for signing using the Trust Anchor private key. That function
/// is handled by the Trust Anchor Signer instead.
use super::*;

use std::{collections::HashMap, convert::TryFrom, fmt, sync::Arc};

use rpki::{
    ca::{
        idexchange::{self, ChildHandle, MyHandle},
        provisioning::{ResourceClassEntitlements, SigningCert},
    },
    crypto::KeyIdentifier,
};

use crate::{
    commons::{
        actor::Actor,
        api::{AddChildRequest, IdCertInfo, RepositoryContact},
        crypto::{CsrInfo, KrillSigner},
        error::Error,
        eventsourcing::{self, Event, InitCommandDetails, InitEvent, WithStorableDetails},
        KrillResult,
    },
    daemon::{
        ca::{Rfc8183Id, UsedKeyState},
        config::IssuanceTimingConfig,
    },
};

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
    signer: Option<TrustAnchorSignerInfo>,

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

    // Track if there is any open signer request. Responses MUST match the
    // the nonce. Furthermore, child interactions are suspended when there
    // is an open request. We first need to process the response, before we
    // can accept new requests from any child.
    open_signer_request: Option<Nonce>,
}

//------------ TrustAnchorProxy: Commands and Events -----------------------

pub type TrustAnchorProxyInitCommand = eventsourcing::SentInitCommand<TrustAnchorProxyInitCommandDetails>;

impl TrustAnchorProxyInitCommand {
    pub fn make(id: &MyHandle, signer: Arc<KrillSigner>, actor: &Actor) -> Self {
        TrustAnchorProxyInitCommand::new(id, TrustAnchorProxyInitCommandDetails { signer }, actor)
    }
}

#[derive(Clone, Debug)]
pub struct TrustAnchorProxyInitCommandDetails {
    signer: Arc<KrillSigner>,
}

impl fmt::Display for TrustAnchorProxyInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

impl InitCommandDetails for TrustAnchorProxyInitCommandDetails {
    type StorableDetails = TrustAnchorProxyCommandDetails;

    fn store(&self) -> Self::StorableDetails {
        TrustAnchorProxyCommandDetails::make_init()
    }
}

pub type TrustAnchorProxyCommand = eventsourcing::SentCommand<TrustAnchorProxyCommandDetails>;

// Initialisation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxyInitEvent {
    id: IdCertInfo,
}

impl InitEvent for TrustAnchorProxyInitEvent {}

impl fmt::Display for TrustAnchorProxyInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the init event.
        write!(f, "Trust Anchor Proxy was initialised.")
    }
}

// Events
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorProxyEvent {
    // Publication Support
    RepositoryAdded(RepositoryContact),

    // Proxy -> Signer interactions
    SignerAdded(TrustAnchorSignerInfo),
    SignerRequestMade(Nonce),
    SignerResponseReceived(TrustAnchorSignedResponse),

    // Children
    ChildAdded(TrustAnchorChild),
    ChildRequestAdded(ChildHandle, ProvisioningRequest),
    ChildResponseGiven(ChildHandle, KeyIdentifier),
}

impl Event for TrustAnchorProxyEvent {}

impl fmt::Display for TrustAnchorProxyEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        match self {
            // Publication Support
            TrustAnchorProxyEvent::RepositoryAdded(repository) => {
                write!(
                    f,
                    "Added repository with service uri: {}",
                    repository.server_info().service_uri()
                )
            }

            // Proxy -> Signer interactions
            TrustAnchorProxyEvent::SignerAdded(signer) => {
                write!(f, "Added signer with ID certificate hash: {}", signer.id.hash())
            }
            TrustAnchorProxyEvent::SignerRequestMade(nonce) => {
                write!(f, "Created signer request with nonce '{}'", nonce)
            }
            TrustAnchorProxyEvent::SignerResponseReceived(response) => {
                write!(f, "Received signer response with nonce '{}'", response.content().nonce)
            }

            // Children
            TrustAnchorProxyEvent::ChildAdded(child) => {
                write!(f, "Added child: {}, with resources: {}", child.handle, child.resources)
            }
            TrustAnchorProxyEvent::ChildRequestAdded(child_handle, request) => {
                write!(f, "Added request for child {}: {}", child_handle, request)
            }
            TrustAnchorProxyEvent::ChildResponseGiven(child_handle, key) => {
                write!(f, "Given response to child {} for key: {}", child_handle, key)
            }
        }
    }
}

// Commands

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorProxyCommandDetails {
    // Create new instance - cannot be sent to an existing instance
    Init,

    // Publication Support
    AddRepository(RepositoryContact),

    // Proxy -> Signer interactions
    AddSigner(TrustAnchorSignerInfo),
    MakeSignerRequest,
    ProcessSignerResponse(TrustAnchorSignedResponse),

    // Children
    AddChild(AddChildRequest),
    AddChildRequest(ChildHandle, ProvisioningRequest),
    GiveChildResponse(ChildHandle, KeyIdentifier),
}

impl fmt::Display for TrustAnchorProxyCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        match self {
            TrustAnchorProxyCommandDetails::Init => {
                write!(f, "Initialise TA proxy")
            }
            // Publication Support
            TrustAnchorProxyCommandDetails::AddRepository(repository) => {
                write!(f, "Add repository at: {}", repository.server_info().service_uri())
            }

            // Proxy -> Signer interactions
            TrustAnchorProxyCommandDetails::AddSigner(signer) => {
                write!(f, "Add signer with id certificate hash: {}", signer.id.hash())
            }
            TrustAnchorProxyCommandDetails::MakeSignerRequest => {
                write!(f, "Create new publish request for signer")
            }
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response) => {
                write!(
                    f,
                    "Process signer response. Nonce: {}. Next Update (before): {}",
                    response.content().nonce,
                    response.content().objects.revision().next_update().to_rfc3339()
                )
            }

            // Children
            TrustAnchorProxyCommandDetails::AddChild(child) => {
                write!(f, "Add child: {}", child)
            }
            TrustAnchorProxyCommandDetails::AddChildRequest(child_handle, request) => {
                write!(f, "Add request for child {}: {}", child_handle, request)
            }
            TrustAnchorProxyCommandDetails::GiveChildResponse(child_handle, key) => {
                write!(
                    f,
                    "Give (and remove) response to child {} for key {}",
                    child_handle, key
                )
            }
        }
    }
}

impl eventsourcing::WithStorableDetails for TrustAnchorProxyCommandDetails {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        match self {
            // Initialisation
            TrustAnchorProxyCommandDetails::Init => crate::commons::api::CommandSummary::new("cmd-ta-proxy-init", self),
            // Publication Support
            TrustAnchorProxyCommandDetails::AddRepository(repository) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-repo-add", self)
                    .with_service_uri(repository.server_info().service_uri())
            }

            // Proxy -> Signer interactions
            TrustAnchorProxyCommandDetails::AddSigner(signer) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-signer-add", self)
                    .with_id_cert_hash(signer.id.hash())
            }
            TrustAnchorProxyCommandDetails::MakeSignerRequest => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-pub-req", self)
            }
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-pub-res", self)
                    .with_arg("nonce", &response.content().nonce)
                    .with_arg("manifest number", response.content().objects.revision().number())
                    .with_arg(
                        "this update",
                        response.content().objects.revision().this_update().to_rfc3339(),
                    )
                    .with_arg(
                        "next update",
                        response.content().objects.revision().next_update().to_rfc3339(),
                    )
            }

            // Children
            TrustAnchorProxyCommandDetails::AddChild(child) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-child-add", self).with_child(child.handle())
            }
            TrustAnchorProxyCommandDetails::AddChildRequest(child_handle, _request) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-child-req", self).with_child(child_handle)
            }
            TrustAnchorProxyCommandDetails::GiveChildResponse(child_handle, _response) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-child-res", self).with_child(child_handle)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
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

    pub fn add_signer(id: &TrustAnchorHandle, signer: TrustAnchorSignerInfo, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(id, None, TrustAnchorProxyCommandDetails::AddSigner(signer), actor)
    }

    pub fn make_signer_request(id: &TrustAnchorHandle, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(id, None, TrustAnchorProxyCommandDetails::MakeSignerRequest, actor)
    }

    pub fn process_signer_response(id: &TrustAnchorHandle, response: TrustAnchorSignedResponse, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(
            id,
            None,
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response),
            actor,
        )
    }

    pub fn add_child(id: &TrustAnchorHandle, child: AddChildRequest, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(id, None, TrustAnchorProxyCommandDetails::AddChild(child), actor)
    }

    pub fn add_child_request(
        id: &TrustAnchorHandle,
        child: ChildHandle,
        request: ProvisioningRequest,
        actor: &Actor,
    ) -> Self {
        TrustAnchorProxyCommand::new(
            id,
            None,
            TrustAnchorProxyCommandDetails::AddChildRequest(child, request),
            actor,
        )
    }

    pub fn give_child_response(id: &TrustAnchorHandle, child: ChildHandle, key: KeyIdentifier, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(
            id,
            None,
            TrustAnchorProxyCommandDetails::GiveChildResponse(child, key),
            actor,
        )
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

    type InitCommand = TrustAnchorProxyInitCommand;
    type InitEvent = TrustAnchorProxyInitEvent;
    type Error = Error;

    fn init(handle: TrustAnchorHandle, event: TrustAnchorProxyInitEvent) -> Self {
        TrustAnchorProxy {
            handle,
            version: 1,
            id: event.id,
            repository: None,
            signer: None,
            child_details: HashMap::new(),
            open_signer_request: None,
        }
    }

    fn process_init_command(command: TrustAnchorProxyInitCommand) -> Result<TrustAnchorProxyInitEvent, Error> {
        Rfc8183Id::generate(&command.into_details().signer).map(|id| TrustAnchorProxyInitEvent { id: id.into() })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn increment_version(&mut self) {
        self.version += 1;
    }

    fn apply(&mut self, event: Self::Event) {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Applying event to Trust Anchor Proxy '{}', version: {}: {}",
                self.handle,
                self.version,
                event
            );
        }

        match event {
            // Publication Support
            TrustAnchorProxyEvent::RepositoryAdded(repository) => self.repository = Some(repository),

            // Proxy -> Signer interactions
            TrustAnchorProxyEvent::SignerAdded(signer) => self.signer = Some(signer),
            TrustAnchorProxyEvent::SignerRequestMade(nonce) => self.open_signer_request = Some(nonce),
            TrustAnchorProxyEvent::SignerResponseReceived(response) => {
                let content = response.into_content();
                for (child_handle, child_responses) in content.child_responses {
                    if let Some(child_details) = self.child_details.get_mut(&child_handle) {
                        for (key_id, response) in child_responses {
                            match &response {
                                ProvisioningResponse::Issuance(_) => {
                                    child_details
                                        .used_keys
                                        .insert(key_id, UsedKeyState::InUse("default".into()));
                                }
                                ProvisioningResponse::Revocation(_) => {
                                    child_details.used_keys.insert(key_id, UsedKeyState::Revoked);
                                }
                                _ => {}
                            }
                            child_details.open_requests.remove(&key_id);
                            child_details.open_responses.insert(key_id, response);
                        }
                    }
                }
                // We cannot have an accepted response if we did not have a signer
                self.signer.as_mut().unwrap().objects = content.objects;
                self.open_signer_request = None;
            }

            // Children
            TrustAnchorProxyEvent::ChildAdded(child) => {
                self.child_details.insert(child.handle.clone(), child);
            }
            TrustAnchorProxyEvent::ChildRequestAdded(child_handle, request) => {
                self.child_details
                    .get_mut(&child_handle)
                    .unwrap() // safe - we can only have an event for this child if it exists
                    .open_requests
                    .insert(request.key_identifier(), request);
            }
            TrustAnchorProxyEvent::ChildResponseGiven(child_handle, key) => {
                self.child_details
                    .get_mut(&child_handle)
                    .unwrap() // safe - we can only have an event for this child if it exists
                    .open_responses
                    .remove(&key);
            }
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
            // Initialisation
            TrustAnchorProxyCommandDetails::Init => {
                // This can't happen really.. we would never send this command
                // to an existing TrustAnchorProxy.
                //
                // This could be solved more elegantly, and more verbosely, if
                // we create a separate TrustAnchorProxyStorableCommand that
                // implements 'WithStorableDetails' - like we have in other cases -
                // because then our initialisation command could map to that type
                // instead of having this additional variant for storing.
                Err(Error::custom("Trust Anchor Proxy already created"))
            }

            // Publication Support
            TrustAnchorProxyCommandDetails::AddRepository(repository) => self.process_add_repository(repository),

            // Proxy -> Signer interactions
            TrustAnchorProxyCommandDetails::AddSigner(signer) => self.process_add_signer(signer),
            TrustAnchorProxyCommandDetails::MakeSignerRequest => self.process_make_signer_request(),
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response) => self.process_signer_response(response),

            // Children
            TrustAnchorProxyCommandDetails::AddChild(child) => self.process_add_child(child),
            TrustAnchorProxyCommandDetails::AddChildRequest(child_handle, request) => {
                self.process_add_child_request(child_handle, request)
            }
            TrustAnchorProxyCommandDetails::GiveChildResponse(child_handle, key) => {
                self.process_give_child_response(child_handle, key)
            }
        }
    }
}

// # Process command details
impl TrustAnchorProxy {
    fn process_add_repository(&self, repository: RepositoryContact) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        if self.repository.is_none() {
            Ok(vec![TrustAnchorProxyEvent::RepositoryAdded(repository)])
        } else {
            Err(Error::TaProxyAlreadyHasRepository)
        }
    }

    fn process_add_signer(&self, signer: TrustAnchorSignerInfo) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        if self.signer.is_none() {
            Ok(vec![TrustAnchorProxyEvent::SignerAdded(signer)])
        } else {
            Err(Error::TaProxyAlreadyHasSigner)
        }
    }

    fn process_make_signer_request(&self) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        if self.open_signer_request.is_some() {
            Err(Error::TaProxyHasRequest)
        } else {
            Ok(vec![TrustAnchorProxyEvent::SignerRequestMade(Nonce::new())])
        }
    }

    fn process_signer_response(&self, response: TrustAnchorSignedResponse) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        let open_request_nonce = self.open_signer_request.as_ref().ok_or(Error::TaProxyHasNoRequest)?;

        if &response.content().nonce != open_request_nonce {
            // It seems that the user uploaded the wrong the response.
            Err(Error::TaProxyRequestNonceMismatch(
                response.into_content().nonce,
                open_request_nonce.clone(),
            ))
        } else if let Some(signer) = &self.signer {
            // Ensure that the response was validly signed.
            response.validate(&signer.id)?;

            // We accept the response as is. Since children cannot be modified, and requests
            // cannot change as long as there is an open signer request we cannot have any
            // mismatches between the children and child requests in the proxy vs the
            // children and responses received from the signer.
            //
            // In other words.. we trust that the associated signer functions correctly and
            // we have no further defensive coding on this side.
            //
            // Note that if we would reject the response, then there would be no way of
            // telling the signer why. So, this is also a matter of the 'the signer is
            // always right'.
            Ok(vec![TrustAnchorProxyEvent::SignerResponseReceived(response)])
        } else {
            // This is rather unexpected.. it implies that we had a request, but no
            // signer. Still - return a clean error for this, so unlikely as this may
            // be, it can be investigated.
            Err(Error::TaProxyHasNoSigner)
        }
    }

    fn process_add_child(&self, child: AddChildRequest) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        if self.child_details.contains_key(child.handle()) {
            Err(Error::CaChildDuplicate(self.handle.clone(), child.handle().clone()))
        } else {
            let (handle, resources, id_cert) = child.unpack();
            Ok(vec![TrustAnchorProxyEvent::ChildAdded(TrustAnchorChild::new(
                handle,
                id_cert.into(),
                resources,
            ))])
        }
    }

    fn process_add_child_request(
        &self,
        child_handle: ChildHandle,
        request: ProvisioningRequest,
    ) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        // We can do some basic checks on the request, like..
        // - CSR is valid
        // - CSR does not exceed entitled resources
        // - CSR is for correct resource class
        // - Revocation is for known key
        // - Revocation is for correct resource class
        //
        // The signer will eventually handle the actual request. So we just
        // schedule it as a manner of speaking. The signer will also do these
        // checks - although that means that we have some duplication this helps
        // to ensure that we can "fail fast" - and on the other hand leave the
        // signer to be responsible for the final say (also.. things may have
        // changed by the time the signer looks at it, like resource entitlements
        // perhaps in future?)
        let child = self.get_child_details(&child_handle)?;
        let ta_resource_class_name = ta_resource_class_name();

        match &request {
            ProvisioningRequest::Issuance(issuance) => {
                if issuance.class_name() != &ta_resource_class_name {
                    return Err(Error::Custom(format!(
                        "TA child certificate sign request uses unknown resource class name '{}'",
                        issuance.class_name()
                    )));
                }
                issuance.limit().apply_to(&child.resources)?; // Errors if request exceeds
                CsrInfo::try_from(issuance.csr())?; // Errors if the CSR is invalid
            }
            ProvisioningRequest::Revocation(revocation) => {
                if revocation.class_name() != &ta_resource_class_name {
                    return Err(Error::Custom(format!(
                        "TA child revocation request uses unknown resource class name '{}'",
                        revocation.class_name()
                    )));
                }
                if !child.used_keys.contains_key(&revocation.key()) {
                    return Err(Error::Custom(format!(
                        "TA child revocation requested for unknown key: {}",
                        revocation.key()
                    )));
                }
            }
        }

        Ok(vec![TrustAnchorProxyEvent::ChildRequestAdded(child_handle, request)])
    }

    fn process_give_child_response(
        &self,
        child_handle: ChildHandle,
        key: KeyIdentifier,
    ) -> KrillResult<Vec<TrustAnchorProxyEvent>> {
        let child = self.get_child_details(&child_handle)?;

        if child.open_responses.contains_key(&key) {
            Ok(vec![TrustAnchorProxyEvent::ChildResponseGiven(child_handle, key)])
        } else {
            // This should not never happen. The command would not be sent, but let's
            // return some useful error anyway.
            Err(Error::Custom(format!(
                "No response found for child {} and key {}",
                child_handle, key
            )))
        }
    }
}

impl TrustAnchorProxy {
    pub fn has_open_request(&self) -> bool {
        self.open_signer_request.is_some()
    }

    pub fn get_signer_request(
        &self,
        timing: TaTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<TrustAnchorSignedRequest> {
        if let Some(nonce) = self.open_signer_request.as_ref().cloned() {
            let mut child_requests = vec![];
            for (child, details) in &self.child_details {
                if !details.open_requests.is_empty() {
                    child_requests.push(TrustAnchorChildRequests {
                        child: child.clone(),
                        resources: details.resources.clone(),
                        requests: details.open_requests.clone(),
                    });
                }
            }

            TrustAnchorSignerRequest { nonce, child_requests }.sign(
                self.id.public_key().key_identifier(),
                timing.signed_message_validity_days,
                signer,
            )
        } else {
            Err(Error::TaProxyHasNoRequest)
        }
    }

    pub fn get_ta_details(&self) -> KrillResult<&TaCertDetails> {
        self.signer
            .as_ref()
            .ok_or(Error::TaNotInitialized)
            .map(|signer| &signer.ta_cert_details)
    }

    pub fn get_trust_anchor_objects(&self) -> KrillResult<&TrustAnchorObjects> {
        self.signer
            .as_ref()
            .ok_or(Error::TaNotInitialized)
            .map(|signer| &signer.objects)
    }

    pub fn id(&self) -> &IdCertInfo {
        &self.id
    }

    pub fn repository(&self) -> Option<&RepositoryContact> {
        self.repository.as_ref()
    }

    pub fn get_child(&self, child: &ChildHandle) -> KrillResult<&TrustAnchorChild> {
        match self.child_details.get(child) {
            None => Err(Error::CaChildUnknown(self.handle.clone(), child.clone())),
            Some(child) => Ok(child),
        }
    }
}

/// # Publication support
impl TrustAnchorProxy {
    /// Returns an RFC 8183 Publisher Request - which can be represented as XML to a
    /// repository for this `CertAuth`
    pub fn publisher_request(&self) -> idexchange::PublisherRequest {
        idexchange::PublisherRequest::new(self.id.base64().clone(), self.handle.convert(), None)
    }
}

/// # As a parent
impl TrustAnchorProxy {
    /// Get the entitlements for a child.
    ///
    /// This is a simplified version of similar code in [`CertAuth`]. There is no apparent
    /// easy abstraction over these two types (a normal CA and a TA proxy). Things are similar,
    /// but then.. the details are quite different. So, we accept some re-implementation of
    /// similar logic here.
    pub fn entitlements(
        &self,
        child_handle: &ChildHandle,
        issuance_timing: &IssuanceTimingConfig,
    ) -> KrillResult<ResourceClassEntitlements> {
        let signer = self.signer.as_ref().ok_or(Error::TaNotInitialized)?;
        let child = self.get_child_details(child_handle)?;

        let signing_cert = {
            let received_cert = signer.ta_cert_details.cert();
            let my_cert = received_cert
                .to_cert()
                .map_err(|e| Error::Custom(format!("Issue with certificate held by TA: {} ", e)))?;
            SigningCert::new(received_cert.uri().clone(), my_cert)
        };

        let mut issued_certs = vec![];

        let mut not_after = issuance_timing.new_child_cert_not_after();
        let threshold = issuance_timing.new_child_cert_issuance_threshold();
        for ki in child.used_keys.keys() {
            if let Some(issued) = signer.objects.get_issued(ki) {
                issued_certs.push(issued.to_rfc6492_issued_cert().map_err(|e| {
                    // This should never happen, unless our current issued certificate can no longer be parsed
                    Error::Custom(format!("Issue with issued certificate held by TA: {} ", e))
                })?);

                let expires = issued.validity().not_after();

                if expires > threshold {
                    not_after = expires;
                }
            }
        }

        Ok(ResourceClassEntitlements::new(
            ta_resource_class_name(),
            child.resources.clone(),
            not_after,
            issued_certs,
            signing_cert,
        ))
    }

    /// Get a response for a child request if there is one.
    ///
    /// Returns an error in case the request does not correspond to the open response.
    /// In that case the manager should probably just clear the open response so that
    /// the child can sync again. This should not happen with local Krill CA children
    /// as they do not create new requests when there is an open request. We should
    /// not support any non-local - i.e. possibly out-of-sync and possibly non-krill
    /// child under a krill trust anchor. They can be a child of the trust anchor
    /// child though.
    pub fn response_for_child(
        &self,
        child_handle: &ChildHandle,
        request: &ProvisioningRequest,
    ) -> KrillResult<Option<&ProvisioningResponse>> {
        let child = self.get_child_details(child_handle)?;

        if let Some(response) = child.open_responses.get(&request.key_identifier()) {
            if request.matches_response(response) {
                Ok(Some(response))
            } else {
                Err(Error::Custom(format!(
                    "Response for {} does not match request type.",
                    child_handle
                )))
            }
        } else {
            Ok(None)
        }
    }

    /// Informs whether there is a matching open request for the child.
    ///
    /// If there is a matching request then we do not need to add it. If there is no matching
    /// request then we may want to add a new request or replace an existing request - which
    /// we just consider 'not matching and now irrelevant' - as long as there is no open request
    /// to the signer.
    ///
    /// Returns an error if the child is not known.
    pub fn matching_open_request(
        &self,
        child_handle: &ChildHandle,
        request: &ProvisioningRequest,
    ) -> KrillResult<bool> {
        let child = self.get_child_details(child_handle)?;
        if let Some(existing) = child.open_requests.get(&request.key_identifier()) {
            match (existing, request) {
                (ProvisioningRequest::Issuance(existing), ProvisioningRequest::Issuance(request)) => {
                    Ok(
                        existing.class_name() == request.class_name() // must be "default" but could differ
                        && existing.limit() == request.limit()
                        && CsrInfo::try_from(existing.csr())? == CsrInfo::try_from(request.csr())?,
                    )
                }
                (ProvisioningRequest::Revocation(existing), ProvisioningRequest::Revocation(request)) => {
                    Ok(existing.class_name() == request.class_name()) // must be "default" but could differ
                }
                _ => Ok(false),
            }
        } else {
            Ok(false)
        }
    }

    fn get_child_details(&self, child_handle: &ChildHandle) -> KrillResult<&TrustAnchorChild> {
        self.child_details
            .get(child_handle)
            .ok_or_else(|| Error::CaChildUnknown(self.handle.clone(), child_handle.clone()))
    }
}
