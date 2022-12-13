//! Trust Anchor Proxy
//!
//! The Trust Anchor Proxy performs all Trust Anchor responsibilities
/// *except* for signing using the Trust Anchor private key. That function
/// is handled by the Trust Anchor Signer instead.
use super::*;

use std::{collections::HashMap, fmt, sync::Arc};

use rpki::{
    ca::{
        idexchange::ChildHandle,
        provisioning::{ResourceClassEntitlements, SigningCert},
    },
    repository::resources::ResourceSet,
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::{IdCertInfo, RepositoryContact},
        crypto::KrillSigner,
        error::Error,
        eventsourcing, KrillResult,
    },
    daemon::{ca::Rfc8183Id, config::IssuanceTimingConfig},
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

    // Track if there is any open signer request. Responses MUST match the
    // the nonce. Furthermore, child interactions are suspended when there
    // is an open request. We first need to process the response, before we
    // can accept new requests from any child.
    open_signer_request: Option<Nonce>,
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
    SignerRequestMade(Nonce),
    SignerResponseReceived(TrustAnchorSignerResponse),
    ChildAdded(TrustAnchorChild),
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
            TrustAnchorProxyEventDetails::SignerRequestMade(nonce) => {
                write!(f, "Created signer request with nonce '{}'", nonce)
            }
            TrustAnchorProxyEventDetails::SignerResponseReceived(response) => {
                write!(f, "Received signer response with nonce '{}'", response.nonce)
            }
            TrustAnchorProxyEventDetails::ChildAdded(child) => {
                write!(f, "Added child: {}, with resources: {}", child.handle, child.resources)
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
    MakeSignerRequest,
    ProcessSignerResponse(TrustAnchorSignerResponse),
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
            TrustAnchorProxyCommandDetails::MakeSignerRequest => {
                write!(f, "Create new publish request for signer")
            }
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response) => {
                write!(
                    f,
                    "Process signer response. Nonce: {}. Next Update (before): {}",
                    response.nonce,
                    response.objects.revision().next_update().to_rfc3339()
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
            TrustAnchorProxyCommandDetails::MakeSignerRequest => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-pub-req", &self)
            }
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(objects) => {
                crate::commons::api::CommandSummary::new("cmd-ta-proxy-pub-res", &self)
                    .with_arg("nonce", &objects.nonce)
                    .with_arg("manifest number", objects.objects.revision().number())
                    .with_arg("this update", objects.objects.revision().this_update().to_rfc3339())
                    .with_arg("next update", objects.objects.revision().next_update().to_rfc3339())
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

    pub fn make_signer_request(id: &TrustAnchorHandle, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(id, None, TrustAnchorProxyCommandDetails::MakeSignerRequest, actor)
    }

    pub fn process_signer_response(id: &TrustAnchorHandle, response: TrustAnchorSignerResponse, actor: &Actor) -> Self {
        TrustAnchorProxyCommand::new(
            id,
            None,
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response),
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
            open_signer_request: None,
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        let (handle, _version, details) = event.unpack();

        if log_enabled!(log::Level::Trace) {
            trace!(
                "Applying event to Trust Anchor Proxy '{}', version: {}: {}",
                handle,
                self.version,
                details
            );
        }

        self.version += 1;
        match details {
            TrustAnchorProxyEventDetails::RepositoryAdded(repository) => self.repository = Some(repository),
            TrustAnchorProxyEventDetails::SignerAdded(signer) => self.signer = Some(signer),
            TrustAnchorProxyEventDetails::SignerRequestMade(nonce) => self.open_signer_request = Some(nonce),
            TrustAnchorProxyEventDetails::SignerResponseReceived(response) => {
                for (child_handle, child_responses) in response.child_responses {
                    if let Some(child_details) = self.child_details.get_mut(&child_handle) {
                        for (key_id, response) in child_responses {
                            child_details.open_requests.remove(&key_id);
                            child_details.open_responses.insert(key_id, response);
                        }
                    }
                }
                // We cannot have an accepted response if we did not have a signer
                self.signer.as_mut().unwrap().objects = response.objects;
                self.open_signer_request = None;
            }
            TrustAnchorProxyEventDetails::ChildAdded(child) => {
                self.child_details.insert(child.handle.clone(), child);
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
            TrustAnchorProxyCommandDetails::AddChild(child) => {
                if self.child_details.contains_key(&child.handle) {
                    Err(Error::CaChildDuplicate(self.handle.clone(), child.handle))
                } else {
                    Ok(vec![TrustAnchorProxyEvent::new(
                        &self.handle,
                        self.version,
                        TrustAnchorProxyEventDetails::ChildAdded(TrustAnchorChild::new(
                            child.handle,
                            child.id,
                            child.resources,
                        )),
                    )])
                }
            }
            TrustAnchorProxyCommandDetails::MakeSignerRequest => {
                if self.open_signer_request.is_some() {
                    Err(Error::TaProxyHasRequest)
                } else {
                    Ok(vec![TrustAnchorProxyEvent::new(
                        &self.handle,
                        self.version,
                        TrustAnchorProxyEventDetails::SignerRequestMade(Nonce::new()),
                    )])
                }
            }
            TrustAnchorProxyCommandDetails::ProcessSignerResponse(response) => {
                if let Some(nonce) = &self.open_signer_request {
                    if &response.nonce != nonce {
                        // It seems that the user uploaded the wrong the response.
                        Err(Error::TaProxyRequestNonceMismatch(response.nonce, nonce.clone()))
                    } else {
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
                        Ok(vec![TrustAnchorProxyEvent::new(
                            &self.handle,
                            self.version,
                            TrustAnchorProxyEventDetails::SignerResponseReceived(response),
                        )])
                    }
                } else {
                    // It seems that the user uploaded a response even though we have no request.
                    Err(Error::TaProxyHasNoRequest)
                }
            }
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

    pub fn get_signer_request(&self) -> KrillResult<TrustAnchorSignerRequest> {
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
            Ok(TrustAnchorSignerRequest { nonce, child_requests })
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

    fn get_repo(&self) -> KrillResult<&RepositoryContact> {
        self.repository
            .as_ref()
            .ok_or_else(|| Error::CaRepoIssue(self.handle.clone(), "No repository configured".to_string()))
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
        let child = self
            .child_details
            .get(child_handle)
            .ok_or_else(|| Error::CaChildUnknown(self.handle.clone(), child_handle.clone()))?;

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
            "default".into(),
            child.resources.clone(),
            not_after,
            issued_certs,
            signing_cert,
        ))
    }
}
