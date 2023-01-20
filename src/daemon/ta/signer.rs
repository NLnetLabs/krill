//! Trust Anchor Signer
//!
//! Handles signing operations using the (offline) Trust Anchor key.
//! Designed to work with a single associated proxy which is responsible
//! for all other functions, like publishing and talking to child CAs.
//! The proxy makes sign requests for the signer to sign.
use super::*;

use std::{collections::HashMap, convert::TryFrom, fmt, sync::Arc};

use chrono::SecondsFormat;
use rpki::{
    ca::{
        idexchange::{ChildHandle, RepoInfo},
        provisioning::{self, IssuanceResponse, RequestResourceLimit, RevocationResponse},
    },
    crypto::KeyIdentifier,
    repository::{
        cert::{KeyUsage, Overclaim, TbsCert},
        resources::ResourceSet,
        x509::{Serial, Time},
    },
    uri,
};

use crate::{
    commons::{
        actor::Actor,
        api::{IdCertInfo, ObjectName, ReceivedCert},
        crypto::{CsrInfo, KrillSigner, SignSupport},
        error::Error,
        eventsourcing, KrillResult,
    },
    daemon::ca::Rfc8183Id,
};

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

    // Proxy Signer Exchanges
    exchanges: TrustAnchorProxySignerExchanges,
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
pub enum TrustAnchorSignerEventDetails {
    ProxySignerExchangeDone(TrustAnchorProxySignerExchange),
}

impl fmt::Display for TrustAnchorSignerEventDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TrustAnchorSignerEventDetails::ProxySignerExchangeDone(exchange) => {
                write!(
                    f,
                    "Proxy signer exchange done on {} for nonce: {}",
                    exchange.time.to_rfc3339(),
                    exchange.request.content().nonce
                )
            }
        }
    }
}

// Commands
#[derive(Clone, Debug)]
pub enum TrustAnchorSignerCommandDetails {
    TrustAnchorSignerRequest(TrustAnchorSignedRequest, Arc<KrillSigner>),
}

impl eventsourcing::CommandDetails for TrustAnchorSignerCommandDetails {
    type Event = TrustAnchorSignerEvent;
    type StorableDetails = TrustAnchorSignerStorableCommand;

    fn store(&self) -> Self::StorableDetails {
        self.into()
    }
}

impl fmt::Display for TrustAnchorSignerCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        TrustAnchorSignerStorableCommand::from(self).fmt(f)
    }
}

impl TrustAnchorSignerCommand {
    pub fn make_process_request_command(
        id: &TrustAnchorHandle,
        request: TrustAnchorSignedRequest,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> TrustAnchorSignerCommand {
        TrustAnchorSignerCommand::new(
            id,
            None,
            TrustAnchorSignerCommandDetails::TrustAnchorSignerRequest(request, signer),
            actor,
        )
    }
}

// Storable Commands (KrillSigner cannot be de-/serialized)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorSignerStorableCommand {
    TrustAnchorSignerRequest(TrustAnchorSignedRequest),
}

impl From<&TrustAnchorSignerCommandDetails> for TrustAnchorSignerStorableCommand {
    fn from(details: &TrustAnchorSignerCommandDetails) -> Self {
        match details {
            TrustAnchorSignerCommandDetails::TrustAnchorSignerRequest(request, _) => {
                TrustAnchorSignerStorableCommand::TrustAnchorSignerRequest(request.clone())
            }
        }
    }
}

impl eventsourcing::WithStorableDetails for TrustAnchorSignerStorableCommand {
    fn summary(&self) -> crate::commons::api::CommandSummary {
        match self {
            TrustAnchorSignerStorableCommand::TrustAnchorSignerRequest(request) => {
                crate::commons::api::CommandSummary::new("cmd-ta-signer-process-request", &self)
                    .with_arg("nonce", &request.content().nonce)
            }
        }
    }
}

impl fmt::Display for TrustAnchorSignerStorableCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        match self {
            TrustAnchorSignerStorableCommand::TrustAnchorSignerRequest(req) => {
                write!(f, "Process signer request with nonce: {}", req.content().nonce)
            }
        }
    }
}

impl eventsourcing::Aggregate for TrustAnchorSigner {
    type Command = TrustAnchorSignerCommand;
    type StorableCommandDetails = TrustAnchorSignerStorableCommand;
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
            exchanges: TrustAnchorProxySignerExchanges::default(),
        })
    }

    fn version(&self) -> u64 {
        self.version
    }

    fn apply(&mut self, event: Self::Event) {
        let (handle, _version, details) = event.unpack();

        if log_enabled!(log::Level::Trace) {
            trace!(
                "Applying event to Trust Anchor Signer '{}', version: {}: {}",
                handle,
                self.version,
                details
            );
        }
        self.version += 1;

        match details {
            TrustAnchorSignerEventDetails::ProxySignerExchangeDone(exchange) => {
                self.objects = exchange.response.content().objects.clone();
                self.exchanges.0.push(exchange);
            }
        }
    }

    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Sending command to Trust Anchor Signer '{}', version: {}: {}",
                self.handle,
                self.version,
                command
            );
        }

        match command.into_details() {
            TrustAnchorSignerCommandDetails::TrustAnchorSignerRequest(request, signer) => {
                self.process_signer_request(request, &signer)
            }
        }
    }
}

impl TrustAnchorSigner {
    pub fn get_signer_info(&self) -> TrustAnchorSignerInfo {
        TrustAnchorSignerInfo {
            id: self.id.clone(),
            objects: self.objects.clone(),
            ta_cert_details: self.ta_cert_details.clone(),
        }
    }

    pub fn get_associated_proxy_id(&self) -> &IdCertInfo {
        &self.proxy_id
    }
}

pub struct TrustAnchorSignerInitCommand {
    pub handle: TrustAnchorHandle,
    pub proxy_id: IdCertInfo,
    pub repo_info: RepoInfo,
    pub tal_https: Vec<uri::Https>,
    pub tal_rsync: uri::Rsync,
    pub private_key_pem: Option<String>,
    pub signer: Arc<KrillSigner>,
}

impl TrustAnchorSigner {
    /// Creates an initialisation event that can be used to create a new Trust Anchor Signer.
    pub fn create_init(cmd: TrustAnchorSignerInitCommand) -> KrillResult<TrustAnchorSignerInitEvent> {
        let signer = cmd.signer;

        let id = Rfc8183Id::generate(&signer)?.into();
        let proxy_id = cmd.proxy_id;
        let ta_cert_details = Self::create_ta_cert_details(
            cmd.repo_info,
            cmd.tal_https,
            cmd.tal_rsync,
            cmd.private_key_pem,
            &signer,
        )?;
        let objects = TrustAnchorObjects::create(ta_cert_details.cert(), &signer)?;

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
        private_key_pem: Option<String>,
        signer: &KrillSigner,
    ) -> KrillResult<TaCertDetails> {
        let key = match private_key_pem {
            None => signer.create_key(),
            Some(pem) => signer.import_key(&pem),
        }?;

        let resources = ResourceSet::all();

        let cert = {
            let serial: Serial = signer.random_serial()?;

            let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
            let name = pub_key.to_subject_name();

            let mut cert = TbsCert::new(
                serial,
                name.clone(),
                SignSupport::sign_validity_years(TA_CERTIFICATE_VALIDITY_YEARS),
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
        request: TrustAnchorSignedRequest,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<TrustAnchorSignerEvent>> {
        let mut objects = self.objects.clone();

        let mut child_responses: HashMap<ChildHandle, HashMap<KeyIdentifier, ProvisioningResponse>> = HashMap::new();

        let signing_cert = self.ta_cert_details.cert();
        let ta_rcn = ta_resource_class_name();

        for child_request in &request.content().child_requests {
            let mut responses = HashMap::new();

            for (key_id, provisioning_request) in child_request.requests.clone() {
                match provisioning_request {
                    ProvisioningRequest::Issuance(issuance_req) => {
                        let (rcn, limit, csr) = issuance_req.unpack();

                        if rcn != ta_rcn {
                            return Err(Error::Custom(format!(
                                "TA child request uses unknown resource class name '{}'",
                                rcn
                            )));
                        }

                        let validity = SignSupport::sign_validity_weeks(TA_ISSUED_CERTIFICATE_VALIDITY_WEEKS);
                        let issue_resources = limit.apply_to(&child_request.resources)?;

                        // Create issued certificate
                        let issued_cert = SignSupport::make_issued_cert(
                            CsrInfo::try_from(&csr)?,
                            &issue_resources,
                            limit.clone(),
                            signing_cert,
                            validity,
                            signer,
                        )?;

                        // Create response for certificate
                        let response = IssuanceResponse::new(
                            ta_rcn.clone(),
                            issue_resources,
                            validity.not_after(),
                            provisioning::IssuedCert::new(
                                issued_cert.uri().clone(),
                                limit,
                                issued_cert.to_cert().unwrap(), // cannot fail
                            ),
                            provisioning::SigningCert::new(signing_cert.uri().clone(), signing_cert.to_cert().unwrap()),
                        );

                        // extend the objects with the issued certs
                        objects.add_issued(issued_cert);

                        // add the response so it can be returned to the child
                        responses.insert(key_id, ProvisioningResponse::Issuance(response));
                    }
                    ProvisioningRequest::Revocation(revocation_req) => {
                        let response = RevocationResponse::from(&revocation_req);

                        let (rcn, key) = revocation_req.unpack();

                        if rcn != ta_rcn {
                            return Err(Error::Custom(format!(
                                "TA child request uses unknown resource class name '{}'",
                                rcn
                            )));
                        }

                        // Try to revoke for this key. Return an error in case of issues.
                        // Note.. we could make this idempotent instead. I.e. if there is no
                        // such key, then perhaps we can just consider it revoked and call
                        // it a day. Then again, we really do not expect that this should
                        // happen between a krill CA and its local TA (proxy). So.. it's
                        // most likely best to have an explicit error in this case so the
                        // issue can be investigated.
                        if !objects.revoke_issued(&key) {
                            return Err(Error::Custom(format!(
                                "TA child requests revocation for unknown key '{}'",
                                key
                            )));
                        }

                        responses.insert(key_id, ProvisioningResponse::Revocation(response));
                    }
                }
            }

            child_responses.insert(child_request.child.clone(), responses);
        }

        objects.republish(signing_cert, signer)?;

        let response = TrustAnchorSignerResponse {
            nonce: request.content().nonce.clone(),
            objects,
            child_responses,
        }
        .sign(self.id.public_key().key_identifier(), signer)?;

        let exchange = TrustAnchorProxySignerExchange {
            time: Time::now(),
            request,
            response,
        };

        Ok(vec![TrustAnchorSignerEvent::new(
            &self.handle,
            self.version,
            TrustAnchorSignerEventDetails::ProxySignerExchangeDone(exchange),
        )])
    }

    /// Get all exchanges
    pub fn get_exchanges(&self) -> &TrustAnchorProxySignerExchanges {
        &self.exchanges
    }

    /// Get exchange for nonce
    pub fn get_exchange(&self, nonce: &Nonce) -> Option<&TrustAnchorProxySignerExchange> {
        self.exchanges.0.iter().find(|ex| &ex.request.content().nonce == nonce)
    }

    pub fn get_latest_exchange(&self) -> Option<&TrustAnchorProxySignerExchange> {
        self.exchanges.0.last()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TrustAnchorProxySignerExchanges(Vec<TrustAnchorProxySignerExchange>);

impl fmt::Display for TrustAnchorProxySignerExchanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for exchange in &self.0 {
            let revision = exchange.response.content().objects.revision();

            writeln!(
                f,
                "==================================================================================="
            )?;
            writeln!(f, "                  Session number:    {}", revision.number() - 1)?; // We don't count init mft
            writeln!(
                f,
                "                  Session date:      {}",
                exchange.time.to_rfc3339_opts(SecondsFormat::Secs, false)
            )?;
            writeln!(
                f,
                "                  Plan next before:  {}",
                revision.next_update().to_rfc3339_opts(SecondsFormat::Secs, false)
            )?;
            writeln!(
                f,
                "==================================================================================="
            )?;
            writeln!(f)?;
            if !exchange.response.content().child_responses.is_empty() {
                writeln!(f, "   response |               key identifier             |  child ")?;
                writeln!(f, "   --------------------------------------------------------------")?;

                for (child, response) in &exchange.response.content().child_responses {
                    for (key, res) in response.iter() {
                        let res_type = match res {
                            ProvisioningResponse::Issuance(_) => "issued  ",
                            ProvisioningResponse::Revocation(_) => "revoked ",
                            ProvisioningResponse::Error => "error   ",
                        };
                        writeln!(f, "   {} | {} | {}", res_type, key, child)?;
                    }
                }
                writeln!(f)?;
            }

            for published in exchange.response.content().objects.publish_elements().unwrap() {
                writeln!(f, "   {}", published.uri())?;
            }

            writeln!(f)?;
        }
        Ok(())
    }
}
