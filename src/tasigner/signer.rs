//! Trust Anchor Signer
//!
//! Handles signing operations using the (offline) Trust Anchor key.
//! Designed to work with a single associated proxy which is responsible
//! for all other functions, like publishing and talking to child CAs.
//! The proxy makes sign requests for the signer to sign.
use super::*;

use std::{collections::HashMap, fmt, sync::Arc};

use chrono::SecondsFormat;
use log::{log_enabled, trace};
use rpki::{
    ca::{
        idexchange::{CaHandle, ChildHandle, RepoInfo},
        provisioning::{
            self, IssuanceResponse, RequestResourceLimit, RevocationResponse,
        },
    },
    crypto::KeyIdentifier,
    repository::{
        cert::{KeyUsage, Overclaim, TbsCert},
        resources::ResourceSet,
        x509::{Serial, Time},
    },
    uri,
};
use serde::{Deserialize, Serialize};

use crate::{
    commons::{
        actor::Actor,
        crypto::{CsrInfo, KrillSigner, SignSupport},
        error::Error,
        eventsourcing::{
            self, Event, InitCommandDetails, InitEvent, WithStorableDetails
        },
        KrillResult,
    },
};
use crate::api::ca::{IdCertInfo, ObjectName, ReceivedCert};
use crate::api::ta::{
    Nonce, ProvisioningRequest, ProvisioningResponse, TaCertDetails,
    TrustAnchorLocator, TrustAnchorObjects, TrustAnchorProxySignerExchange,
    TrustAnchorSignedRequest, TrustAnchorSignerInfo,
    TrustAnchorSignerResponse,
};
use crate::constants::ta_resource_class_name;


//------------ TrustAnchorSigner -------------------------------------------

/// The Trust Anchor Signer signs requests sent to it by its associated
/// proxy, as long as it can verify that the proxy signed that request.

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustAnchorSigner {
    // event-sourcing support
    handle: CaHandle,
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

pub type TrustAnchorSignerInitCommand =
    eventsourcing::SentInitCommand<TrustAnchorSignerInitCommandDetails>;

#[derive(Clone, Debug)]
pub struct TrustAnchorSignerInitCommandDetails {
    pub proxy_id: IdCertInfo,
    pub repo_info: RepoInfo,
    pub tal_https: Vec<uri::Https>,
    pub tal_rsync: uri::Rsync,
    pub private_key_pem: Option<String>,
    pub ta_mft_nr_override: Option<u64>,
    pub timing: TaTimingConfig,
    pub signer: Arc<KrillSigner>,
}

impl fmt::Display for TrustAnchorSignerInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

impl InitCommandDetails for TrustAnchorSignerInitCommandDetails {
    type StorableDetails = TrustAnchorSignerStorableCommand;

    fn store(&self) -> Self::StorableDetails {
        TrustAnchorSignerStorableCommand::make_init()
    }
}


pub type TrustAnchorSignerCommand =
    eventsourcing::SentCommand<TrustAnchorSignerCommandDetails>;

// Initialisation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignerInitEvent {
    id: IdCertInfo,
    proxy_id: IdCertInfo,
    ta_cert_details: TaCertDetails,
    objects: TrustAnchorObjects,
}

impl InitEvent for TrustAnchorSignerInitEvent {}

impl fmt::Display for TrustAnchorSignerInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the init
        // event.
        write!(f, "Trust Anchor Signer was initialised.")
    }
}

// Events
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorSignerEvent {
    ProxySignerExchangeDone(TrustAnchorProxySignerExchange),
    SignerReissueDone(TaCertDetails)
}

impl Event for TrustAnchorSignerEvent {}

impl fmt::Display for TrustAnchorSignerEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TrustAnchorSignerEvent::ProxySignerExchangeDone(exchange) => {
                write!(
                    f,
                    "Proxy signer exchange done on {} for nonce: {}",
                    exchange.time.to_rfc3339(),
                    exchange.request.content().nonce
                )
            },
            TrustAnchorSignerEvent::SignerReissueDone(ta_cert_details) => {
                write!(
                    f,
                    "Signer reissue done with serial {}",
                    ta_cert_details.cert().serial
                )
            }
        }
    }
}

// Commands
#[derive(Clone, Debug)]
pub enum TrustAnchorSignerCommandDetails {
    TrustAnchorSignerRequest {
        signed_request: TrustAnchorSignedRequest,
        ta_timing_config: TaTimingConfig,
        ta_mft_number_override: Option<u64>,
        signer: Arc<KrillSigner>,
    },
    TrustAnchorSignerReissueRequest {
        repo_info: RepoInfo,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        timing: TaTimingConfig,
        signer: Arc<KrillSigner>,
    },
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
        id: &CaHandle,
        signed_request: TrustAnchorSignedRequest,
        ta_timing_config: TaTimingConfig,
        ta_mft_number_override: Option<u64>,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> TrustAnchorSignerCommand {
        TrustAnchorSignerCommand::new(
            id.clone(),
            None,
            TrustAnchorSignerCommandDetails::TrustAnchorSignerRequest {
                signed_request,
                ta_timing_config,
                ta_mft_number_override,
                signer,
            },
            actor,
        )
    }

    pub fn make_reissue_command(
        id: &CaHandle,
        repo_info: RepoInfo,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        ta_timing_config: TaTimingConfig,
        signer: Arc<KrillSigner>,
        actor: &Actor,
    ) -> TrustAnchorSignerCommand {
        TrustAnchorSignerCommand::new(
            id.clone(),
            None,
            TrustAnchorSignerCommandDetails::TrustAnchorSignerReissueRequest {
                repo_info,
                tal_https,
                tal_rsync,
                timing: ta_timing_config,
                signer,
            }, 
            actor
        )
    }
}

// Storable Commands (KrillSigner cannot be de-/serialized)
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TrustAnchorSignerStorableCommand {
    Init,
    TrustAnchorSignerRequest(TrustAnchorSignedRequest),
    TrustAnchorSignerReissueRequest {
        repo_info: RepoInfo,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
    }
}

impl From<&TrustAnchorSignerCommandDetails>
    for TrustAnchorSignerStorableCommand
{
    fn from(details: &TrustAnchorSignerCommandDetails) -> Self {
        match details {
            TrustAnchorSignerCommandDetails::TrustAnchorSignerRequest {
                signed_request,
                ..
            } => TrustAnchorSignerStorableCommand::TrustAnchorSignerRequest(
                signed_request.clone(),
            ),
            TrustAnchorSignerCommandDetails::TrustAnchorSignerReissueRequest { 
                repo_info, tal_https, tal_rsync, ..
            } => {
                Self::TrustAnchorSignerReissueRequest {
                    repo_info: repo_info.clone(),
                    tal_https: tal_https.clone(),
                    tal_rsync: tal_rsync.clone(),
                }
            }
        }
    }
}


impl eventsourcing::WithStorableDetails for TrustAnchorSignerStorableCommand {
    fn summary(&self) -> crate::api::history::CommandSummary {
        match self {
            TrustAnchorSignerStorableCommand::Init => {
                crate::api::history::CommandSummary::new(
                    "cmd-ta-signer-init",
                    self,
                )
            }
            Self::TrustAnchorSignerRequest(
                request,
            ) => {
                crate::api::history::CommandSummary::new(
                    "cmd-ta-signer-process-request",
                    self,
                ).arg("nonce", &request.content().nonce)
            }
            Self::TrustAnchorSignerReissueRequest {
                repo_info: _,
                tal_https: _,
                tal_rsync: _,
            } => {
                crate::api::history::CommandSummary::new(
                    "cmd-ta-signer-reissue", 
                    self
                )
                // XXX This should probably include the stored values.
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

impl fmt::Display for TrustAnchorSignerStorableCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // note that this is a summary, full details are stored in the json.
        match self {
            TrustAnchorSignerStorableCommand::Init => {
                write!(f, "Initialise TA signer")
            }
            TrustAnchorSignerStorableCommand::TrustAnchorSignerRequest(
                req,
            ) => {
                write!(
                    f,
                    "Process signer request with nonce: {}",
                    req.content().nonce
                )
            },
            Self::TrustAnchorSignerReissueRequest {
                ..
            } => {
                write!(f, "Reissue the TA signer")
                // XXX This should probably print all the values.
            }
        }
    }
}

impl eventsourcing::Aggregate for TrustAnchorSigner {
    type Command = TrustAnchorSignerCommand;
    type StorableCommandDetails = TrustAnchorSignerStorableCommand;
    type Event = TrustAnchorSignerEvent;

    type InitCommand = TrustAnchorSignerInitCommand;
    type InitEvent = TrustAnchorSignerInitEvent;
    type Error = Error;

    fn init(handle: &CaHandle, event: Self::InitEvent) -> Self {
        TrustAnchorSigner {
            handle: handle.clone(),
            version: 1,
            id: event.id,
            proxy_id: event.proxy_id,
            ta_cert_details: event.ta_cert_details,
            objects: event.objects,
            exchanges: TrustAnchorProxySignerExchanges::default(),
        }
    }

    fn process_init_command(
        command: TrustAnchorSignerInitCommand,
    ) -> Result<TrustAnchorSignerInitEvent, Error> {
        let cmd = command.into_details();
        let timing = cmd.timing;

        let signer = cmd.signer;

        let id = signer.create_self_signed_id_cert()?.into();
        let proxy_id = cmd.proxy_id;
        let ta_cert_details = Self::create_ta_cert_details(
            cmd.repo_info,
            cmd.tal_https,
            cmd.tal_rsync,
            cmd.private_key_pem,
            timing.certificate_validity_years,
            &signer,
        )?;
        let objects = TrustAnchorObjects::create(
            ta_cert_details.cert(),
            cmd.ta_mft_nr_override.unwrap_or(1),
            timing.mft_next_update_weeks,
            &signer,
        )?;

        Ok(TrustAnchorSignerInitEvent {
            id,
            proxy_id,
            ta_cert_details,
            objects,
        })
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
                "Applying event to Trust Anchor Signer '{}', version: {}: {}",
                self.handle,
                self.version,
                event
            );
        }

        match event {
            TrustAnchorSignerEvent::ProxySignerExchangeDone(exchange) => {
                self.objects = exchange.response.content().objects.clone();
                self.exchanges.0.push(exchange);
            },
            TrustAnchorSignerEvent::SignerReissueDone(ta_cert_details) => {
                self.ta_cert_details = ta_cert_details;
            }
        }
    }

    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Event>, Self::Error> {
        if log_enabled!(log::Level::Trace) {
            trace!(
                "Sending command to Trust Anchor Signer '{}', version: {}: {}",
                self.handle,
                self.version,
                command
            );
        }

        match command.into_details() {
            TrustAnchorSignerCommandDetails::TrustAnchorSignerRequest {
                signed_request,
                ta_timing_config,
                ta_mft_number_override,
                signer,
            } => self.process_signer_request(
                signed_request,
                ta_timing_config,
                ta_mft_number_override,
                &signer,
            ),
            TrustAnchorSignerCommandDetails::TrustAnchorSignerReissueRequest { 
                repo_info, 
                tal_https, 
                tal_rsync, 
                timing, 
                signer 
            } => {
                let years = timing.certificate_validity_years;
                let res = self.update_ta_cert_details(
                    repo_info, 
                    tal_https, 
                    tal_rsync, 
                    years, 
                    &signer
                );
                match res {
                    Err(r) => Err(r),
                    Ok(r) => Ok(vec![
                            TrustAnchorSignerEvent::SignerReissueDone(r)])
                }
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

impl TrustAnchorSigner {
    fn create_ta_cert_details(
        repo_info: RepoInfo,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        private_key_pem: Option<String>,
        years: i32,
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
                SignSupport::sign_validity_years(years),
                Some(name),
                pub_key.clone(),
                KeyUsage::Ca,
                Overclaim::Refuse,
            );

            cert.set_basic_ca(Some(true));

            // The TA will publish directly in its root. It only has 1
            // resource class so it does not use namespaces
            // (sub-folders). Furthermore, this should facilitate
            // a structure where the TA can publish to the root of the
            // rsync repository, and other CAs get their own folders under it.
            // This will help recursive rsync fetches.
            let ns = "";

            cert.set_ca_repository(Some(repo_info.ca_repository(ns)));
            cert.set_rpki_manifest(Some(repo_info.resolve(
                ns,
                ObjectName::mft_from_ca_key(&pub_key.key_identifier()).as_ref(),
            )));
            cert.set_rpki_notify(repo_info.rpki_notify().cloned());

            cert.set_as_resources(resources.to_as_resources());
            cert.set_v4_resources(resources.to_ip_resources_v4());
            cert.set_v6_resources(resources.to_ip_resources_v6());

            signer.sign_cert(cert, &key)?
        };

        let tal = TrustAnchorLocator::new(
            tal_https,
            tal_rsync.clone(),
            cert.subject_public_key_info(),
        );

        let rcvd_cert = ReceivedCert::create(
            cert,
            tal_rsync,
            resources,
            RequestResourceLimit::default(),
        )
        .map_err(Error::custom)?;

        Ok(TaCertDetails::new(rcvd_cert, tal))
    }
    
    fn update_ta_cert_details(
        &self,
        repo_info: RepoInfo,
        tal_https: Vec<uri::Https>,
        tal_rsync: uri::Rsync,
        years: i32,
        signer: &KrillSigner,
    ) -> KrillResult<TaCertDetails> {
        let resources = ResourceSet::all();

        let key = self.ta_cert_details.cert().key_identifier();

        let cert = {
            let serial: Serial = signer.random_serial()?;

            let pub_key = signer.get_key_info(&key).map_err(Error::signer)?;
            let name = pub_key.to_subject_name();

            let mut cert = TbsCert::new(
                serial,
                name.clone(),
                SignSupport::sign_validity_years(years),
                Some(name),
                pub_key.clone(),
                KeyUsage::Ca,
                Overclaim::Refuse,
            );

            cert.set_basic_ca(Some(true));

            // The TA will publish directly in its root. It only has 1
            // resource class so it does not use namespaces
            // (sub-folders). Furthermore, this should facilitate
            // a structure where the TA can publish to the root of the
            // rsync repository, and other CAs get their own folders under it.
            // This will help recursive rsync fetches.
            let ns = "";

            cert.set_ca_repository(Some(repo_info.ca_repository(ns)));
            cert.set_rpki_manifest(Some(repo_info.resolve(
                ns,
                ObjectName::mft_from_ca_key(&pub_key.key_identifier()).as_ref(),
            )));
            cert.set_rpki_notify(repo_info.rpki_notify().cloned());

            cert.set_as_resources(resources.to_as_resources());
            cert.set_v4_resources(resources.to_ip_resources_v4());
            cert.set_v6_resources(resources.to_ip_resources_v6());

            signer.sign_cert(cert, &key)?
        };

        let tal = TrustAnchorLocator::new(
            tal_https,
            tal_rsync.clone(),
            cert.subject_public_key_info(),
        );

        let rcvd_cert = ReceivedCert::create(
            cert,
            tal_rsync,
            resources,
            RequestResourceLimit::default(),
        )
        .map_err(Error::custom)?;

        Ok(TaCertDetails::new(rcvd_cert, tal))
    }

    /// Process a request.
    fn process_signer_request(
        &self,
        signed_request: TrustAnchorSignedRequest,
        ta_timing_config: TaTimingConfig,
        ta_mft_number_override: Option<u64>,
        signer: &KrillSigner,
    ) -> KrillResult<Vec<TrustAnchorSignerEvent>> {
        // Let's first make sure this request is valid
        // and the 'content' is not tampered with.
        signed_request.validate(&self.proxy_id)?;

        let mut objects = self.objects.clone();

        let mut child_responses: HashMap<
            ChildHandle,
            HashMap<KeyIdentifier, ProvisioningResponse>,
        > = HashMap::new();

        let signing_cert = self.ta_cert_details.cert();
        let ta_rcn = ta_resource_class_name();

        for child_request in &signed_request.content().child_requests {
            let mut responses = HashMap::new();

            for (key_id, provisioning_request) in
                child_request.requests.clone()
            {
                match provisioning_request {
                    ProvisioningRequest::Issuance(issuance_req) => {
                        let (rcn, limit, csr) = issuance_req.unpack();

                        if rcn != ta_rcn {
                            return Err(Error::Custom(format!(
                                "TA child request uses unknown resource class name '{}'",
                                rcn
                            )));
                        }

                        let validity = SignSupport::sign_validity_weeks(
                            ta_timing_config
                                .issued_certificate_validity_weeks,
                        );
                        let issue_resources =
                            limit.apply_to(&child_request.resources)?;

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
                                issued_cert.uri.clone(),
                                limit,
                                issued_cert.to_cert().unwrap(), /* cannot fail */
                            ),
                            provisioning::SigningCert::new(
                                signing_cert.uri.clone(),
                                signing_cert.to_cert().unwrap(),
                            ),
                        );

                        // extend the objects with the issued certs
                        objects.add_issued(issued_cert);

                        // add the response so it can be returned to the child
                        responses.insert(
                            key_id,
                            ProvisioningResponse::Issuance(response),
                        );
                    }
                    ProvisioningRequest::Revocation(revocation_req) => {
                        let response =
                            RevocationResponse::from(&revocation_req);

                        let (rcn, key) = revocation_req.unpack();

                        if rcn != ta_rcn {
                            return Err(Error::Custom(format!(
                                "TA child request uses unknown resource class name '{}'",
                                rcn
                            )));
                        }

                        // Try to revoke for this key. Return an error in case
                        // of issues. Note.. we could
                        // make this idempotent instead. I.e. if there is no
                        // such key, then perhaps we can just consider it
                        // revoked and call
                        // it a day. Then again, we really do not expect that
                        // this should happen between
                        // a krill CA and its local TA (proxy). So.. it's
                        // most likely best to have an explicit error in this
                        // case so the issue can be
                        // investigated.
                        if !objects.revoke_issued(&key) {
                            return Err(Error::Custom(format!(
                                "TA child requests revocation for unknown key '{}'",
                                key
                            )));
                        }

                        responses.insert(
                            key_id,
                            ProvisioningResponse::Revocation(response),
                        );
                    }
                }
            }

            child_responses.insert(child_request.child.clone(), responses);
        }

        objects.republish(
            signing_cert,
            ta_timing_config.mft_next_update_weeks,
            ta_mft_number_override,
            signer,
        )?;

        let response = TrustAnchorSignerResponse {
            nonce: signed_request.content().nonce.clone(),
            objects,
            child_responses,
        }
        .sign(
            ta_timing_config.signed_message_validity_days,
            self.id.public_key.key_identifier(),
            signer,
        )?;

        let exchange = TrustAnchorProxySignerExchange {
            time: Time::now(),
            request: signed_request,
            response,
        };

        Ok(vec![TrustAnchorSignerEvent::ProxySignerExchangeDone(
            exchange,
        )])
    }

    /// Get all exchanges
    pub fn get_exchanges(&self) -> &TrustAnchorProxySignerExchanges {
        &self.exchanges
    }

    /// Get exchange for nonce
    pub fn get_exchange(
        &self,
        nonce: &Nonce,
    ) -> Option<&TrustAnchorProxySignerExchange> {
        self.exchanges
            .0
            .iter()
            .find(|ex| &ex.request.content().nonce == nonce)
    }

    pub fn get_latest_exchange(
        &self,
    ) -> Option<&TrustAnchorProxySignerExchange> {
        self.exchanges.0.last()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TrustAnchorProxySignerExchanges(
    Vec<TrustAnchorProxySignerExchange>,
);

impl fmt::Display for TrustAnchorProxySignerExchanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for exchange in &self.0 {
            let revision = exchange.response.content().objects.revision();

            writeln!(
                f,
                "==================================================================================="
            )?;
            writeln!(
                f,
                "                  Session number:    {}",
                revision.number() - 1
            )?; // We don't count init mft
            writeln!(
                f,
                "                  Session date:      {}",
                exchange.time.to_rfc3339_opts(SecondsFormat::Secs, false)
            )?;
            writeln!(
                f,
                "                  Plan next before:  {}",
                revision
                    .next_update()
                    .to_rfc3339_opts(SecondsFormat::Secs, false)
            )?;
            writeln!(
                f,
                "==================================================================================="
            )?;
            writeln!(f)?;
            if !exchange.response.content().child_responses.is_empty() {
                writeln!(f, "   response |               key identifier             |  child ")?;
                writeln!(f, "   --------------------------------------------------------------")?;

                for (child, response) in
                    &exchange.response.content().child_responses
                {
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

            for published in exchange
                .response
                .content()
                .objects
                .publish_elements()
                .unwrap()
            {
                writeln!(f, "   {}", published.uri)?;
            }

            writeln!(f)?;
        }
        Ok(())
    }
}
