//! Trust Anchor Signer
//!
//! Handles signing operations using the (offline) Trust Anchor key.
//! Designed to work with a single associated proxy which is responsible
//! for all other functions, like publishing and talking to child CAs.
//! The proxy makes sign requests for the signer to sign.
use super::*;

use std::{collections::HashMap, convert::TryFrom, fmt, sync::Arc};

use rpki::{
    ca::{
        idexchange::{ChildHandle, RepoInfo},
        provisioning::RequestResourceLimit,
    },
    repository::{
        cert::{KeyUsage, Overclaim, TbsCert},
        resources::ResourceSet,
        x509::{Serial, Time, Validity},
    },
    uri,
};

use crate::{
    commons::{
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
    pub handle: TrustAnchorHandle,
    pub proxy_id: IdCertInfo,
    pub repo_info: RepoInfo,
    pub tal_https: Vec<uri::Https>,
    pub tal_rsync: uri::Rsync,
    // todo: support importing existing key
    pub signer: Arc<KrillSigner>,
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
        request: super::TrustAnchorRequest,
        signer: &KrillSigner,
    ) -> KrillResult<TrustAnchorResponse> {
        let mut objects = self.objects.clone();

        let mut child_responses: HashMap<ChildHandle, Vec<ProvisioningResponse>> = HashMap::new();

        objects.increment_revision();

        let signing_cert = self.ta_cert_details.cert();

        for (child, child_requests) in request.child_requests {
            child_responses.insert(child, vec![]);
            let resources = child_requests.resources;
            for provisioning_request in child_requests.requests {
                match provisioning_request {
                    ProvisioningRequest::Issuance(issuance_req) => {
                        let (_rcn, limit, csr) = issuance_req.unpack();

                        let validity = SignSupport::sign_validity_weeks(52);

                        let issued = SignSupport::make_issued_cert(
                            CsrInfo::try_from(&csr)?,
                            &resources,
                            limit,
                            signing_cert,
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
