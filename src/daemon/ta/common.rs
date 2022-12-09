//! Common types used in the communication (API) between the Proxy and Signer

use std::collections::HashMap;

use rpki::{
    ca::{idexchange::ChildHandle, provisioning, publication::Base64},
    crypto::{KeyIdentifier, PublicKey},
    repository::{resources::ResourceSet, x509::Time},
    uri,
};

use crate::{
    commons::{
        api::{IdCertInfo, IssuedCertificate, ReceivedCert, Revocations},
        crypto::KrillSigner,
        KrillResult,
    },
    daemon::ca::{CrlBuilder, ManifestBuilder, ObjectSetRevision, PublishedCrl, PublishedManifest, UsedKeyState},
};

//------------ TrustAnchorObjects ------------------------------------------

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
    pub fn create(ta_cert_details: &TaCertDetails, signer: &KrillSigner) -> KrillResult<Self> {
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

    pub fn revision(&self) -> &ObjectSetRevision {
        &self.revision
    }

    pub fn increment_revision(&mut self) {
        self.revision.next(Self::next_update());
    }

    pub fn this_update() -> Time {
        Time::five_minutes_ago()
    }

    pub fn next_update() -> Time {
        Time::now() + chrono::Duration::weeks(12)
    }
}

//------------ TaCertDetails -------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaCertDetails {
    cert: ReceivedCert,
    tal: TrustAnchorLocator,
}

impl TaCertDetails {
    pub fn new(cert: ReceivedCert, tal: TrustAnchorLocator) -> Self {
        TaCertDetails { cert, tal }
    }

    pub fn cert(&self) -> &ReceivedCert {
        &self.cert
    }

    pub fn resources(&self) -> &ResourceSet {
        self.cert.resources()
    }

    pub fn tal(&self) -> &TrustAnchorLocator {
        &self.tal
    }
}

//------------ TrustAnchorLocator --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorLocator {
    uris: Vec<uri::Https>,
    rsync_uri: uri::Rsync,
    encoded_ski: Base64,
}

impl TrustAnchorLocator {
    /// Creates a new TAL, panics when the provided Cert is not a TA cert.
    pub fn new(uris: Vec<uri::Https>, rsync_uri: uri::Rsync, public_key: &PublicKey) -> Self {
        let encoded_ski = Base64::from_content(&public_key.to_info_bytes());

        TrustAnchorLocator {
            uris,
            rsync_uri,
            encoded_ski,
        }
    }
}

impl std::fmt::Display for TrustAnchorLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let base64_string = self.encoded_ski.to_string();

        for uri in self.uris.iter() {
            writeln!(f, "{}", uri)?;
        }
        writeln!(f, "{}", self.rsync_uri)?;

        writeln!(f)?;

        let len = base64_string.len();
        let wrap = 64;

        for i in 0..=(len / wrap) {
            if (i * wrap + wrap) < len {
                writeln!(f, "{}", &base64_string[i * wrap..i * wrap + wrap])?;
            } else {
                write!(f, "{}", &base64_string[i * wrap..])?;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxySignerInfo {
    // The ID of the associated signer.
    pub id: IdCertInfo,
    // Trust Anchor objects to be published
    pub objects: TrustAnchorObjects,
    // The TA certificate and TAL
    pub ta_cert_details: TaCertDetails,
}

/// Request for the Trust Anchor Signer to update the signed
/// objects (new mft, crl). Can contain requests for one or
/// more children to either issue a new certificate, or revoke
/// a key. If there are no requests for a child, then it is
/// assumed that the current issued certificate(s) to the child
/// should not change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorRequest {
    pub nonce: String, // should be matched in response (replay protection)
    pub child_requests: HashMap<ChildHandle, TrustAnchorChildRequests>,
}

/// Requests for Trust Anchor Child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorChildRequests {
    pub child: ChildHandle,
    pub resources: ResourceSet,
    pub requests: Vec<ProvisioningRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorResponse {
    pub nonce: String, // should match the request (replay protection)
    pub objects: TrustAnchorObjects,
    pub child_responses: HashMap<ChildHandle, Vec<ProvisioningResponse>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorChild {
    pub handle: ChildHandle,
    pub id: IdCertInfo,
    pub resources: ResourceSet,
    pub used_keys: HashMap<KeyIdentifier, UsedKeyState>,
    pub open_request: Option<ProvisioningRequest>,
    pub open_response: Option<ProvisioningResponse>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProvisioningRequest {
    Issuance(provisioning::IssuanceRequest),
    Revocation(provisioning::RevocationRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProvisioningResponse {
    Issuance(provisioning::IssuanceResponse),
    Revocation(provisioning::RevocationResponse),
    Error(String),
}
