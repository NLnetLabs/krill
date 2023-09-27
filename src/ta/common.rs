//! Common types used in the communication (API) between the Proxy and Signer

use std::{
    collections::HashMap,
    fmt::{self, Debug},
    sync::Arc,
};

use bytes::Bytes;
use rpki::{
    ca::{
        idexchange::{ChildHandle, RecipientHandle, SenderHandle},
        provisioning,
        publication::Base64,
        sigmsg::SignedMessage,
    },
    crypto::{KeyIdentifier, PublicKey},
    repository::{resources::ResourceSet, x509::Time},
    uri,
};
use serde::Serialize;

use crate::{
    commons::{
        api::{IdCertInfo, IssuedCertificate, ObjectName, ReceivedCert, Revocations},
        crypto::KrillSigner,
        error::Error,
        KrillResult,
    },
    daemon::ca::{
        CrlBuilder, ManifestBuilder, ObjectSetRevision, PublishedCrl, PublishedManifest, PublishedObject, UsedKeyState,
    },
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

    // TA Key Identifier (may not change)
    key_identifier: KeyIdentifier,

    // Base URI for objects published by this TA (may not change)
    base_uri: uri::Rsync,

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
    pub fn create(signing_cert: &ReceivedCert, next_update_weeks: i64, signer: &KrillSigner) -> KrillResult<Self> {
        let revision = ObjectSetRevision::new(1, Self::this_update(), Self::next_update(next_update_weeks));
        let key_identifier = signing_cert.key_identifier();
        let base_uri = signing_cert.ca_repository().clone();
        let revocations = Revocations::default();

        let signing_key = signing_cert.key_identifier();
        let issuer = signing_cert.subject().clone();

        let crl = CrlBuilder::build(signing_key, issuer, &revocations, revision, signer)?;

        let manifest = ManifestBuilder::new(revision)
            .with_objects(&crl, &HashMap::new())
            .build_new_mft(signing_cert, signer)
            .map(|m| m.into())?;

        Ok(TrustAnchorObjects {
            revision,
            key_identifier,
            base_uri,
            revocations,
            crl,
            manifest,
            issued: HashMap::new(),
        })
    }

    /// Publish next revision of the published objects.
    /// - Update CRL (times and revocations)
    /// - Update Manifest (times and listed objects)
    pub fn republish(
        &mut self,
        signing_cert: &ReceivedCert,
        next_update_weeks: i64,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        self.revision.next(Self::next_update(next_update_weeks));

        let signing_key = signing_cert.key_identifier();

        if signing_key != self.key_identifier {
            // This would be a bug.. we will need to re-think this when implementing
            // signed TALs and TA key rollovers.
            Err(Error::custom("TA key changed when republishing"))
        } else {
            let issuer = signing_cert.subject().clone();

            self.crl = CrlBuilder::build(signing_key, issuer, &self.revocations, self.revision, signer)?;

            self.manifest = ManifestBuilder::new(self.revision)
                .with_objects(&self.crl, &self.issued_certs_objects())
                .build_new_mft(signing_cert, signer)
                .map(|m| m.into())?;

            Ok(())
        }
    }

    pub fn publish_elements(&self) -> KrillResult<Vec<crate::commons::api::rrdp::PublishElement>> {
        let mut res = vec![];

        let mft_uri = self
            .base_uri
            .join(ObjectName::mft_for_key(&self.key_identifier).as_ref())
            .map_err(|e| Error::Custom(format!("Cannot make uri: {}", e)))?;
        res.push(self.manifest.publish_element(mft_uri));

        let crl_uri = self
            .base_uri
            .join(ObjectName::crl_for_key(&self.key_identifier).as_ref())
            .map_err(|e| Error::Custom(format!("Cannot make uri: {}", e)))?;
        res.push(self.crl.publish_element(crl_uri));

        for (name, object) in self.issued_certs_objects() {
            let cert_uri = self
                .base_uri
                .join(name.as_ref())
                .map_err(|e| Error::Custom(format!("Cannot make uri: {}", e)))?;
            res.push(object.publish_element(cert_uri));
        }
        Ok(res)
    }

    fn issued_certs_objects(&self) -> HashMap<ObjectName, PublishedObject> {
        self.issued
            .iter()
            .map(|(ki, cert)| {
                let object = PublishedObject::for_cert_info(cert);
                let name = ObjectName::cer_for_key(ki);
                (name, object)
            })
            .collect()
    }

    pub fn manifest(&self) -> &PublishedManifest {
        &self.manifest
    }

    pub fn revision(&self) -> &ObjectSetRevision {
        &self.revision
    }

    pub fn this_update() -> Time {
        Time::five_minutes_ago()
    }

    pub fn next_update(weeks: i64) -> Time {
        Time::now() + chrono::Duration::weeks(weeks)
    }

    // Adds a new issued certificate, replaces and revokes the previous if present.
    pub fn add_issued(&mut self, issued: IssuedCertificate) {
        if let Some(previous) = self.issued.insert(issued.key_identifier(), issued) {
            self.revocations.add(previous.revocation());
            self.revocations.remove_expired();
        }
    }

    // Gets an issued certificate if it is known.
    pub fn get_issued(&self, ki: &KeyIdentifier) -> Option<&IssuedCertificate> {
        self.issued.get(ki)
    }

    // Revoke any issued certificate for the given key, and remove it. Returns false
    // if there was no such certificate.
    pub fn revoke_issued(&mut self, key: &KeyIdentifier) -> bool {
        if let Some(issued) = self.issued.remove(key) {
            self.revocations.add(issued.revocation());
            self.revocations.remove_expired();
            true
        } else {
            false
        }
    }
}

impl fmt::Display for TrustAnchorObjects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f, "                 Trust Anchor Objects")?;
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f)?;
        writeln!(f, "Revision:    {}", self.revision.number())?;
        writeln!(f, "Next Update: {}", self.revision.next_update().to_rfc3339())?;
        writeln!(f)?;
        writeln!(f, "Objects:",)?;
        for publish in self.publish_elements().map_err(|_| fmt::Error)? {
            writeln!(f, "{}", publish.uri())?;
            writeln!(f, " ({})", publish.base64().to_hash())?;
        }
        writeln!(f)?;
        writeln!(f, "-------------------------------------------------------")
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

impl From<TaCertDetails> for ReceivedCert {
    fn from(details: TaCertDetails) -> Self {
        details.cert
    }
}

impl From<TaCertDetails> for TrustAnchorLocator {
    fn from(details: TaCertDetails) -> Self {
        details.tal
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

    pub fn uris(&self) -> &Vec<uri::Https> {
        &self.uris
    }

    pub fn rsync_uri(&self) -> &uri::Rsync {
        &self.rsync_uri
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

//------------ TrustAnchorSignerInfo ---------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignerInfo {
    // The ID of the associated signer.
    pub id: IdCertInfo,
    // Trust Anchor objects to be published
    pub objects: TrustAnchorObjects,
    // The TA certificate and TAL
    pub ta_cert_details: TaCertDetails,
}

impl fmt::Display for TrustAnchorSignerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f, "                 ID Certificate")?;
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f)?;
        writeln!(f, "{}", self.id)?;
        writeln!(f)?;
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f)?;
        writeln!(f, "{}", self.objects)?;
        writeln!(f)?;
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f, "                          TAL")?;
        writeln!(f, "-------------------------------------------------------")?;
        writeln!(f)?;
        writeln!(f, "{}", self.ta_cert_details.tal())?;
        writeln!(f)?;
        writeln!(f, "-------------------------------------------------------")?;

        Ok(())
    }
}

//------------ Nonce -------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Nonce(Arc<str>);

impl Nonce {
    pub fn new() -> Self {
        Nonce(uuid::Uuid::new_v4().to_string().into())
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce::new()
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

//------------ TrustAnchorProxySignerExchange ------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorProxySignerExchange {
    pub time: Time,
    pub request: TrustAnchorSignedRequest,
    pub response: TrustAnchorSignedResponse,
}

//------------ TrustAnchorSignedMessage ------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignedMessage {
    message: Base64,
}

impl TrustAnchorSignedMessage {
    pub fn validate(&self, issuer_key: &PublicKey) -> KrillResult<SignedMessage> {
        self.validate_at(issuer_key, Time::now())
    }

    pub fn validate_at(&self, issuer_key: &PublicKey, time: Time) -> KrillResult<SignedMessage> {
        let bytes = self.message.to_bytes();
        let signed_message = SignedMessage::decode(bytes, true)
            .map_err(|e| Error::Custom(format!("Cannot decode signed message: {}", e)))?;

        signed_message
            .validate_at(issuer_key, time)
            .map_err(|e| Error::Custom(format!("Invalid signed message: {}", e)))?;

        Ok(signed_message)
    }
}

impl From<SignedMessage> for TrustAnchorSignedMessage {
    fn from(signed_msg: SignedMessage) -> Self {
        let message = Base64::from_content(&signed_msg.to_captured().into_bytes());
        TrustAnchorSignedMessage { message }
    }
}

//------------ TrustAnchorSignedRequest ------------------------------------

/// A [`TrustAnchorSignerRequest`] and its signed message as base64 for
/// (re-)validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignedRequest {
    signed: TrustAnchorSignedMessage,
    request: TrustAnchorSignerRequest,
}

impl TrustAnchorSignedRequest {
    pub fn validate(&self, issuer: &IdCertInfo) -> Result<(), Error> {
        let signed_message = self.signed.validate(issuer.public_key())?;

        // Verify that the content of the signed message matches the
        // clear text request as well.
        let signed_bytes = signed_message.content().to_bytes();
        let signed_request: TrustAnchorSignerRequest = serde_json::from_slice(&signed_bytes).map_err(|e| {
            Error::Custom(format!(
                "Cannot deserialize content of signed Trust Anchor request: {}",
                e
            ))
        })?;

        if self.request != signed_request {
            Err(Error::custom(
                "Clear text request content does not match the contained signed message in Trust Anchor request",
            ))
        } else {
            Ok(())
        }
    }

    /// Get content without validation, handle with care
    pub fn content(&self) -> &TrustAnchorSignerRequest {
        &self.request
    }
}

impl fmt::Display for TrustAnchorSignedRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.request)
    }
}

//------------ TrustAnchorSignerRequest ------------------------------------

/// Request for the Trust Anchor Signer to update the signed
/// objects (new mft, crl). Can contain requests for one or
/// more children to either issue a new certificate, or revoke
/// a key. If there are no requests for a child, then it is
/// assumed that the current issued certificate(s) to the child
/// should not change.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignerRequest {
    pub nonce: Nonce, // should be matched in response (replay protection)
    pub child_requests: Vec<TrustAnchorChildRequests>,
}

impl TrustAnchorSignerRequest {
    pub fn sign(
        &self,
        signing_key: KeyIdentifier,
        validity_days: i64,
        signer: &KrillSigner,
    ) -> Result<TrustAnchorSignedRequest, Error> {
        let data = serde_json::to_string_pretty(&self).unwrap();
        let data = Bytes::from(data);

        signer
            .create_ta_signed_message(data, validity_days, &signing_key)
            .map(|msg| TrustAnchorSignedRequest {
                request: self.clone(),
                signed: msg.into(),
            })
            .map_err(Error::signer)
    }
}

impl fmt::Display for TrustAnchorSignerRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-------------------------------")?;
        writeln!(f, "nonce: {}", self.nonce)?;
        writeln!(f, "-------------------------------")?;
        writeln!(f)?;

        for request in &self.child_requests {
            writeln!(f, "-------------------------------")?;
            writeln!(f, "          child request")?;
            writeln!(f, "-------------------------------")?;
            writeln!(f, "child:         {}", request.child)?;
            writeln!(f, "entitlements:  {}", request.resources)?;
            for (key, child_req) in &request.requests {
                match child_req {
                    ProvisioningRequest::Issuance(_) => writeln!(f, "key:           {}    (re-)issue", key)?,
                    ProvisioningRequest::Revocation(_) => writeln!(f, "key:           {}    revoke", key)?,
                }
            }
            writeln!(f)?;
        }
        writeln!(f, "NOTE: Use the JSON output for the signer.")?;

        Ok(())
    }
}

//------------ TrustAnchorChildRequests ------------------------------------

/// Requests for Trust Anchor Child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorChildRequests {
    pub child: ChildHandle,
    pub resources: ResourceSet,
    pub requests: HashMap<KeyIdentifier, ProvisioningRequest>,
}

//------------ TrustAnchorSignedResponse -----------------------------------

/// A [`TrustAnchorSignerResponse`] and its signed message as base64 for
/// (re-)validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignedResponse {
    signed: TrustAnchorSignedMessage,
    response: TrustAnchorSignerResponse,
}

impl TrustAnchorSignedResponse {
    pub fn validate(&self, issuer: &IdCertInfo) -> Result<(), Error> {
        let signed_message = self.signed.validate(issuer.public_key())?;

        // Verify that the content of the signed message matches the
        // clear text request as well.
        let signed_bytes = signed_message.content().to_bytes();
        let signed_response: TrustAnchorSignerResponse = serde_json::from_slice(&signed_bytes).map_err(|e| {
            Error::Custom(format!(
                "Cannot deserialize content of signed Trust Anchor response: {}",
                e
            ))
        })?;

        if self.response != signed_response {
            Err(Error::custom(
                "Clear text request content does not match the contained signed message in Trust Anchor response",
            ))
        } else {
            Ok(())
        }
    }

    /// Get content without validation, handle with care
    pub fn content(&self) -> &TrustAnchorSignerResponse {
        &self.response
    }

    pub fn into_content(self) -> TrustAnchorSignerResponse {
        self.response
    }
}

impl fmt::Display for TrustAnchorSignedResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.response)
    }
}

//------------ TrustAnchorSignerResponse -----------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorSignerResponse {
    pub nonce: Nonce, // should match the request (replay protection)
    pub objects: TrustAnchorObjects,
    pub child_responses: HashMap<ChildHandle, HashMap<KeyIdentifier, ProvisioningResponse>>,
}

impl TrustAnchorSignerResponse {
    pub fn sign(
        &self,
        validity_days: i64,
        signing_key: KeyIdentifier,
        signer: &KrillSigner,
    ) -> Result<TrustAnchorSignedResponse, Error> {
        let data = serde_json::to_string_pretty(&self).unwrap();
        let data = Bytes::from(data);

        signer
            .create_ta_signed_message(data, validity_days, &signing_key)
            .map(|msg| TrustAnchorSignedResponse {
                response: self.clone(),
                signed: msg.into(),
            })
            .map_err(Error::signer)
    }
}

impl fmt::Display for TrustAnchorSignerResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-------------------------------")?;
        writeln!(f, "nonce: {}", self.nonce)?;
        writeln!(f, "-------------------------------")?;
        writeln!(f)?;
        writeln!(f, "{}", self.objects)?;
        writeln!(f)?;
        for (child, responses) in &self.child_responses {
            writeln!(f, "-------------------------------")?;
            writeln!(f, "          child response")?;
            writeln!(f, "-------------------------------")?;
            writeln!(f, "child:         {}", child)?;
            for (key, response) in responses.iter() {
                match response {
                    ProvisioningResponse::Error => writeln!(f, "key:           {}    ERROR", key)?,
                    ProvisioningResponse::Issuance(_) => writeln!(f, "key:           {}    issued", key)?,
                    ProvisioningResponse::Revocation(_) => writeln!(f, "key:           {}    revoked", key)?,
                }
            }
        }
        writeln!(f)?;
        writeln!(f, "NOTE: use the json format for the proxy.")?;

        Ok(())
    }
}

//------------ TrustAnchorChild --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustAnchorChild {
    pub handle: ChildHandle,
    pub id: IdCertInfo,
    pub resources: ResourceSet,
    pub used_keys: HashMap<KeyIdentifier, UsedKeyState>,
    pub open_requests: HashMap<KeyIdentifier, ProvisioningRequest>,
    pub open_responses: HashMap<KeyIdentifier, ProvisioningResponse>,
}

impl TrustAnchorChild {
    pub fn new(handle: ChildHandle, id: IdCertInfo, resources: ResourceSet) -> Self {
        TrustAnchorChild {
            handle,
            id,
            resources,
            used_keys: HashMap::new(),
            open_requests: HashMap::new(),
            open_responses: HashMap::new(),
        }
    }
}

//------------ ProvisioningRequest -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProvisioningRequest {
    Issuance(provisioning::IssuanceRequest),
    Revocation(provisioning::RevocationRequest),
}

impl ProvisioningRequest {
    pub fn key_identifier(&self) -> KeyIdentifier {
        match self {
            ProvisioningRequest::Issuance(req) => req.csr().public_key().key_identifier(),
            ProvisioningRequest::Revocation(req) => req.key(),
        }
    }

    pub fn matches_response(&self, response: &ProvisioningResponse) -> bool {
        match self {
            ProvisioningRequest::Issuance(_) => !matches!(response, ProvisioningResponse::Revocation(_)),
            ProvisioningRequest::Revocation(_) => !matches!(response, ProvisioningResponse::Issuance(_)),
        }
    }
}

impl std::fmt::Display for ProvisioningRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProvisioningRequest::Issuance(_) => write!(f, "issue certificate for key: {}", self.key_identifier()),
            ProvisioningRequest::Revocation(_) => write!(f, "revoke certificates for key: {}", self.key_identifier()),
        }
    }
}

//------------ ProvisioningResponse ----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProvisioningResponse {
    Issuance(provisioning::IssuanceResponse),
    Revocation(provisioning::RevocationResponse),
    Error,
}

impl ProvisioningResponse {
    pub fn to_provisioning_message(self, sender: SenderHandle, recipient: RecipientHandle) -> provisioning::Message {
        match self {
            ProvisioningResponse::Issuance(issuance_response) => {
                provisioning::Message::issue_response(sender, recipient, issuance_response)
            }
            ProvisioningResponse::Revocation(revocation_response) => {
                provisioning::Message::revoke_response(sender, recipient, revocation_response)
            }
            ProvisioningResponse::Error => {
                provisioning::Message::not_performed_response(
                    sender,
                    recipient,
                    provisioning::NotPerformedResponse::err_2001(),
                )
                .unwrap() // safe unwrap, this function always returns Ok.
            }
        }
    }
}
