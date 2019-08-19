use rpki::cert::Cert;
use rpki::crypto::{KeyIdentifier, PublicKey};
use rpki::csr::Csr;
use rpki::resources::{AsBlocks, IpBlocks};
use rpki::uri;
use rpki::x509::Time;

use crate::api::ca::{IssuedCert, RcvdCert, ResourceClassName, ResourceSet};
use crate::util::ext_serde;

//------------ ProvisioningRequest -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProvisioningRequest {
    List,
    Request(IssuanceRequest),
}

impl ProvisioningRequest {
    pub fn list() -> Self {
        ProvisioningRequest::List
    }
    pub fn request(r: IssuanceRequest) -> Self {
        ProvisioningRequest::Request(r)
    }
}

//------------ ProvisioningResponse -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProvisioningResponse {
    List(Entitlements),
}

//------------ Entitlements -------------------------------------------------

/// This structure is what is called the "Resource Class List Response"
/// in section 3.3.2 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Entitlements {
    classes: Vec<EntitlementClass>,
}

impl Entitlements {
    pub fn with_default_class(
        issuer: SigningCert,
        resource_set: ResourceSet,
        not_after: Time,
        issued: Vec<IssuedCert>,
    ) -> Self {
        Entitlements {
            classes: vec![EntitlementClass {
                class_name: ResourceClassName::default(),
                issuer,
                resource_set,
                not_after,
                issued,
            }],
        }
    }
    pub fn new(classes: Vec<EntitlementClass>) -> Self {
        Entitlements { classes }
    }

    pub fn classes(&self) -> &Vec<EntitlementClass> {
        &self.classes
    }
}

//------------ EntitlementClass ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntitlementClass {
    class_name: ResourceClassName,
    issuer: SigningCert,
    resource_set: ResourceSet,
    not_after: Time,
    issued: Vec<IssuedCert>,
}

impl EntitlementClass {
    pub fn new(
        class_name: ResourceClassName,
        issuer: SigningCert,
        resource_set: ResourceSet,
        not_after: Time,
        issued: Vec<IssuedCert>,
    ) -> Self {
        EntitlementClass {
            class_name,
            issuer,
            resource_set,
            not_after,
            issued,
        }
    }

    fn unwrap(
        self,
    ) -> (
        ResourceClassName,
        SigningCert,
        ResourceSet,
        Time,
        Vec<IssuedCert>,
    ) {
        (
            self.class_name,
            self.issuer,
            self.resource_set,
            self.not_after,
            self.issued,
        )
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }

    pub fn issuer(&self) -> &SigningCert {
        &self.issuer
    }

    pub fn resource_set(&self) -> &ResourceSet {
        &self.resource_set
    }

    pub fn not_after(&self) -> Time {
        self.not_after
    }

    pub fn issued(&self) -> &Vec<IssuedCert> {
        &self.issued
    }

    /// Converts this into an IssuanceResponse for the given key. I.e. includes
    /// the issued certificate matching the given public key only. Returns a
    /// None if no match is found.
    pub fn into_issuance_response(self, key: &PublicKey) -> Option<IssuanceResponse> {
        let (class_name, issuer, resource_set, not_after, issued) = self.unwrap();

        issued
            .into_iter()
            .find(|issued| issued.cert().subject_public_key_info() == key)
            .map(|issued| {
                IssuanceResponse::new(class_name, issuer, resource_set, not_after, issued)
            })
    }
}

//------------ SigningCert ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningCert {
    uri: uri::Rsync,
    cert: Cert,
}

impl SigningCert {
    pub fn new(uri: uri::Rsync, cert: Cert) -> Self {
        SigningCert { uri, cert }
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }
    pub fn cert(&self) -> &Cert {
        &self.cert
    }
}

impl PartialEq for SigningCert {
    fn eq(&self, other: &SigningCert) -> bool {
        self.uri == other.uri
            && self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for SigningCert {}

impl From<&RcvdCert> for SigningCert {
    fn from(c: &RcvdCert) -> Self {
        SigningCert {
            uri: c.uri().clone(),
            cert: c.cert().clone(),
        }
    }
}

//------------ IssuanceRequest -----------------------------------------------

/// This type reflects the content of a Certificate Issuance Request
/// defined in section 3.4.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuanceRequest {
    class_name: ResourceClassName,
    limit: RequestResourceLimit,
    csr: Csr,
}

impl IssuanceRequest {
    pub fn new(class_name: ResourceClassName, limit: RequestResourceLimit, csr: Csr) -> Self {
        IssuanceRequest {
            class_name,
            limit,
            csr,
        }
    }

    pub fn unwrap(self) -> (ResourceClassName, RequestResourceLimit, Csr) {
        (self.class_name, self.limit, self.csr)
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }
    pub fn limit(&self) -> &RequestResourceLimit {
        &self.limit
    }
    pub fn csr(&self) -> &Csr {
        &self.csr
    }
}

impl PartialEq for IssuanceRequest {
    fn eq(&self, other: &IssuanceRequest) -> bool {
        self.class_name == other.class_name
            && self.limit == other.limit
            && self.csr.to_captured().as_slice() == other.csr.to_captured().as_slice()
    }
}

impl Eq for IssuanceRequest {}

//------------ IssuanceResponse ----------------------------------------------

/// A Certificate Issuance Response equivalent to the one defined in
/// section 3.4.2 of RFC6492.
///
/// Note that this is like a single EntitlementClass response, except that
/// it includes the one certificate which has just been issued only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuanceResponse {
    class_name: ResourceClassName,
    issuer: SigningCert,
    resource_set: ResourceSet, // resources allowed on a cert
    not_after: Time,
    issued: IssuedCert,
}

impl IssuanceResponse {
    pub fn new(
        class_name: ResourceClassName,
        issuer: SigningCert,
        resource_set: ResourceSet, // resources allowed on a cert
        not_after: Time,
        issued: IssuedCert,
    ) -> Self {
        IssuanceResponse {
            class_name,
            issuer,
            resource_set,
            not_after,
            issued,
        }
    }

    pub fn unwrap(self) -> (ResourceClassName, SigningCert, ResourceSet, IssuedCert) {
        (self.class_name, self.issuer, self.resource_set, self.issued)
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }

    pub fn issuer(&self) -> &SigningCert {
        &self.issuer
    }

    pub fn resource_set(&self) -> &ResourceSet {
        &self.resource_set
    }

    pub fn not_after(&self) -> Time {
        self.not_after
    }

    pub fn issued(&self) -> &IssuedCert {
        &self.issued
    }
}

//------------ RequestResourceLimit ------------------------------------------

/// The scope of resources that a child CA wants to have certified. By default
/// there are no limits, i.e. all the child wants all resources the parent is
/// willing to give. Only if some values are specified for certain resource
/// types will the scope be limited for that type only. Note that asking for
/// more than you are entitled to as a child, will anger a parent. In this case
/// the IssuanceRequest will be rejected.
///
/// See: https://tools.ietf.org/html/rfc6492#section-3.4.1
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestResourceLimit {
    asn: Option<AsBlocks>,

    #[serde(
        deserialize_with = "ext_serde::de_ip_blocks_4_opt",
        serialize_with = "ext_serde::ser_ip_blocks_4_opt"
    )]
    v4: Option<IpBlocks>,

    #[serde(
        deserialize_with = "ext_serde::de_ip_blocks_6_opt",
        serialize_with = "ext_serde::ser_ip_blocks_6_opt"
    )]
    v6: Option<IpBlocks>,
}

impl RequestResourceLimit {
    pub fn new() -> RequestResourceLimit {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.asn == None && self.v4 == None && self.v6 == None
    }

    pub fn with_asn(&mut self, asn: AsBlocks) {
        self.asn = Some(asn);
    }

    pub fn with_ipv4(&mut self, ipv4: IpBlocks) {
        self.v4 = Some(ipv4);
    }

    pub fn with_ipv6(&mut self, ipv6: IpBlocks) {
        self.v6 = Some(ipv6);
    }

    pub fn asn(&self) -> Option<&AsBlocks> {
        self.asn.as_ref()
    }

    pub fn v4(&self) -> Option<&IpBlocks> {
        self.v4.as_ref()
    }

    pub fn v6(&self) -> Option<&IpBlocks> {
        self.v6.as_ref()
    }
}

impl Default for RequestResourceLimit {
    fn default() -> Self {
        RequestResourceLimit {
            asn: None,
            v4: None,
            v6: None,
        }
    }
}

//------------ RevocationRequest ---------------------------------------------

/// This type represents a Certificate Revocation Request as
/// defined in section 3.5.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationRequest {
    class_name: ResourceClassName,
    key: KeyIdentifier,
}

impl RevocationRequest {
    pub fn new(class_name: ResourceClassName, key: KeyIdentifier) -> Self {
        RevocationRequest { class_name, key }
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }
    pub fn key(&self) -> &KeyIdentifier {
        &self.key
    }
}

//------------ RevocationResponse --------------------------------------------

/// This type represents a Certificate Revocation Response as
/// defined in section 3.5.2 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationResponse {
    class_name: ResourceClassName,
    key: KeyIdentifier,
}

impl RevocationResponse {
    pub fn new(class_name: ResourceClassName, key: KeyIdentifier) -> Self {
        RevocationResponse { class_name, key }
    }

    pub fn unpack(self) -> (ResourceClassName, KeyIdentifier) {
        (self.class_name, self.key)
    }

    pub fn class_name(&self) -> &ResourceClassName {
        &self.class_name
    }
    pub fn key(&self) -> &KeyIdentifier {
        &self.key
    }
}

impl From<&RevocationRequest> for RevocationResponse {
    fn from(req: &RevocationRequest) -> Self {
        RevocationResponse {
            class_name: req.class_name.clone(),
            key: req.key,
        }
    }
}

impl From<RevocationRequest> for RevocationResponse {
    fn from(req: RevocationRequest) -> Self {
        RevocationResponse {
            class_name: req.class_name,
            key: req.key,
        }
    }
}
