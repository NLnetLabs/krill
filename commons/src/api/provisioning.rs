use api::ca::{ResourceSet, IssuedCert, RcvdCert};
use rpki::x509::Time;
use rpki::cert::{Cert, Overclaim};
use rpki::csr::Csr;
use rpki::uri;
use rpki::resources::{AsResources, Ipv4Resources, Ipv6Resources};
use rpki::crypto::{PublicKey, KeyIdentifier};

pub const DFLT_CLASS: &str = "all";

//------------ ProvisioningRequest -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProvisioningRequest {
    List,
    Request(IssuanceRequest)
}

impl ProvisioningRequest {
    pub fn list() -> Self { ProvisioningRequest::List }
    pub fn request(r: IssuanceRequest) -> Self { ProvisioningRequest::Request(r)}
}


//------------ ProvisioningResponse -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProvisioningResponse {
    List(Entitlements)
}


//------------ Entitlements -------------------------------------------------

/// This structure is what is called the "Resource Class List Response"
/// in section 3.3.2 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Entitlements {
    classes: Vec<EntitlementClass>
}

impl Entitlements {
    pub fn with_default_class(
        issuer: SigningCert,
        resource_set: ResourceSet,
        not_after: Time,
        issued: Vec<IssuedCert>
    ) -> Self {
        let name = DFLT_CLASS.to_string();
        Entitlements { classes: vec![
            EntitlementClass { class_name: name, issuer, resource_set, not_after, issued }
        ]}
    }
    pub fn new(classes: Vec<EntitlementClass>) -> Self {
        Entitlements { classes }
    }

    pub fn classes(&self) -> &Vec<EntitlementClass> { &self.classes }
}


//------------ EntitlementClass ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntitlementClass {
    class_name: String,
    issuer: SigningCert,
    resource_set: ResourceSet,
    not_after: Time,
    issued: Vec<IssuedCert>
}

impl EntitlementClass {
    pub fn new(
        class_name: String,
        issuer: SigningCert,
        resource_set: ResourceSet,
        not_after: Time,
        issued: Vec<IssuedCert>
    ) -> Self {
        EntitlementClass { class_name, issuer, resource_set, not_after, issued }
    }

    fn unwrap(
        self
    ) -> (String, SigningCert, ResourceSet, Time, Vec<IssuedCert>) {
        (
            self.class_name,
            self.issuer,
            self.resource_set,
            self.not_after,
            self.issued
        )
    }

    pub fn class_name(&self) -> &str { &self.class_name }
    pub fn issuer(&self) -> &SigningCert { &self.issuer }
    pub fn resource_set(&self) -> &ResourceSet { &self.resource_set }
    pub fn not_after(&self) -> Time { self.not_after }
    pub fn issued(&self) -> &Vec<IssuedCert> { &self.issued }

    /// Converts this into an IssuanceResponse for the given key. I.e. includes
    /// the issued certificate matching the given public key only. Returns a
    /// None if no match is found.
    pub fn into_issuance_response(self, key: &PublicKey) -> Option<IssuanceResponse> {
        let (class_name, issuer, resource_set, not_after, issued) = self.unwrap();

        issued.into_iter()
            .find(|issued| issued.cert().subject_public_key_info() == key)
            .map(|issued| {
                IssuanceResponse::new(
                    class_name,
                    issuer,
                    resource_set,
                    not_after,
                    issued
                )
            })
    }
}


//------------ SigningCert ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningCert {
    uri: uri::Rsync,
    cert: Cert
}

impl SigningCert {
    pub fn new(uri: uri::Rsync, cert: Cert) -> Self {
        SigningCert { uri, cert }
    }

    pub fn uri(&self) -> &uri::Rsync { &self.uri }
    pub fn cert(&self) -> &Cert { &self.cert }
}


impl PartialEq for SigningCert {
    fn eq(&self, other: &SigningCert) -> bool {
        self.uri == other.uri &&
        self.cert.to_captured().as_slice() == other.cert.to_captured().as_slice()
    }
}

impl Eq for SigningCert {}

impl From<&RcvdCert> for SigningCert {
    fn from(c: &RcvdCert) -> Self {
        SigningCert {
            uri: c.uri().clone(),
            cert: c.cert().clone()
        }
    }
}


//------------ IssuanceRequest -----------------------------------------------

/// This type reflects the content of a Certificate Issuance Request
/// defined in section 3.4.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuanceRequest {
    class_name: String,
    limit: RequestResourceLimit,
    csr: Csr
}

impl IssuanceRequest {
    pub fn new(
        class_name: String,
        limit: RequestResourceLimit,
        csr: Csr
    ) -> Self {
        IssuanceRequest { class_name, limit, csr }
    }

    pub fn unwrap(self) -> (String, RequestResourceLimit, Csr) {
        (self.class_name, self.limit, self.csr)
    }

    pub fn class_name(&self) -> &str { &self.class_name }
    pub fn limit(&self) -> &RequestResourceLimit { &self.limit }
    pub fn csr(&self) -> &Csr { &self.csr }
}

impl PartialEq for IssuanceRequest {
    fn eq(&self, other: &IssuanceRequest) -> bool {
        self.class_name == other.class_name &&
        self.limit == other.limit &&
        self.csr.to_captured().as_slice() == other.csr.to_captured().as_slice()
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
    class_name: String,
    issuer: SigningCert,
    resource_set: ResourceSet, // resources allowed on a cert
    not_after: Time,
    issued: IssuedCert
}

impl IssuanceResponse {
    pub fn new(
        class_name: String,
        issuer: SigningCert,
        resource_set: ResourceSet, // resources allowed on a cert
        not_after: Time,
        issued: IssuedCert
    ) -> Self {
        IssuanceResponse { class_name, issuer, resource_set, not_after, issued }
    }

    pub fn unwrap(self) -> (String, SigningCert, ResourceSet, IssuedCert) {
        (self.class_name, self.issuer, self.resource_set, self.issued)
    }

    pub fn class_name(&self) -> &str { &self.class_name }
    pub fn issuer(&self) -> &SigningCert { &self.issuer }
    pub fn resource_set(&self) -> &ResourceSet { &self.resource_set }
    pub fn not_after(&self) -> Time { self.not_after }
    pub fn issued(&self) -> &IssuedCert { &self.issued }
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
    asn: Option<AsResources>,
    v4: Option<Ipv4Resources>,
    v6: Option<Ipv6Resources>
}

impl RequestResourceLimit {
    pub fn new() -> RequestResourceLimit { Self::default() }

    pub fn is_empty(&self) -> bool {
        self.asn == None && self.v4 == None && self.v6 == None
    }

    pub fn with_asn(&mut self, asn: AsResources) {
        self.asn = Some(asn);
    }

    pub fn with_ipv4(&mut self, ipv4: Ipv4Resources) {
        self.v4 = Some(ipv4);
    }

    pub fn with_ipv6(&mut self, ipv6: Ipv6Resources) {
        self.v6 = Some(ipv6);
    }

    pub fn asn(&self) -> Option<&AsResources> { self.asn.as_ref() }
    pub fn v4(&self) -> Option<&Ipv4Resources> { self.v4.as_ref() }
    pub fn v6(&self) -> Option<&Ipv6Resources> { self.v6.as_ref() }

    /// Give back a ResourceSet based on the input set as limited by this.
    /// Note, if the limit exceeds the input set for any resource type
    /// [`None`] is returned instead.
    pub fn resolve(&self, set: &ResourceSet) -> Option<ResourceSet> {
        let asn = match &self.asn {
            None => set.asn().clone(),
            Some(asn) => {
                match set.asn().as_blocks() {
                    None => {
                        // Asking for a specific sub-set of inherited
                        // resources. This is unverifiable. As Krill
                        // will never use the "inherit" type on CA certificates
                        // it is safe to just return a None here.
                        return None
                    },
                    Some(parent_asn) => {
                        if parent_asn.validate_issued(
                            Some(asn),
                            Overclaim::Refuse
                        ).is_err() {
                            return None // Child is overclaiming
                        }
                        asn.clone() // Child gets what they ask for
                    }
                }
            }
        };

        let v4 = match &self.v4 {
            None => set.v4().clone(),
            Some(v4) => {
                match set.v4().as_blocks() {
                    None => {
                        // Asking for a specific sub-set of inherited
                        // resources. This is unverifiable. As Krill
                        // will never use the "inherit" type on CA certificates
                        // it is safe to just return a None here.
                        return None
                    },
                    Some(parent_v4) => {
                        if parent_v4.validate_issued(
                            Some(v4),
                            Overclaim::Refuse
                        ).is_err() {
                            return None // Child is overclaiming
                        }
                        v4.clone() // Child gets what they ask for
                    }
                }
            }
        };

        let v6 = match &self.v6 {
            None => set.v6().clone(),
            Some(v6) => {
                match set.v6().as_blocks() {
                    None => {
                        // Asking for a specific sub-set of inherited
                        // resources. This is unverifiable. As Krill
                        // will never use the "inherit" type on CA certificates
                        // it is safe to just return a None here.
                        return None
                    },
                    Some(parent_v6) => {
                        if parent_v6.validate_issued(
                            Some(v6),
                            Overclaim::Refuse
                        ).is_err() {
                            return None // Child is overclaiming
                        }
                        v6.clone() // Child gets what they ask for
                    }
                }
            }
        };

        Some(ResourceSet::new(asn, v4, v6))
    }
}

impl Default for RequestResourceLimit {
    fn default() -> Self {
        RequestResourceLimit {
            asn: None,
            v4: None,
            v6: None
        }
    }
}


//------------ RevocationRequest ---------------------------------------------

/// This type represents a Certificate Revocation Request as
/// defined in section 3.5.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevocationRequest {
    class_name: String,
    key: KeyIdentifier
}

impl RevocationRequest {
    pub fn new(class_name: String, key: KeyIdentifier) -> Self {
        RevocationRequest { class_name, key}
    }

    pub fn class_name(&self) -> &str { &self.class_name }
    pub fn key(&self) -> &KeyIdentifier { &self.key }
}


