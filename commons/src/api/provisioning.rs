use api::ca::{ResourceSet, IssuedCert};
use rpki::x509::Time;
use rpki::cert::Cert;
use rpki::csr::Csr;
use rpki::uri;

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
        signing_cert: SigningCert,
        resource_set: ResourceSet,
        until: Time,
        issued: Vec<IssuedCert>
    ) -> Self {
        let name = DFLT_CLASS.to_string();
        Entitlements { classes: vec![
            EntitlementClass { name, signing_cert, resource_set, until, issued }
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
    name: String,
    signing_cert: SigningCert,
    resource_set: ResourceSet,
    until: Time,
    issued: Vec<IssuedCert>
}

impl EntitlementClass {
    pub fn new(
        name: String,
        signer: SigningCert,
        resource_set: ResourceSet,
        until: Time,
        issued: Vec<IssuedCert>
    ) -> Self {
        EntitlementClass { name, signing_cert: signer, resource_set, until, issued }
    }

    pub fn name(&self) -> &str { &self.name }
    pub fn signer(&self) -> &SigningCert { &self.signing_cert }
    pub fn resource_set(&self) -> &ResourceSet { &self.resource_set }
    pub fn until(&self) -> Time { self.until }
    pub fn issued(&self) -> &Vec<IssuedCert> { &self.issued }
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


//------------ IssuanceRequest -----------------------------------------------

/// This type reflects the content of a Certificate Issuance Request
/// defined in section 3.4.1 of RFC6492.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssuanceRequest {
    class_name: String,
    limit: Option<ResourceSet>,
    csr: Csr
}

impl IssuanceRequest {
    pub fn new(
        class_name: String,
        limit: Option<ResourceSet>,
        csr: Csr
    ) -> Self {
        IssuanceRequest { class_name, limit, csr }
    }

    pub fn unwrap(self) -> (String, Option<ResourceSet>, Csr) {
        (self.class_name, self.limit, self.csr)
    }

    pub fn class_name(&self) -> &str {
        &self.class_name
    }
}

impl PartialEq for IssuanceRequest {
    fn eq(&self, other: &IssuanceRequest) -> bool {
        self.class_name == other.class_name &&
        self.limit == other.limit &&
        self.csr.to_captured().as_slice() == other.csr.to_captured().as_slice()
    }
}

impl Eq for IssuanceRequest {}
