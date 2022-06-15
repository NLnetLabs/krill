use std::fmt;

use rpki::{
    ca::{csr::BgpsecCsr, publication::Base64},
    crypto::KeyIdentifier,
    repository::resources::Asn,
};

//------------ BgpSecDefinition --------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BgpSecDefinition {
    asn: Asn,
    csr: BgpsecCsr,
}

impl BgpSecDefinition {
    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn csr(&self) -> &BgpsecCsr {
        &self.csr
    }
}

impl PartialEq for BgpSecDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.asn == other.asn && self.csr.to_captured().as_slice() == other.csr.to_captured().as_slice()
    }
}

impl Eq for BgpSecDefinition {}

//------------ BgpSecAsnKey ------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BgpSecAsnKey {
    asn: Asn,
    key: KeyIdentifier,
}

impl BgpSecAsnKey {
    pub fn new(asn: Asn, key: KeyIdentifier) -> Self {
        BgpSecAsnKey { asn, key }
    }

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn key_identifier(&self) -> KeyIdentifier {
        self.key
    }
}

impl fmt::Display for BgpSecAsnKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ROUTER-{:x}-{}", self.asn.into_u32(), self.key)
    }
}

impl From<&BgpSecDefinition> for BgpSecAsnKey {
    fn from(def: &BgpSecDefinition) -> Self {
        BgpSecAsnKey {
            asn: def.asn(),
            key: def.csr().public_key().key_identifier(),
        }
    }
}

//------------ BgpSecDefinitionUpdates -------------------------------------

/// Contains BGPSec definition updates sent to the API.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecDefinitionUpdates {
    add: Vec<BgpSecDefinition>,
    remove: Vec<BgpSecAsnKey>,
}

impl BgpSecDefinitionUpdates {
    pub fn new(add: Vec<BgpSecDefinition>, remove: Vec<BgpSecAsnKey>) -> Self {
        BgpSecDefinitionUpdates { add, remove }
    }

    pub fn unpack(self) -> (Vec<BgpSecDefinition>, Vec<BgpSecAsnKey>) {
        (self.add, self.remove)
    }
}

/// This type is shown through the API
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCsrInfo {
    asn: Asn,
    key_identifier: KeyIdentifier,
    csr: Base64,
}

impl BgpSecCsrInfo {
    pub fn new(asn: Asn, key_identifier: KeyIdentifier, csr: Base64) -> Self {
        BgpSecCsrInfo {
            asn,
            key_identifier,
            csr,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCsrInfoList(Vec<BgpSecCsrInfo>);

impl BgpSecCsrInfoList {
    pub fn new(list: Vec<BgpSecCsrInfo>) -> Self {
        BgpSecCsrInfoList(list)
    }
}
