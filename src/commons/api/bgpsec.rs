use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::{
    ca::{csr::BgpsecCsr, publication::Base64},
    crypto::KeyIdentifier,
    repository::resources::Asn,
};

use super::ObjectName;

//------------ BgpSecDefinition --------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BgpSecDefinition {
    asn: Asn,
    csr: BgpsecCsr,
}

impl BgpSecDefinition {
    pub fn new(asn: Asn, csr: BgpsecCsr) -> Self {
        BgpSecDefinition { asn, csr }
    }

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn csr(&self) -> &BgpsecCsr {
        &self.csr
    }
}

impl PartialEq for BgpSecDefinition {
    fn eq(&self, other: &Self) -> bool {
        self.asn == other.asn
            && self.csr.to_captured().as_slice()
                == other.csr.to_captured().as_slice()
    }
}

impl Eq for BgpSecDefinition {}

//------------ BgpSecAsnKey ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
        // We use a format similar to the recommendation for the router
        // certificate subject from section 3.1.1 in RFC 8209.
        write!(f, "ROUTER-{:08X}-{}", self.asn.into_u32(), self.key)
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

impl FromStr for BgpSecAsnKey {
    type Err = BgpSecAsnKeyFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("ROUTER-").ok_or(BgpSecAsnKeyFmtError)?;

        let parts: Vec<_> = s.split('-').collect();

        if parts.len() != 2 {
            return Err(BgpSecAsnKeyFmtError);
        }

        let asn_hex = parts.first().ok_or(BgpSecAsnKeyFmtError)?;
        let key_id_str = parts.get(1).ok_or(BgpSecAsnKeyFmtError)?;

        let asn_nr = u32::from_str_radix(asn_hex, 16)
            .map_err(|_| BgpSecAsnKeyFmtError)?;
        let asn = Asn::from_u32(asn_nr);

        let key = KeyIdentifier::from_str(key_id_str)
            .map_err(|_| BgpSecAsnKeyFmtError)?;

        Ok(BgpSecAsnKey { asn, key })
    }
}

#[derive(Clone, Debug)]
pub struct BgpSecAsnKeyFmtError;

impl std::error::Error for BgpSecAsnKeyFmtError {}

impl fmt::Display for BgpSecAsnKeyFmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid BGPSec ASN and Key format. Expected: ROUTER-<hex-encoded-asn>-<hex-encoded-key-identifier>"
        )
    }
}

/// We use BgpSecAsnKey as (JSON) map keys and therefore we need it
/// to be serializable to a single simple string.
impl Serialize for BgpSecAsnKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

/// We use BgpSecAsnKey as (JSON) map keys and therefore we need it
/// to be deserializable from a single simple string.
impl<'de> Deserialize<'de> for BgpSecAsnKey {
    fn deserialize<D>(d: D) -> Result<BgpSecAsnKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        BgpSecAsnKey::from_str(string.as_str()).map_err(de::Error::custom)
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
    pub fn new(
        add: Vec<BgpSecDefinition>,
        remove: Vec<BgpSecAsnKey>,
    ) -> Self {
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

    pub fn asn(&self) -> Asn {
        self.asn
    }

    pub fn key_identifier(&self) -> KeyIdentifier {
        self.key_identifier
    }

    pub fn csr(&self) -> &Base64 {
        &self.csr
    }

    pub fn object_name(&self) -> ObjectName {
        ObjectName::bgpsec(self.asn, self.key_identifier)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCsrInfoList(Vec<BgpSecCsrInfo>);

impl BgpSecCsrInfoList {
    pub fn new(list: Vec<BgpSecCsrInfo>) -> Self {
        BgpSecCsrInfoList(list)
    }

    pub fn unpack(self) -> Vec<BgpSecCsrInfo> {
        self.0
    }
}

impl fmt::Display for BgpSecCsrInfoList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ASN, key identifier, CSR base64")?;
        for info in self.0.iter() {
            writeln!(
                f,
                "{}, {}, {}",
                info.asn, info.key_identifier, info.csr
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::BgpSecAsnKey;

    #[test]
    fn bgp_sec_to_from_str() {
        let string =
            "ROUTER-0000FDE8-17316903F0671229E8808BA8E8AB0105FA915A07";
        let key = BgpSecAsnKey::from_str(string).unwrap();
        let to_string = key.to_string();
        assert_eq!(string, &to_string);
    }
}
