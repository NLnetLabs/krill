//! BGPsec router keys.

use std::fmt;
use std::str::FromStr;

use rpki::ca::csr::BgpsecCsr;
use rpki::ca::publication::Base64;
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::Asn;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use super::ca::ObjectName;


//------------ BgpSecDefinition --------------------------------------------

/// Information for creating a BGPsec router key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BgpSecDefinition {
    /// The autonomous system that uses the router key.
    pub asn: Asn,

    /// The certificate signing request for the router key.
    pub csr: BgpsecCsr,
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

/// A BGPsec router key for a specific ASN.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BgpSecAsnKey {
    /// The autonomous system that uses the router key.
    pub asn: Asn,

    /// The key identifier of the router key.
    pub key: KeyIdentifier,
}

impl From<&BgpSecDefinition> for BgpSecAsnKey {
    fn from(def: &BgpSecDefinition) -> Self {
        BgpSecAsnKey {
            asn: def.asn,
            key: def.csr.public_key().key_identifier(),
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

impl fmt::Display for BgpSecAsnKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // We use a format similar to the recommendation for the router
        // certificate subject from section 3.1.1 in RFC 8209.
        write!(f, "ROUTER-{:08X}-{}", self.asn.into_u32(), self.key)
    }
}

impl Serialize for BgpSecAsnKey {
    /// Serialize this value into the given Serde serializer.
    ///
    /// We use BgpSecAsnKey as (JSON) map keys and therefore we need it
    /// to be serializable to a single simple string.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(s)
    }
}

impl<'de> Deserialize<'de> for BgpSecAsnKey {
    /// Deserialize this value from the given Serde deserializer.
    ///
    /// We use BgpSecAsnKey as (JSON) map keys and therefore we need it
    /// to be deserializable from a single simple string.
    fn deserialize<D: Deserializer<'de>>(
        d: D
    ) -> Result<BgpSecAsnKey, D::Error> {
        BgpSecAsnKey::from_str(
            String::deserialize(d)?.as_str()
        ).map_err(de::Error::custom)
    }
}


//------------ BgpSecDefinitionUpdates ---------------------------------------

/// Information for updating multiple router key definitions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecDefinitionUpdates {
    /// The router key definitions to add.
    pub add: Vec<BgpSecDefinition>,

    /// The router keys to remove.
    pub remove: Vec<BgpSecAsnKey>,
}


//------------ BgpSecCsrInfo -------------------------------------------------

/// All information for a BGPsec router key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCsrInfo {
    /// The autonomous system that uses the router key.
    pub asn: Asn,

    /// The key identifier of the router key.
    pub key_identifier: KeyIdentifier,

    /// The certificate signing request for the router key.
    pub csr: Base64,
}

impl BgpSecCsrInfo {
    /// Returns the object name for the router key.
    pub fn object_name(&self) -> ObjectName {
        ObjectName::bgpsec(self.asn, self.key_identifier)
    }
}


//------------ BgpSecCsrInfoList ---------------------------------------------

/// A list with information for multiple BGPsec router keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpSecCsrInfoList(Vec<BgpSecCsrInfo>);

impl BgpSecCsrInfoList {
    pub fn new(list: Vec<BgpSecCsrInfo>) -> Self {
        BgpSecCsrInfoList(list)
    }

    pub fn as_slice(&self) -> &[BgpSecCsrInfo] {
        self.0.as_slice()
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


//============ Error Types ===================================================

//------------ BgpSecAsnKeyFmtError ------------------------------------------

/// An error happened while parsing an BGPsec router key definition.
#[derive(Clone, Debug)]
pub struct BgpSecAsnKeyFmtError;

impl std::error::Error for BgpSecAsnKeyFmtError {}

impl fmt::Display for BgpSecAsnKeyFmtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid BGPSec ASN and Key format. \
             Expected: ROUTER-<hex-encoded-asn>-<hex-encoded-key-identifier>"
        )
    }
}


//============ Tests =========================================================

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
