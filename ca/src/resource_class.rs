use krill_commons::util::softsigner::SignerKeyId;

use std::str::FromStr;
use rpki::resources::{AsResources, Ipv4Resources, Ipv6Resources};
use crate::Cert;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResourceClass {
    resources: ResourceSet,
    current_key: ActiveKey
}

impl ResourceClass {
    pub fn new(resources: ResourceSet, key: SignerKeyId, cert: Cert) -> Self {
        let current_key = ActiveKey { key, cert};
        ResourceClass { resources, current_key }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ActiveKey {
    key: SignerKeyId,
    cert: Cert
}

/// This type defines a set of Internet Number Resources.
///
/// This type supports conversions to and from string representations,
/// and is (de)serializable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSet {
    asn: AsResources,
    v4: Ipv4Resources,
    v6: Ipv6Resources
}

impl ResourceSet {
    pub fn from_strs(asns: &str, ipv4: &str, ipv6: &str) -> Result<Self, Error> {
        let asn = AsResources::from_str(asns).map_err(|_| Error::AsnParsing)?;
        let v4 = Ipv4Resources::from_str(ipv4).map_err(|_| Error::Ipv4Parsing)?;
        let v6 = Ipv6Resources::from_str(ipv6).map_err(|_| Error::Ipv6Parsing)?;
        Ok(ResourceSet { asn , v4, v6 })
    }

    pub fn asn(&self) -> &AsResources {
        &self.asn
    }

    pub fn v4(&self) -> &Ipv4Resources {
        &self.v4
    }

    pub fn v6(&self) -> &Ipv6Resources {
        &self.v6
    }
}


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum Error {
    #[display(fmt="Cannot parse ASN resources")]
    AsnParsing,

    #[display(fmt="Cannot parse IPv4 resources")]
    Ipv4Parsing,

    #[display(fmt="Cannot parse IPv6 resources")]
    Ipv6Parsing,

    #[display(fmt="Mixed Address Families in configured resource set")]
    MixedFamilies,
}



//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_deserialize_asn_blocks() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "";
        let ipv6s = "";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }


    #[test]
    fn serialize_deserialize_resource_set() {
        let asns = "inherit";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let json = serde_json::to_string(&set).unwrap();
        let deser_set = serde_json::from_str(&json).unwrap();

        assert_eq!(set, deser_set);
    }




}