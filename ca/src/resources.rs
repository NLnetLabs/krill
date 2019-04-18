//! Resources used by Certificate Authorities

use rpki::resources::{
    AsBlocks,
    IpBlocks,
    ResourcesChoice,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;
use std::str::FromStr;

const INHERIT: &str = "inherit";

/// Defines a Set of Asns
//
// This is a wrapper around ResourceChoice<AsBlocks> so that
// we can have additional functionality for CAs, such as the
// ability to (de)serialize so CA state can be persisted.
#[derive(Clone, Debug)]
struct AsnSet(ResourcesChoice<AsBlocks>);

impl PartialEq for AsnSet {
    fn eq(&self, other: &AsnSet) -> bool {
        match &self.0 {
            ResourcesChoice::Inherit => {
                match &other.0 {
                    ResourcesChoice::Inherit => true,
                    ResourcesChoice::Blocks(_) => false,
                }
            },
            ResourcesChoice::Blocks(blocks) => {
                match &other.0 {
                    ResourcesChoice::Inherit => false,
                    ResourcesChoice::Blocks(other_blocks) => {
                        let mut iter_other = other_blocks.iter();

                        for bl in blocks.iter() {
                            if let Some(other_block) = iter_other.next() {
                                if bl.min() != other_block.min() || bl.max() != other_block.max() {
                                    return false
                                }
                            } else {
                                return false
                            }
                        }
                        true
                    }
                }
            }
        }
    }
}

impl Eq for AsnSet {}

impl Serialize for AsnSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        match &self.0 {
            ResourcesChoice::Inherit => INHERIT.serialize(serializer),
            ResourcesChoice::Blocks(asn) => asn.to_string().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for AsnSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let string = String::deserialize(deserializer)?;
        Ok(AsnSet::from_str(&string).map_err(de::Error::custom)?)
    }
}

impl FromStr for AsnSet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == INHERIT {
            Ok(AsnSet(ResourcesChoice::Inherit))
        } else {
            let blocks = AsBlocks::from_str(s).map_err(|_| Error::AsnParsing)?;
            Ok(AsnSet(ResourcesChoice::Blocks(blocks)))
        }
    }
}

fn ip_blocks_equal(left: &ResourcesChoice<IpBlocks>, right: &ResourcesChoice<IpBlocks>) -> bool {
    match left {
        ResourcesChoice::Inherit => {
            match right {
                ResourcesChoice::Inherit => true,
                ResourcesChoice::Blocks(_) => false
            }
        },
        ResourcesChoice::Blocks(left_blocks) => {
            match right {
                ResourcesChoice::Inherit => false,
                ResourcesChoice::Blocks(right_blocks) => {
                    let mut right_iter = right_blocks.iter();
                    for left in left_blocks.iter() {
                        if let Some(right) = right_iter.next() {
                            if left.min() != right.min() ||left.max() != right.max() {
                                return false
                            }
                        } else {
                            return false
                        }
                    }
                    true
                }
            }
        }
    }
}

/// Defines a Set of IPv4 Blocks
//
// This is a wrapper around ResourceChoice<IpBlocks> so that
// we can have additional functionality for CAs, such as the
// ability to (de)serialize so CA state can be persisted.
//
// Furthemore this ensures that the contained IpBlocks are all
// IPv4
#[derive(Clone, Debug)]
struct Ipv4Set(ResourcesChoice<IpBlocks>);

impl Serialize for Ipv4Set {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        match &self.0 {
            ResourcesChoice::Inherit => INHERIT.serialize(serializer),
            ResourcesChoice::Blocks(ips) => ips.as_v4().to_string().serialize(serializer)
        }
    }
}

impl PartialEq for Ipv4Set {
    fn eq(&self, other: &Ipv4Set) -> bool {
        ip_blocks_equal(&self.0, &other.0)
    }
}

impl Eq for Ipv4Set {}

impl<'de> Deserialize<'de> for Ipv4Set {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let string = String::deserialize(deserializer)?;
        Ok(Ipv4Set::from_str(&string).map_err(de::Error::custom)?)
    }
}

impl FromStr for Ipv4Set {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == INHERIT {
            Ok(Ipv4Set(ResourcesChoice::Inherit))
        } else if s.contains(':') {
            Err(Error::MixedFamilies)
        } else {
            let blocks = IpBlocks::from_str(s).map_err(|_| Error::Ipv4Parsing)?;
            Ok(Ipv4Set(ResourcesChoice::Blocks(blocks)))
        }
    }
}


/// Defines a Set of IPv6 Blocks
//
// This is a wrapper around ResourceChoice<IpBlocks> so that
// we can have additional functionality for CAs, such as the
// ability to (de)serialize so CA state can be persisted.
//
// Furthemore this ensures that the contained IpBlocks are all
// IPv6
#[derive(Clone, Debug)]
struct Ipv6Set(ResourcesChoice<IpBlocks>);

impl Serialize for Ipv6Set {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        match &self.0 {
            ResourcesChoice::Inherit => INHERIT.serialize(serializer),
            ResourcesChoice::Blocks(ips) => ips.as_v6().to_string().serialize(serializer)
        }
    }
}

impl PartialEq for Ipv6Set {
    fn eq(&self, other: &Ipv6Set) -> bool {
        ip_blocks_equal(&self.0, &other.0)
    }
}

impl Eq for Ipv6Set {}

impl<'de> Deserialize<'de> for Ipv6Set {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let string = String::deserialize(deserializer)?;
        Ok(Ipv6Set::from_str(&string).map_err(de::Error::custom)?)
    }
}

impl FromStr for Ipv6Set {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == INHERIT {
            Ok(Ipv6Set(ResourcesChoice::Inherit))
        } else if s.contains('.') {
            Err(Error::MixedFamilies)
        } else {
            let blocks = IpBlocks::from_str(s).map_err(|_| Error::Ipv6Parsing)?;
            Ok(Ipv6Set(ResourcesChoice::Blocks(blocks)))
        }
    }
}

/// This type defines a set of Internet Number Resources.
///
/// This type supports conversions to and from string representations,
/// and is (de)serializable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceSet {
    asn: AsnSet,
    v4: Ipv4Set,
    v6: Ipv6Set
}

impl ResourceSet {
    pub fn from_strs(asns: &str, ipv4: &str, ipv6: &str) -> Result<Self, Error> {
        let asn = AsnSet::from_str(asns)?;
        let v4 = Ipv4Set::from_str(ipv4)?;
        let v6 = Ipv6Set::from_str(ipv6)?;
        Ok(ResourceSet { asn , v4, v6 })
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
    fn resource_set_from_strs() {
        let asns = "inherit";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";

        let _set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();
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