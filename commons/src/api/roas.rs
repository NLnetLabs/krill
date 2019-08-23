use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use api::ca::ResourceSet;
use rpki::resources::{AddressFamily, AsBlocks, AsId, IpBlocks, IpBlocksBuilder, Prefix};
use std::net::IpAddr;

//------------ RouteAuthorizationUpdates -----------------------------------

/// This type defines a delta of Route Authorizations, i.e. additions or removals
/// of authorizations of tuples of (Prefix, Max Length, ASN) that ultimately
/// are put into ROAs by a CA, in as far as the CA has the required prefixes
/// on its resource certificates.
///
/// Multiple updates are sent as a single delta, because it's important that
/// all authorisations for a given prefix are published together in order to
/// avoid invalidating announcements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteAuthorizationUpdates {
    added: HashSet<RouteAuthorization>,
    removed: HashSet<RouteAuthorization>,
}

impl RouteAuthorizationUpdates {
    pub fn new(added: HashSet<RouteAuthorization>, removed: HashSet<RouteAuthorization>) -> Self {
        RouteAuthorizationUpdates { added, removed }
    }

    /// Unpack this and return all added (left), and all removed (right) route
    /// authorizations.
    pub fn unpack(self) -> (HashSet<RouteAuthorization>, HashSet<RouteAuthorization>) {
        (self.added, self.removed)
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn add(&mut self, add: RouteAuthorization) {
        self.added.insert(add);
    }

    pub fn remove(&mut self, rem: RouteAuthorization) {
        self.removed.insert(rem);
    }
}

impl Default for RouteAuthorizationUpdates {
    fn default() -> Self {
        RouteAuthorizationUpdates {
            added: HashSet::new(),
            removed: HashSet::new(),
        }
    }
}

//------------ RouteAuthorization ------------------------------------------

/// This type defines a prefix and optional maximum length (other than the
/// prefix length) which is to be authorized for the given origin ASN.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RouteAuthorization {
    origin: AsNumber,
    prefix: RoaPrefix,
}

impl RouteAuthorization {
    pub fn new(origin: AsNumber, prefix: RoaPrefix) -> Self {
        RouteAuthorization { origin, prefix }
    }

    pub fn origin(&self) -> AsNumber {
        self.origin
    }

    pub fn prefix(&self) -> RoaPrefix {
        self.prefix
    }
}

impl FromStr for RouteAuthorization {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("=>");
        let prefix_str = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        let asn_str = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        if parts.next().is_some() {
            return Err(AuthorizationFmtError::auth(s));
        }
        let prefix = RoaPrefix::from_str(&prefix_str)?;
        let origin = AsNumber::from_str(&asn_str)?;

        Ok(RouteAuthorization { origin, prefix })
    }
}

impl fmt::Display for RouteAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} => {}", self.prefix, self.origin)
    }
}

//------------ RoaPrefix ---------------------------------------------------

/// This type defines a ROA IPv4 or IPv6 prefix and optional max length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoaPrefix {
    prefix: Prefix,
    max_length: Option<u8>,
    family: AddressFamily,
}

impl RoaPrefix {
    pub fn addr(&self) -> IpAddr {
        match self.family {
            AddressFamily::Ipv4 => IpAddr::V4(self.prefix.to_v4()),
            AddressFamily::Ipv6 => IpAddr::V6(self.prefix.to_v6()),
        }
    }
    pub fn len(&self) -> u8 {
        self.prefix.addr_len()
    }
    pub fn max_length(&self) -> Option<u8> {
        self.max_length
    }
}

impl From<RoaPrefix> for ResourceSet {
    fn from(pfx: RoaPrefix) -> Self {
        let mut builder = IpBlocksBuilder::new();
        builder.push(pfx.prefix);
        let blocks = builder.finalize();

        match pfx.family {
            AddressFamily::Ipv4 => ResourceSet::new(AsBlocks::empty(), blocks, IpBlocks::empty()),
            AddressFamily::Ipv6 => ResourceSet::new(AsBlocks::empty(), IpBlocks::empty(), blocks),
        }
    }
}

impl Hash for RoaPrefix {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.prefix.hash(state);
        self.max_length.hash(state);
    }
}

impl fmt::Display for RoaPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let add = self.prefix.addr();
        let add_str = match self.family {
            AddressFamily::Ipv4 => add.to_v4().to_string(),
            AddressFamily::Ipv6 => add.to_v6().to_string(),
        };
        match self.max_length {
            None => write!(f, "{}/{}", add_str, self.prefix.addr_len()),
            Some(max) => write!(f, "{}/{}-{}", add_str, self.prefix.addr_len(), max),
        }
    }
}

impl FromStr for RoaPrefix {
    type Err = AuthorizationFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        let mut parts = s.split("-");
        let prefix = parts.next().ok_or_else(|| AuthorizationFmtError::pfx(s))?;

        let family = if s.contains('.') {
            AddressFamily::Ipv4
        } else if s.contains(':') {
            AddressFamily::Ipv6
        } else {
            return Err(AuthorizationFmtError::pfx(s));
        };

        let prefix = match family {
            AddressFamily::Ipv4 => {
                Prefix::from_v4_str(prefix).map_err(|_| AuthorizationFmtError::pfx(s))
            }
            AddressFamily::Ipv6 => {
                Prefix::from_v6_str(prefix).map_err(|_| AuthorizationFmtError::pfx(s))
            }
        }
        .map_err(|_| AuthorizationFmtError::pfx(s))?;

        let max_length = match parts.next() {
            None => None,
            Some(s) => Some(u8::from_str(s).map_err(|_| AuthorizationFmtError::pfx(s))?),
        };

        if let Some(max) = max_length {
            let too_long = match family {
                AddressFamily::Ipv4 => max > 32,
                AddressFamily::Ipv6 => max > 128,
            };
            if max < prefix.addr_len() || too_long {
                return Err(AuthorizationFmtError::pfx(s));
            }
        }

        Ok(RoaPrefix {
            prefix,
            max_length,
            family,
        })
    }
}

impl Serialize for RoaPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RoaPrefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        RoaPrefix::from_str(string.as_str()).map_err(de::Error::custom)
    }
}

//------------ AsNumber ----------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AsNumber(u32);

impl AsNumber {
    pub fn new(number: u32) -> Self {
        AsNumber(number)
    }
}

impl From<AsNumber> for AsId {
    fn from(asn: AsNumber) -> Self {
        AsId::from(asn.0)
    }
}

impl FromStr for AsNumber {
    type Err = AuthorizationFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let number = u32::from_str(s).map_err(|_| AuthorizationFmtError::asn(s))?;
        Ok(AsNumber(number))
    }
}

impl fmt::Display for AsNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//------------ RoaPrefixError ----------------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum AuthorizationFmtError {
    #[display(fmt = "Invalid prefix string: {}", _0)]
    Pfx(String),

    #[display(fmt = "Invalid asn in string: {}", _0)]
    Asn(String),

    #[display(fmt = "Invalid authorisation string: {}", _0)]
    Auth(String),
}

impl AuthorizationFmtError {
    fn pfx(s: &str) -> Self {
        AuthorizationFmtError::Pfx(s.to_string())
    }

    fn asn(s: &str) -> Self {
        AuthorizationFmtError::Asn(s.to_string())
    }

    fn auth(s: &str) -> Self {
        AuthorizationFmtError::Auth(s.to_string())
    }
}

//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roa_prefix() {
        assert!(RoaPrefix::from_str("192.168.0.0/16").is_ok());
        assert!(RoaPrefix::from_str("192.168.0.0/16-16").is_ok());
        assert!(RoaPrefix::from_str("192.168.0.0/16-24").is_ok());
        assert!(RoaPrefix::from_str("192.168.0.0/16-15").is_err());
        assert!(RoaPrefix::from_str("192.168.0.0/16-33").is_err());
    }

    #[test]
    fn parse_route_authorization() {
        fn parse_encode_authorization(s: &str) {
            let authz = RouteAuthorization::from_str(s).unwrap();
            assert_eq!(s, authz.to_string().as_str());
        }

        parse_encode_authorization("192.168.0.0/16 => 64496");
        parse_encode_authorization("192.168.0.0/16-24 => 64496");
    }

}
