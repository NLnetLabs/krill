use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::resources::{AsBlocks, AsId, IpBlocks, IpBlocksBuilder, Prefix};

use crate::commons::api::ResourceSet;
use crate::daemon::ca::RouteAuthorizationUpdates;

//------------ RoaDefinition -----------------------------------------------

/// This type defines the definition of a Route Origin Authorization (ROA), i.e.
/// the originating asn, IPv4 or IPv6 prefix, and optionally a max length.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaDefinition {
    asn: AsNumber,
    prefix: TypedPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_length: Option<u8>,
}

impl RoaDefinition {
    pub fn new(asn: AsNumber, prefix: TypedPrefix, max_length: Option<u8>) -> Self {
        RoaDefinition {
            asn,
            prefix,
            max_length,
        }
    }

    pub fn asn(&self) -> AsNumber {
        self.asn
    }

    pub fn prefix(&self) -> TypedPrefix {
        self.prefix
    }

    pub fn max_length(&self) -> Option<u8> {
        self.max_length
    }

    pub fn effective_max_length(&self) -> u8 {
        match self.max_length {
            None => self.prefix.addr_len(),
            Some(len) => len,
        }
    }

    pub fn max_length_valid(&self) -> bool {
        if let Some(max_length) = self.max_length {
            match self.prefix {
                TypedPrefix::V4(_) => max_length >= self.prefix.addr_len() && max_length <= 32,
                TypedPrefix::V6(_) => max_length >= self.prefix.addr_len() && max_length <= 128,
            }
        } else {
            true
        }
    }
}

impl FromStr for RoaDefinition {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("=>");

        let prefix_part = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        let mut prefix_parts = prefix_part.split('-');
        let prefix_str = prefix_parts
            .next()
            .ok_or_else(|| AuthorizationFmtError::auth(s))?;

        let prefix = TypedPrefix::from_str(&prefix_str.trim())?;

        let max_length = match prefix_parts.next() {
            None => None,
            Some(length_str) => {
                Some(u8::from_str(&length_str.trim()).map_err(|_| AuthorizationFmtError::auth(s))?)
            }
        };

        let asn_str = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        if parts.next().is_some() {
            return Err(AuthorizationFmtError::auth(s));
        }
        let origin = AsNumber::from_str(&asn_str.trim())?;

        Ok(RoaDefinition {
            asn: origin,
            prefix,
            max_length,
        })
    }
}

impl fmt::Display for RoaDefinition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.max_length {
            None => write!(f, "{} => {}", self.prefix, self.asn),
            Some(length) => write!(f, "{}-{} => {}", self.prefix, length, self.asn),
        }
    }
}

impl AsRef<TypedPrefix> for RoaDefinition {
    fn as_ref(&self) -> &TypedPrefix {
        &self.prefix
    }
}

//------------ RouteAuthorizationUpdates -----------------------------------

/// This type defines a delta of Route Authorizations, i.e. additions or removals
/// of authorizations of tuples of (Prefix, Max Length, ASN) that ultimately
/// are put into ROAs by a CA, in as far as the CA has the required prefixes
/// on its resource certificates.
///
/// Multiple updates are sent as a single delta, because it's important that
/// all authorizations for a given prefix are published together in order to
/// avoid invalidating announcements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaDefinitionUpdates {
    added: HashSet<RoaDefinition>,
    removed: HashSet<RoaDefinition>,
}

impl RoaDefinitionUpdates {
    pub fn new(added: HashSet<RoaDefinition>, removed: HashSet<RoaDefinition>) -> Self {
        RoaDefinitionUpdates { added, removed }
    }

    /// Unpack this and return all added (left), and all removed (right) route
    /// authorizations.
    pub fn unpack(self) -> (HashSet<RoaDefinition>, HashSet<RoaDefinition>) {
        (self.added, self.removed)
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn add(&mut self, add: RoaDefinition) {
        self.added.insert(add);
    }

    pub fn added(&self) -> &HashSet<RoaDefinition> {
        &self.added
    }

    pub fn removed(&self) -> &HashSet<RoaDefinition> {
        &self.removed
    }

    pub fn remove(&mut self, rem: RoaDefinition) {
        self.removed.insert(rem);
    }
}

impl Default for RoaDefinitionUpdates {
    fn default() -> Self {
        RoaDefinitionUpdates {
            added: HashSet::new(),
            removed: HashSet::new(),
        }
    }
}

impl fmt::Display for RoaDefinitionUpdates {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for a in &self.added {
            writeln!(f, "A: {}", a)?;
        }
        for r in &self.removed {
            writeln!(f, "R: {}", r)?;
        }
        Ok(())
    }
}

impl FromStr for RoaDefinitionUpdates {
    type Err = AuthorizationFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut added = HashSet::new();
        let mut removed = HashSet::new();

        for line in s.lines() {
            let line = match line.find('#') {
                None => &line,
                Some(pos) => &line[..pos],
            };
            let line = line.trim();

            if line.is_empty() {
                continue;
            } else if line.starts_with("A:") {
                let line = &line[2..];
                let line = line.trim();
                let auth = RoaDefinition::from_str(line)?;
                added.insert(auth);
            } else if line.starts_with("R:") {
                let line = &line[2..];
                let line = line.trim();
                let auth = RoaDefinition::from_str(line)?;
                removed.insert(auth);
            } else {
                return Err(AuthorizationFmtError::delta(line));
            }
        }

        Ok(RoaDefinitionUpdates { added, removed })
    }
}

impl From<RouteAuthorizationUpdates> for RoaDefinitionUpdates {
    fn from(auth_updates: RouteAuthorizationUpdates) -> Self {
        let (auth_added, auth_removed) = auth_updates.unpack();
        let added = auth_added.into_iter().map(|a| a.into()).collect();
        let removed = auth_removed.into_iter().map(|a| a.into()).collect();
        RoaDefinitionUpdates { added, removed }
    }
}

//------------ TypedPrefix -------------------------------------------------
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TypedPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl TypedPrefix {
    pub fn prefix(&self) -> &Prefix {
        self.as_ref()
    }

    pub fn ip_addr(&self) -> IpAddr {
        match self {
            TypedPrefix::V4(v4) => IpAddr::V4(v4.0.to_v4()),
            TypedPrefix::V6(v6) => IpAddr::V6(v6.0.to_v6()),
        }
    }

    fn matches_type(&self, other: &TypedPrefix) -> bool {
        match &self {
            TypedPrefix::V4(_) => match other {
                TypedPrefix::V4(_) => true,
                TypedPrefix::V6(_) => false,
            },
            TypedPrefix::V6(_) => match other {
                TypedPrefix::V4(_) => false,
                TypedPrefix::V6(_) => true,
            },
        }
    }

    pub fn covers(&self, other: &TypedPrefix) -> bool {
        self.matches_type(other) && self.min().le(&other.min()) && self.max().ge(&other.max())
    }
}

impl FromStr for TypedPrefix {
    type Err = AuthorizationFmtError;

    fn from_str(prefix: &str) -> Result<Self, Self::Err> {
        if prefix.contains('.') {
            Ok(TypedPrefix::V4(Ipv4Prefix(
                Prefix::from_v4_str(prefix.trim())
                    .map_err(|_| AuthorizationFmtError::pfx(prefix))?,
            )))
        } else {
            Ok(TypedPrefix::V6(Ipv6Prefix(
                Prefix::from_v6_str(prefix.trim())
                    .map_err(|_| AuthorizationFmtError::pfx(prefix))?,
            )))
        }
    }
}

impl fmt::Display for TypedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TypedPrefix::V4(pfx) => pfx.fmt(f),
            TypedPrefix::V6(pfx) => pfx.fmt(f),
        }
    }
}

impl AsRef<Prefix> for TypedPrefix {
    fn as_ref(&self) -> &Prefix {
        match self {
            TypedPrefix::V4(v4) => &v4.0,
            TypedPrefix::V6(v6) => &v6.0,
        }
    }
}

impl Deref for TypedPrefix {
    type Target = Prefix;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl Serialize for TypedPrefix {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

impl<'de> Deserialize<'de> for TypedPrefix {
    fn deserialize<D>(d: D) -> Result<TypedPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        TypedPrefix::from_str(string.as_str()).map_err(de::Error::custom)
    }
}

impl From<TypedPrefix> for ResourceSet {
    fn from(tp: TypedPrefix) -> ResourceSet {
        match tp {
            TypedPrefix::V4(v4) => {
                let mut builder = IpBlocksBuilder::new();
                builder.push(v4.0);
                let blocks = builder.finalize();

                ResourceSet::new(AsBlocks::empty(), blocks, IpBlocks::empty())
            }
            TypedPrefix::V6(v6) => {
                let mut builder = IpBlocksBuilder::new();
                builder.push(v6.0);
                let blocks = builder.finalize();

                ResourceSet::new(AsBlocks::empty(), IpBlocks::empty(), blocks)
            }
        }
    }
}

//------------ Ipv4Prefix --------------------------------------------------
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Prefix(Prefix);

impl AsRef<Prefix> for Ipv4Prefix {
    fn as_ref(&self) -> &Prefix {
        &self.0
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.0.to_v4(), self.0.addr_len())
    }
}

//------------ Ipv6Prefix --------------------------------------------------
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv6Prefix(Prefix);

impl AsRef<Prefix> for Ipv6Prefix {
    fn as_ref(&self) -> &Prefix {
        &self.0
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.0.to_v6(), self.0.addr_len())
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

//------------ AuthorizationFmtError -------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
pub enum AuthorizationFmtError {
    #[display(fmt = "Invalid prefix string: {}", _0)]
    Pfx(String),

    #[display(fmt = "Invalid asn in string: {}", _0)]
    Asn(String),

    #[display(fmt = "Invalid authorization string: {}", _0)]
    Auth(String),

    #[display(fmt = "Invalid authorization delta string: {}", _0)]
    Delta(String),
}

impl AuthorizationFmtError {
    fn pfx(s: &str) -> Self {
        AuthorizationFmtError::Pfx(s.to_string())
    }

    fn asn(s: &str) -> Self {
        AuthorizationFmtError::Asn(s.to_string())
    }

    pub fn auth(s: &str) -> Self {
        AuthorizationFmtError::Auth(s.to_string())
    }

    pub fn delta(s: &str) -> Self {
        AuthorizationFmtError::Delta(s.to_string())
    }
}

//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_delta() {
        let delta = concat!(
            "# Some comment\n",
            "  # Indented comment\n",
            "\n", // empty line
            "A: 192.168.0.0/16 => 64496 # inline comment\n",
            "A: 192.168.1.0/24 => 64496\n",
            "R: 192.168.3.0/24 => 64496\n",
        );

        let expected = {
            let mut added = HashSet::new();
            added.insert(RoaDefinition::from_str("192.168.0.0/16 => 64496").unwrap());
            added.insert(RoaDefinition::from_str("192.168.1.0/24 => 64496").unwrap());

            let mut removed = HashSet::new();
            removed.insert(RoaDefinition::from_str("192.168.3.0/24 => 64496").unwrap());
            RoaDefinitionUpdates::new(added, removed)
        };

        let parsed = RoaDefinitionUpdates::from_str(delta).unwrap();
        assert_eq!(expected, parsed);

        let reparsed = RoaDefinitionUpdates::from_str(&parsed.to_string()).unwrap();
        assert_eq!(parsed, reparsed);
    }

    #[test]
    fn parse_type_prefix() {
        assert!(TypedPrefix::from_str("192.168.0.0/16").is_ok());
        assert!(TypedPrefix::from_str("2001:db8::/32").is_ok());
    }

    #[test]
    fn normalize_roa_definition_json() {
        let def = RoaDefinition::from_str("192.168.0.0/16 => 64496").unwrap();
        let json = serde_json::to_string(&def).unwrap();
        let expected = "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\"}";
        assert_eq!(json, expected);

        let def = RoaDefinition::from_str("192.168.0.0/16-24 => 64496").unwrap();
        let json = serde_json::to_string(&def).unwrap();
        let expected = "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\",\"max_length\":24}";
        assert_eq!(json, expected);
    }

    #[test]
    fn serde_roa_definition() {
        fn parse_ser_de_print_definition(s: &str) {
            let def = RoaDefinition::from_str(s).unwrap();
            let ser = serde_json::to_string(&def).unwrap();
            let de = serde_json::from_str(&ser).unwrap();
            assert_eq!(def, de);
            assert_eq!(s, de.to_string().as_str())
        }

        parse_ser_de_print_definition("192.168.0.0/16 => 64496");
        parse_ser_de_print_definition("192.168.0.0/16-24 => 64496");
        parse_ser_de_print_definition("2001:db8::/32 => 64496");
        parse_ser_de_print_definition("2001:db8::/32-48 => 64496");
    }

    #[test]
    fn roa_max_length() {
        fn valid_max_length(s: &str) {
            let def = RoaDefinition::from_str(s).unwrap();
            assert!(def.max_length_valid())
        }

        fn invalid_max_length(s: &str) {
            let def = RoaDefinition::from_str(s).unwrap();
            assert!(!def.max_length_valid())
        }

        valid_max_length("192.168.0.0/16 => 64496");
        valid_max_length("192.168.0.0/16-16 => 64496");
        valid_max_length("192.168.0.0/16-24 => 64496");
        valid_max_length("192.168.0.0/16-32 => 64496");
        valid_max_length("2001:db8::/32 => 64496");
        valid_max_length("2001:db8::/32-32 => 64496");
        valid_max_length("2001:db8::/32-48 => 64496");
        valid_max_length("2001:db8::/32-128 => 64496");

        invalid_max_length("192.168.0.0/16-15 => 64496");
        invalid_max_length("192.168.0.0/16-33 => 64496");
        invalid_max_length("2001:db8::/32-31 => 64496");
        invalid_max_length("2001:db8::/32-129 => 64496");
    }
}
