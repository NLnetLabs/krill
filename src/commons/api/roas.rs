use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::resources::{AsBlocks, AsId, IpBlocks, IpBlocksBuilder, Prefix};
use rpki::roa::RoaIpAddress;

use crate::commons::api::ResourceSet;
use crate::daemon::ca::RouteAuthorizationUpdates;

//------------ RoaAggregateKey ---------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoaAggregateKey {
    asn: AsNumber,
    group: Option<u32>,
}

impl RoaAggregateKey {
    pub fn new(asn: AsNumber, group: Option<u32>) -> Self {
        RoaAggregateKey { asn, group }
    }

    pub fn asn(&self) -> AsNumber {
        self.asn
    }

    pub fn group(&self) -> Option<u32> {
        self.group
    }
}

impl fmt::Display for RoaAggregateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.group {
            None => write!(f, "AS{}", self.asn),
            Some(nr) => write!(f, "AS{}-{}", self.asn, nr),
        }
    }
}

impl FromStr for RoaAggregateKey {
    type Err = RoaAggregateKeyFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('-');

        let asn_part = parts.next().ok_or_else(|| RoaAggregateKeyFmtError::string(s))?;

        if !asn_part.starts_with("AS") || asn_part.len() < 3 {
            return Err(RoaAggregateKeyFmtError::string(s));
        }

        let asn = AsNumber::from_str(&asn_part[2..]).map_err(|_| RoaAggregateKeyFmtError::string(s))?;

        let group = if let Some(group) = parts.next() {
            let group = u32::from_str(group).map_err(|_| RoaAggregateKeyFmtError::string(s))?;
            Some(group)
        } else {
            None
        };

        if parts.next().is_some() {
            Err(RoaAggregateKeyFmtError::string(s))
        } else {
            Ok(RoaAggregateKey { asn, group })
        }
    }
}

/// We use RoaGroup as (json) map keys and therefore we need it
/// to be serializable to a single simple string.
impl Serialize for RoaAggregateKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

/// We use RoaGroup as (json) map keys and therefore we need it
/// to be deserializable from a single simple string.
impl<'de> Deserialize<'de> for RoaAggregateKey {
    fn deserialize<D>(d: D) -> Result<RoaAggregateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        RoaAggregateKey::from_str(string.as_str()).map_err(de::Error::custom)
    }
}

//------------ AuthorizationFmtError -------------------------------------

#[derive(Clone, Debug, Display, Eq, PartialEq)]
#[display(fmt = "Invalid ROA Group format ({})", _0)]
pub struct RoaAggregateKeyFmtError(String);

impl RoaAggregateKeyFmtError {
    fn string(s: &str) -> Self {
        RoaAggregateKeyFmtError(s.to_string())
    }
}

//------------ RoaDefinition -----------------------------------------------

/// This type defines the definition of a Route Origin Authorization (ROA), i.e.
/// the originating asn, IPv4 or IPv6 prefix, and optionally a max length.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

    pub fn explicit_max_length(self) -> Self {
        RoaDefinition {
            asn: self.asn,
            prefix: self.prefix,
            max_length: Some(self.effective_max_length()),
        }
    }

    pub fn as_roa_ip_address(&self) -> RoaIpAddress {
        RoaIpAddress::new(*self.prefix.prefix(), self.max_length)
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

    /// Returns `true` if the this definition includes the other definition.
    pub fn includes(&self, other: &RoaDefinition) -> bool {
        self.asn == other.asn
            && self.prefix.matching_or_less_specific(&other.prefix)
            && self.effective_max_length() >= other.effective_max_length()
    }

    /// Returns `true` if this is an AS0 definition which overlaps the other.
    pub fn overlaps(&self, other: &RoaDefinition) -> bool {
        self.prefix.matching_or_less_specific(&other.prefix) || other.prefix.matching_or_less_specific(&self.prefix)
    }

    /// Returns all prefixes covered by the max length of this definition.
    /// Note that if the effective max length equals the prefix length, this
    /// means that the single prefix in this definition is returned.
    pub fn to_specific_prefixes(&self) -> Vec<TypedPrefix> {
        self.prefix.to_specific_prefixes(self.effective_max_length())
    }
}

impl FromStr for RoaDefinition {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("=>");

        let prefix_part = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        let mut prefix_parts = prefix_part.split('-');
        let prefix_str = prefix_parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;

        let prefix = TypedPrefix::from_str(&prefix_str.trim())?;

        let max_length = match prefix_parts.next() {
            None => None,
            Some(length_str) => Some(u8::from_str(&length_str.trim()).map_err(|_| AuthorizationFmtError::auth(s))?),
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

impl fmt::Debug for RoaDefinition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
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

impl Ord for RoaDefinition {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.prefix.cmp(&other.prefix);

        if ordering == Ordering::Equal {
            ordering = self.effective_max_length().cmp(&other.effective_max_length());
        }

        if ordering == Ordering::Equal {
            ordering = self.asn.cmp(&other.asn);
        }

        ordering
    }
}

impl PartialOrd for RoaDefinition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<TypedPrefix> for RoaDefinition {
    fn as_ref(&self) -> &TypedPrefix {
        &self.prefix
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaDefinitions(Vec<RoaDefinition>);

impl fmt::Display for RoaDefinitions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for def in self.0.iter() {
            writeln!(f, "{}", def)?;
        }
        Ok(())
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
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

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
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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

    pub fn matching_or_less_specific(&self, other: &TypedPrefix) -> bool {
        self.matches_type(other)
            && self.prefix().min().le(&other.prefix().min())
            && self.prefix().max().ge(&other.prefix().max())
    }

    pub fn to_specific_prefixes(&self, len: u8) -> Vec<TypedPrefix> {
        let mut res = vec![];

        let nr_specifics = 1 << (len - self.addr_len());

        // note that the lower 12 bytes are disregarded for IPv4
        // by our implementation, so the increment here is the
        // same for both address families.
        let increment: u128 = 1 << (128 - len);

        for i in 0..nr_specifics {
            let base = self.addr().to_bits() + i * increment;
            let pfx = Prefix::new(base, len);

            let pfx = match self {
                TypedPrefix::V4(_) => TypedPrefix::V4(Ipv4Prefix(pfx)),
                TypedPrefix::V6(_) => TypedPrefix::V6(Ipv6Prefix(pfx)),
            };

            res.push(pfx);
        }

        res
    }
}

impl FromStr for TypedPrefix {
    type Err = AuthorizationFmtError;

    fn from_str(prefix: &str) -> Result<Self, Self::Err> {
        if prefix.contains('.') {
            Ok(TypedPrefix::V4(Ipv4Prefix(
                Prefix::from_v4_str(prefix.trim()).map_err(|_| AuthorizationFmtError::pfx(prefix))?,
            )))
        } else {
            Ok(TypedPrefix::V6(Ipv6Prefix(
                Prefix::from_v6_str(prefix.trim()).map_err(|_| AuthorizationFmtError::pfx(prefix))?,
            )))
        }
    }
}

impl fmt::Debug for TypedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
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

impl Ord for TypedPrefix {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.addr().cmp(&other.addr());
        if ordering == Ordering::Equal {
            ordering = self.addr_len().cmp(&other.addr_len())
        }
        ordering
    }
}

impl PartialOrd for TypedPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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

impl fmt::Debug for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

//------------ Ipv6Prefix --------------------------------------------------
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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

impl fmt::Debug for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

//------------ AsNumber ----------------------------------------------------

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AsNumber(u32);

impl AsNumber {
    pub fn new(number: u32) -> Self {
        AsNumber(number)
    }

    pub fn zero() -> Self {
        AsNumber(0)
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

impl fmt::Debug for AsNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

impl fmt::Display for AsNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Ord for AsNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for AsNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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

    use crate::test::definition;
    use crate::test::typed_prefix;

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
            added.insert(definition("192.168.0.0/16 => 64496"));
            added.insert(definition("192.168.1.0/24 => 64496"));

            let mut removed = HashSet::new();
            removed.insert(definition("192.168.3.0/24 => 64496"));
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
        let def = definition("192.168.0.0/16 => 64496");
        let json = serde_json::to_string(&def).unwrap();
        let expected = "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\"}";
        assert_eq!(json, expected);

        let def = definition("192.168.0.0/16-24 => 64496");
        let json = serde_json::to_string(&def).unwrap();
        let expected = "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\",\"max_length\":24}";
        assert_eq!(json, expected);
    }

    #[test]
    fn serde_roa_definition() {
        fn parse_ser_de_print_definition(s: &str) {
            let def = definition(s);
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

    #[test]
    fn roa_includes() {
        let covering = definition("192.168.0.0/16-20 => 64496");

        let included_no_ml = definition("192.168.0.0/16 => 64496");
        let included_more_specific = definition("192.168.0.0/20 => 64496");

        let allowing_more_specific = definition("192.168.0.0/16-24 => 64496");
        let more_specific = definition("192.168.3.0/24 => 64496");
        let other_asn = definition("192.168.3.0/24 => 64497");

        assert!(covering.includes(&included_no_ml));
        assert!(covering.includes(&included_more_specific));

        assert!(!covering.includes(&more_specific));
        assert!(!covering.includes(&allowing_more_specific));
        assert!(!covering.includes(&other_asn));
    }

    #[test]
    fn roa_group_string() {
        let roa_group_asn_only = RoaAggregateKey {
            asn: AsNumber::new(0),
            group: None,
        };

        let roa_group_asn_only_expected_str = "AS0";
        assert_eq!(roa_group_asn_only.to_string().as_str(), roa_group_asn_only_expected_str);

        let roa_group_asn_only_expected = RoaAggregateKey::from_str(roa_group_asn_only_expected_str).unwrap();
        assert_eq!(roa_group_asn_only, roa_group_asn_only_expected)
    }

    #[test]
    fn split_definition_to_specifics() {
        fn check(def: &str, pfxs: &[&str]) {
            let def = definition(def);
            let expected: Vec<TypedPrefix> = pfxs.iter().map(|s| typed_prefix(s)).collect();
            let seen = def.to_specific_prefixes();
            assert_eq!(seen, expected);
        }

        check("10.0.0.0/16-16 => 64496", &["10.0.0.0/16"]);
        check("10.0.0.0/15-16 => 64496", &["10.0.0.0/16", "10.1.0.0/16"]);

        check("2001:db8::/32-32 => 64496", &["2001:db8::/32"]);
        check("2001:db8::/32-33 => 64496", &["2001:db8::/33", "2001:db8:8000::/33"]);
    }
}
