use std::{cmp::Ordering, fmt, net::IpAddr, ops::Deref, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use rpki::repository::{
    resources::{AsBlocks, Asn, IpBlocks, IpBlocksBuilder, Prefix, ResourceSet},
    roa::RoaIpAddress,
};

use crate::commons::bgp::Announcement;

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

/// Ordering is based on ASN first, and group second if there are
/// multiple keys for the same ASN. Note: we don't currently use
/// such groups. It's here in case we want to give users more
/// options in future.
impl Ord for RoaAggregateKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.asn.cmp(&other.asn) {
            Ordering::Equal => self.group.cmp(&other.group),
            Ordering::Greater => Ordering::Greater,
            Ordering::Less => Ordering::Less,
        }
    }
}

impl PartialOrd for RoaAggregateKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//------------ AuthorizationFmtError -------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoaAggregateKeyFmtError(String);

impl fmt::Display for RoaAggregateKeyFmtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid ROA Group format ({})", self.0)
    }
}

impl RoaAggregateKeyFmtError {
    fn string(s: &str) -> Self {
        RoaAggregateKeyFmtError(s.to_string())
    }
}

//------------ RoaPayload --------------------------------------------------

/// This type defines the definition of a Route Origin Authorization (ROA)
/// payload: ASN, Prefix and optional Max Length
///
/// Note that an RFC 6482 ROA object may contain multiple prefixes and
/// optional max length values, aggregated by (a single) ASN. The term
/// "Validated ROA Payload" is used in RFC 6811 (BGP Prefix Origin
/// Validation) to describe validated tuples of ASN, Prefix and optional
/// Max Length.
///
/// Note that Krill does not allow users to specify RFC 6482 ROA objects
/// as such. Instead it allows users to configure the intent of which
/// "ROA Payloads" should be authorized. We could call this type
/// IntendRoaPayload, but we stuck with RoaPayload for brevity.
///
/// In any case, Krill will create RFC 6482 for RoaPayloads appearing
/// on saved configurations - in as far as the CA holds the prefixes
/// on its certificate(s). It will prefer to issue a single object
/// per payload in accordance with best practices (avoid fate sharing
/// in case a prefix is suddenly no longer held), but aggregation will
/// be done if a (configurable) threshold is exceeded.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaPayload {
    asn: AsNumber,
    prefix: TypedPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_length: Option<u8>,
}

impl RoaPayload {
    pub fn new(asn: AsNumber, prefix: TypedPrefix, max_length: Option<u8>) -> Self {
        RoaPayload {
            asn,
            prefix,
            max_length,
        }
    }

    /// Ensures that the payload uses an explicit max length
    pub fn into_explicit_max_length(self) -> Self {
        RoaPayload {
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

    pub fn nr_of_specific_prefixes(&self) -> u128 {
        let pfx_len = self.prefix.addr_len();
        let max_len = self.effective_max_length();

        // 10.0.0.0/8-8 -> 1   2^0
        // 10.0.0.0/8-9 -> 2   2^1
        // 10.0.0.0/8-10 -> 4  2^2
        // 10.0.0.0/8-11 -> 8  2^3

        1u128 << (max_len - pfx_len)
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
    pub fn includes(&self, other: &RoaPayload) -> bool {
        self.asn == other.asn
            && self.prefix.matching_or_less_specific(&other.prefix)
            && self.effective_max_length() >= other.effective_max_length()
    }

    /// Returns `true` if this is an AS0 definition which overlaps the other.
    pub fn overlaps(&self, other: &RoaPayload) -> bool {
        self.prefix.matching_or_less_specific(&other.prefix) || other.prefix.matching_or_less_specific(&self.prefix)
    }
}

impl FromStr for RoaPayload {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("=>");

        let prefix_part = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        let mut prefix_parts = prefix_part.split('-');
        let prefix_str = prefix_parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;

        let prefix = TypedPrefix::from_str(prefix_str.trim())?;

        let max_length = match prefix_parts.next() {
            None => None,
            Some(length_str) => Some(u8::from_str(length_str.trim()).map_err(|_| AuthorizationFmtError::auth(s))?),
        };

        let asn_str = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        if parts.next().is_some() {
            return Err(AuthorizationFmtError::auth(s));
        }
        let origin = AsNumber::from_str(asn_str.trim())?;

        Ok(RoaPayload {
            asn: origin,
            prefix,
            max_length,
        })
    }
}

impl fmt::Debug for RoaPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}

impl fmt::Display for RoaPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.max_length {
            None => write!(f, "{} => {}", self.prefix, self.asn),
            Some(length) => write!(f, "{}-{} => {}", self.prefix, length, self.asn),
        }
    }
}

impl Ord for RoaPayload {
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

impl PartialOrd for RoaPayload {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<TypedPrefix> for RoaPayload {
    fn as_ref(&self) -> &TypedPrefix {
        &self.prefix
    }
}

//------------ RoaConfiguration --------------------------------------------

/// This type defines an *intended* configuration for a ROA.
///
/// This type is intended to be used for updates through the API.
///
/// It includes the actual ROA payload that needs be authorized on an RFC 6482
/// ROA object, as well as other information that is only visible to the Krill
/// users - like the optional comment field, which can be used to store useful
/// reminders of the purpose of this configuration. And in future perhaps other
/// things such as tags used for classification/monitoring/bpp analysis could
/// be added.
///
/// Note that the [`ConfiguredRoa`] type defines an *existing* configured ROA.
/// Existing ROAs may contain other information that the Krill system is
/// responsible for, rather than the API (update) user. For example: which ROA
/// object(s) the intended configuration appears on.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaConfiguration {
    // We flatten the payload and have defaults for other fields, so
    // that the JSON serialized representation can be backward compatible
    // with the RoaDefinition type that was used until Krill 0.10.0.
    //
    // I.e:
    // - The API can still accept the 'old' style JSON without comments
    // - We do not need to do data migrations on upgrade
    // - The query API will include an extra field ("comment"), but
    //   most API users will ignore additional fields.
    #[serde(flatten)]
    payload: RoaPayload,
    #[serde(default)] // missing is same as no comment
    comment: Option<String>,
}

impl RoaConfiguration {
    pub fn new(payload: RoaPayload, comment: Option<String>) -> Self {
        RoaConfiguration { payload, comment }
    }

    pub fn unpack(self) -> (RoaPayload, Option<String>) {
        (self.payload, self.comment)
    }

    pub fn payload(&self) -> RoaPayload {
        self.payload
    }

    pub fn comment(&self) -> Option<&String> {
        self.comment.as_ref()
    }

    /// Ensures that the payload uses an explicit max length
    pub fn into_explicit_max_length(self) -> Self {
        RoaConfiguration {
            payload: self.payload.into_explicit_max_length(),
            comment: self.comment,
        }
    }
}

impl fmt::Display for RoaConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.payload)?;
        if let Some(comment) = &self.comment {
            write!(f, " # {}", comment)?;
        }
        Ok(())
    }
}

impl FromStr for RoaConfiguration {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    // "192.168.0.0/16 => 64496 # my nice ROA"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '#');
        let payload_part = parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;

        let payload = RoaPayload::from_str(payload_part)?;
        let comment = parts.next().map(|s| s.trim().to_string());

        Ok(RoaConfiguration { payload, comment })
    }
}

impl Ord for RoaConfiguration {
    fn cmp(&self, other: &Self) -> Ordering {
        self.payload.cmp(&other.payload)
    }
}

impl PartialOrd for RoaConfiguration {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<RoaPayload> for RoaConfiguration {
    fn from(payload: RoaPayload) -> Self {
        RoaConfiguration { payload, comment: None }
    }
}

//------------ ConfiguredRoa -----------------------------------------------

/// Defines an existing ROA configuration.
///
/// This type is used in the API for listing/reporting.
///
/// It contains the user determined intended RoaConfiguration as well as
/// system determined things, like the roa objects - at least it will
/// as soon as #864 is implemented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfiguredRoa {
    #[serde(flatten)]
    roa_configuration: RoaConfiguration,
    // roa_objects: Vec<RoaInfo>, // will be added when #864 is implemented
}

impl ConfiguredRoa {
    pub fn new(roa_configuration: RoaConfiguration) -> Self {
        ConfiguredRoa { roa_configuration }
    }

    pub fn payload(&self) -> RoaPayload {
        self.roa_configuration.payload
    }

    pub fn asn(&self) -> AsNumber {
        self.roa_configuration.payload.asn()
    }

    pub fn prefix(&self) -> TypedPrefix {
        self.roa_configuration.payload.prefix()
    }

    pub fn effective_max_length(&self) -> u8 {
        self.roa_configuration.payload.effective_max_length()
    }

    pub fn nr_of_specific_prefixes(&self) -> u128 {
        self.roa_configuration.payload.nr_of_specific_prefixes()
    }

    pub fn as_roa_ip_address(&self) -> RoaIpAddress {
        self.roa_configuration.payload().as_roa_ip_address()
    }
}

impl From<Announcement> for ConfiguredRoa {
    fn from(announcement: Announcement) -> Self {
        let payload = RoaPayload::from(announcement);
        let roa_configuration = RoaConfiguration::from(payload);
        ConfiguredRoa { roa_configuration }
    }
}

impl AsRef<RoaConfiguration> for ConfiguredRoa {
    fn as_ref(&self) -> &RoaConfiguration {
        &self.roa_configuration
    }
}

impl fmt::Display for ConfiguredRoa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.roa_configuration)
    }
}

impl Ord for ConfiguredRoa {
    fn cmp(&self, other: &Self) -> Ordering {
        self.roa_configuration.cmp(&other.roa_configuration)
    }
}

impl PartialOrd for ConfiguredRoa {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//------------ RoaConfigurations -------------------------------------------

/// This type defines a list of ConfiguredRoa so that we can have
/// an easy fmt::Display implementation to use in the CLI report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfiguredRoas(Vec<ConfiguredRoa>);

impl fmt::Display for ConfiguredRoas {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for def in self.0.iter() {
            writeln!(f, "{}", def)?;
        }
        Ok(())
    }
}

//------------ RoaConfigurationUpdates -------------------------------------

/// This type defines a delta of RoaDefinitions submitted through the API.
///
/// Multiple updates are sent as a single delta, because it's important that
/// all authorizations for a given prefix are published together in order to
/// avoid invalidating announcements.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaConfigurationUpdates {
    added: Vec<RoaConfiguration>,
    removed: Vec<RoaPayload>,
}

impl RoaConfigurationUpdates {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    pub fn new(added: Vec<RoaConfiguration>, removed: Vec<RoaPayload>) -> Self {
        RoaConfigurationUpdates { added, removed }
    }

    /// Ensures that an explicit (canonical) max length is used.
    pub fn into_explicit_max_length(self) -> Self {
        let added = self.added.into_iter().map(|a| a.into_explicit_max_length()).collect();
        let removed = self.removed.into_iter().map(|r| r.into_explicit_max_length()).collect();

        RoaConfigurationUpdates { added, removed }
    }

    /// Reports the resources included in these updates.
    pub fn affected_prefixes(&self) -> ResourceSet {
        let mut resources = ResourceSet::default();
        for roa_config in &self.added {
            resources = resources.union(&roa_config.payload().prefix().into());
        }
        for roa_payload in &self.removed {
            resources = resources.union(&roa_payload.prefix().into());
        }
        resources
    }

    /// Unpack this and return all added (left), and all removed (right) route
    /// authorizations.
    pub fn unpack(self) -> (Vec<RoaConfiguration>, Vec<RoaPayload>) {
        (self.added, self.removed)
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn add(&mut self, add: RoaConfiguration) {
        self.added.push(add);
    }

    pub fn added(&self) -> &Vec<RoaConfiguration> {
        &self.added
    }

    pub fn removed(&self) -> &Vec<RoaPayload> {
        &self.removed
    }

    pub fn remove(&mut self, rem: RoaPayload) {
        self.removed.push(rem);
    }
}

impl fmt::Display for RoaConfigurationUpdates {
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

impl FromStr for RoaConfigurationUpdates {
    type Err = AuthorizationFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut added = vec![];
        let mut removed = vec![];

        for line in s.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            } else if let Some(stripped) = line.strip_prefix("A:") {
                let auth = RoaConfiguration::from_str(stripped.trim())?;
                added.push(auth);
            } else if let Some(stripped) = line.strip_prefix("R:") {
                // ignore comments on remove lines
                if let Some(payload_str) = stripped.split('#').next() {
                    let auth = RoaPayload::from_str(payload_str.trim())?;
                    removed.push(auth);
                } else {
                    return Err(AuthorizationFmtError::delta(line));
                }
            } else {
                return Err(AuthorizationFmtError::delta(line));
            }
        }

        Ok(RoaConfigurationUpdates { added, removed })
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

                ResourceSet::new(AsBlocks::empty(), blocks.into(), IpBlocks::empty().into())
            }
            TypedPrefix::V6(v6) => {
                let mut builder = IpBlocksBuilder::new();
                builder.push(v6.0);
                let blocks = builder.finalize();

                ResourceSet::new(AsBlocks::empty(), IpBlocks::empty().into(), blocks.into())
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

impl From<AsNumber> for Asn {
    fn from(asn: AsNumber) -> Self {
        Asn::from(asn.0)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationFmtError {
    Pfx(String),
    Asn(String),
    Auth(String),
    Delta(String),
}

impl fmt::Display for AuthorizationFmtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthorizationFmtError::Pfx(s) => write!(f, "Invalid prefix string: {}", s),
            AuthorizationFmtError::Asn(s) => write!(f, "Invalid asn in string: {}", s),
            AuthorizationFmtError::Auth(s) => write!(f, "Invalid authorization string: {}", s),
            AuthorizationFmtError::Delta(s) => write!(f, "Invalid authorization delta string: {}", s),
        }
    }
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

    use crate::test::{roa_configuration, roa_payload};

    #[test]
    fn parse_delta() {
        let delta = concat!(
            "# Some comment\n",
            "  # Indented comment\n",
            "\n", // empty line
            "A: 192.168.0.0/16 => 64496 # ROA comment\n",
            "A: 192.168.1.0/24 => 64496\n",
            "R: 192.168.3.0/24 => 64496 # ignored comment for removed ROA\n",
        );

        let expected = {
            let added = vec![
                roa_configuration("192.168.0.0/16 => 64496 # ROA comment"),
                roa_configuration("192.168.1.0/24 => 64496"),
            ];

            let removed = vec![roa_payload("192.168.3.0/24 => 64496")];
            RoaConfigurationUpdates::new(added, removed)
        };

        let parsed = RoaConfigurationUpdates::from_str(delta).unwrap();
        assert_eq!(expected, parsed);

        let re_parsed = RoaConfigurationUpdates::from_str(&parsed.to_string()).unwrap();
        assert_eq!(parsed, re_parsed);
    }

    #[test]
    fn parse_type_prefix() {
        assert!(TypedPrefix::from_str("192.168.0.0/16").is_ok());
        assert!(TypedPrefix::from_str("2001:db8::/32").is_ok());
    }

    #[test]
    fn normalize_roa_definition_json() {
        let def = roa_payload("192.168.0.0/16 => 64496");
        let json = serde_json::to_string(&def).unwrap();
        let expected = "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\"}";
        assert_eq!(json, expected);

        let def = roa_payload("192.168.0.0/16-24 => 64496");
        let json = serde_json::to_string(&def).unwrap();
        let expected = "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\",\"max_length\":24}";
        assert_eq!(json, expected);
    }

    #[test]
    fn serde_roa_configuration() {
        fn parse_ser_de_print_configuration(s: &str) {
            let def = roa_configuration(s);
            let ser = serde_json::to_string(&def).unwrap();
            let de = serde_json::from_str(&ser).unwrap();
            assert_eq!(def, de);
            assert_eq!(s, de.to_string().as_str())
        }

        parse_ser_de_print_configuration("192.168.0.0/16 => 64496 # comment");
        parse_ser_de_print_configuration("192.168.0.0/16-24 => 64496");
        parse_ser_de_print_configuration("2001:db8::/32 => 64496 # comment with extra #");
        parse_ser_de_print_configuration("2001:db8::/32-48 => 64496");
    }

    #[test]
    fn serde_roa_payload() {
        fn parse_ser_de_print_payload(s: &str) {
            let def = roa_payload(s);
            let ser = serde_json::to_string(&def).unwrap();
            let de = serde_json::from_str(&ser).unwrap();
            assert_eq!(def, de);
            assert_eq!(s, de.to_string().as_str())
        }

        parse_ser_de_print_payload("192.168.0.0/16 => 64496");
        parse_ser_de_print_payload("192.168.0.0/16-24 => 64496");
        parse_ser_de_print_payload("2001:db8::/32 => 64496");
        parse_ser_de_print_payload("2001:db8::/32-48 => 64496");
    }

    #[test]
    fn roa_max_length() {
        fn valid_max_length(s: &str) {
            let def = RoaPayload::from_str(s).unwrap();
            assert!(def.max_length_valid())
        }

        fn invalid_max_length(s: &str) {
            let def = RoaPayload::from_str(s).unwrap();
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
        let covering = roa_payload("192.168.0.0/16-20 => 64496");

        let included_no_ml = roa_payload("192.168.0.0/16 => 64496");
        let included_more_specific = roa_payload("192.168.0.0/20 => 64496");

        let allowing_more_specific = roa_payload("192.168.0.0/16-24 => 64496");
        let more_specific = roa_payload("192.168.3.0/24 => 64496");
        let other_asn = roa_payload("192.168.3.0/24 => 64497");

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
    fn roa_nr_specific_pfx() {
        fn check(def: &str, expected: u128) {
            let def = roa_payload(def);
            let calculated = def.nr_of_specific_prefixes();
            assert_eq!(calculated, expected);
        }

        check("10.0.0.0/15-15 => 64496", 1);
        check("10.0.0.0/15-16 => 64496", 2);
        check("10.0.0.0/15-17 => 64496", 4);
        check("10.0.0.0/15-18 => 64496", 8);
    }
}
