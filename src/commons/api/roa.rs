//! Route origin authorizations.

use std::{error, fmt};
use std::cmp::Ordering;
use std::net::IpAddr;
use std::str::FromStr;
use rpki::uri;
use rpki::ca::publication::Base64;
use rpki::repository::resources::{
    AsBlocks, Asn, IpBlocks, IpBlocksBuilder, Prefix, ResourceSet,
};
use rpki::repository::roa::{Roa, RoaIpAddress};
use rpki::repository::x509::{Serial, Time, Validity};
use rpki::rrdp::Hash;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use super::bgp::BgpAnalysisSuggestion;
use super::ca::Revocation;


//------------ RoaPayload ----------------------------------------------------

/// The definition of a Route Origin Authorization (ROA) payload.
///
/// We define “ROA payload” to be the originating ASN, a single prefix, and
/// an optional max prefix length.
///
/// An RFC 6482 ROA object may contain multiple prefixes and optional max
/// length values, aggregated by (a single) ASN. The term "Validated ROA
/// Payload" is used in RFC 6811 (BGP Prefix Origin Validation) to describe
/// validated tuples of ASN, Prefix and optional Max Length.
///
/// Note that Krill does not allow users to specify RFC 6482 ROA objects
/// as such. Instead it allows users to configure the intent which
/// "ROA Payloads" should be authorized. We could call this type
/// RoaPayloadIntent, but we stuck with RoaPayload for brevity.
///
/// Krill will create RFC 6482 for RoaPayloads appearing on saved
/// configurations – in as far as the CA holds the prefixes on its
/// certificate(s). It will prefer to issue a single object per payload in
/// accordance with best practices (avoid fate sharing in case a prefix is
/// suddenly no longer held), but aggregation will be done if a
/// (configurable) threshold is exceeded.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaPayload {
    /// The autonomous system authorized to originate routes.
    pub asn: AsNumber,

    /// The prefix the system is authorized to originate routes for.
    pub prefix: TypedPrefix,

    /// The maximum prefix length for authorized originated routes.
    ///
    /// If this is `None`, then it is considered to be the length of the
    /// `prefix`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u8>,
}

impl RoaPayload {
    fn set_explicit_max_length(&mut self) {
        self.max_length = Some(self.effective_max_length());
    }

    /// Ensures that the payload uses an explicit max length
    pub fn into_explicit_max_length(self) -> Self {
        Self {
            asn: self.asn,
            prefix: self.prefix,
            max_length: Some(self.effective_max_length())
        }
    }

    /// Converts the prefix and max length into a `RoaIpAddress`.
    pub fn as_roa_ip_address(self) -> RoaIpAddress {
        RoaIpAddress::new(self.prefix.prefix(), self.max_length)
    }

    /// Returns the effective max length.
    ///
    /// This is `self.max_length` if it is explicitely given or the prefix
    /// length of `self.prefix` otherwise.
    pub fn effective_max_length(&self) -> u8 {
        match self.max_length {
            None => self.prefix.addr_len(),
            Some(len) => len,
        }
    }

    /// Returns the number of prefixes covered by this payload.
    ///
    /// If the max length is identical to the prefix length (or not given),
    /// this will be one, otherwise it grows exponentially very quickly.
    pub fn nr_of_specific_prefixes(&self) -> u128 {
        let pfx_len = self.prefix.addr_len();
        let max_len = self.effective_max_length();

        // 10.0.0.0/8-8 -> 1   2^0
        // 10.0.0.0/8-9 -> 2   2^1
        // 10.0.0.0/8-10 -> 4  2^2
        // 10.0.0.0/8-11 -> 8  2^3

        1u128 << (max_len - pfx_len)
    }

    /// Returns whether the max length is valid.
    ///
    /// It is valid if it is not smaller than the prefix’s length and not
    /// larger than the maximum prefix length of the address family.
    pub fn max_length_valid(&self) -> bool {
        if let Some(max_length) = self.max_length {
            match self.prefix {
                TypedPrefix::V4(_) => {
                    max_length >= self.prefix.addr_len() && max_length <= 32
                }
                TypedPrefix::V6(_) => {
                    max_length >= self.prefix.addr_len() && max_length <= 128
                }
            }
        } else {
            true
        }
    }

    /// Returns whether this definition includes the other definition.
    pub fn includes(&self, other: RoaPayload) -> bool {
        self.asn == other.asn
            && self.prefix.matching_or_less_specific(other.prefix)
            && self.effective_max_length() >= other.effective_max_length()
    }

    /// Returns whether if this is an AS0 definition which overlaps the other.
    pub fn overlaps(&self, other: RoaPayload) -> bool {
        self.prefix.matching_or_less_specific(other.prefix)
            || other.prefix.matching_or_less_specific(self.prefix)
    }
}


//--- FromStr

impl FromStr for RoaPayload {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("=>");

        let prefix_part =
            parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
        let mut prefix_parts = prefix_part.split('-');
        let prefix_str = prefix_parts
            .next()
            .ok_or_else(|| AuthorizationFmtError::auth(s))?;

        let prefix = TypedPrefix::from_str(prefix_str.trim())?;

        let max_length = match prefix_parts.next() {
            None => None,
            Some(length_str) => Some(
                u8::from_str(length_str.trim())
                    .map_err(|_| AuthorizationFmtError::auth(s))?,
            ),
        };

        let asn_str =
            parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;
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


//--- PartialOrd and Ord

impl PartialOrd for RoaPayload {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RoaPayload {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.prefix.cmp(&other.prefix);

        if ordering == Ordering::Equal {
            ordering = self
                .effective_max_length()
                .cmp(&other.effective_max_length());
        }

        if ordering == Ordering::Equal {
            ordering = self.asn.cmp(&other.asn);
        }

        ordering
    }
}


//--- Display and Debug

impl fmt::Display for RoaPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.max_length {
            None => write!(f, "{} => {}", self.prefix, self.asn),
            Some(length) => {
                write!(f, "{}-{} => {}", self.prefix, length, self.asn)
            }
        }
    }
}

impl fmt::Debug for RoaPayload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RoaPayload({})", &self)
    }
}


//------------ RoaPayloadJsonMapKey ------------------------------------------

/// A [`RoaPayload`] that serializes as a string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
pub struct RoaPayloadJsonMapKey(RoaPayload);

impl RoaPayloadJsonMapKey {
    pub fn asn(self) -> AsNumber {
        self.0.asn
    }
}


impl From<RoaPayload> for RoaPayloadJsonMapKey {
    fn from(def: RoaPayload) -> Self {
        RoaPayloadJsonMapKey(def)
    }
}

impl From<RoaPayloadJsonMapKey> for RoaPayload {
    fn from(auth: RoaPayloadJsonMapKey) -> Self {
        auth.0
    }
}

impl AsRef<RoaPayload> for RoaPayloadJsonMapKey {
    fn as_ref(&self) -> &RoaPayload {
        &self.0
    }
}

impl fmt::Display for RoaPayloadJsonMapKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for RoaPayloadJsonMapKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(s)
    }
}

impl<'de> Deserialize<'de> for RoaPayloadJsonMapKey {
    fn deserialize<D>(d: D) -> Result<RoaPayloadJsonMapKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(
            RoaPayload::from_str(
                &String::deserialize(d)?
            ).map_err(de::Error::custom)?
        ))
    }
}

//------------ RoaConfiguration ----------------------------------------------

/// This type defines an *intended* configuration for a ROA.
///
/// This type is intended to be used for updates through the API.
///
/// It includes the actual ROA payload that needs be authorized on an RFC 6482
/// ROA object, as well as other information that is only visible to Krill
/// users – like the optional comment field, which can be used to store useful
/// reminders of the purpose of this configuration. And in future perhaps
/// other things such as tags used for classification/monitoring/bpp analysis
/// could be added.
///
/// Note that the [`ConfiguredRoa`] type defines an *existing* configured ROA.
/// Existing ROAs may contain other information that the Krill system is
/// responsible for, rather than the API (update) user. For example: which ROA
/// object(s) the intended configuration appears on.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaConfiguration {
    /// The ROA payload definition.
    ///
    /// We flatten the payload and have defaults for other fields, so
    /// that the JSON serialized representation can be backward compatible
    /// with the RoaDefinition type that was used until Krill 0.10.0.
    ///
    /// I.e:
    /// * The API can still accept the 'old' style JSON without comments
    /// * We do not need to do data migrations on upgrade
    /// * The query API will include an extra field ("comment"), but most API
    ///   users will ignore additional fields.
    #[serde(flatten)]
    pub payload: RoaPayload,

    /// An optional comment for the ROA configuration.
    #[serde(default)] // missing is same as no comment
    pub comment: Option<String>,
}

impl RoaConfiguration {
    /// Converts that the payload into one with an explicit max length.
    pub fn set_explicit_max_length(&mut self) {
        self.payload.set_explicit_max_length();
    }
}

//--- From and FromStr

impl From<RoaPayload> for RoaConfiguration {
    fn from(payload: RoaPayload) -> Self {
        RoaConfiguration {
            payload,
            comment: None,
        }
    }
}

impl FromStr for RoaConfiguration {
    type Err = AuthorizationFmtError;

    // "192.168.0.0/16 => 64496"
    // "192.168.0.0/16 => 64496 # my nice ROA"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, '#');
        let payload_part =
            parts.next().ok_or_else(|| AuthorizationFmtError::auth(s))?;

        let payload = RoaPayload::from_str(payload_part)?;
        let comment = parts.next().map(|s| s.trim().to_string());

        Ok(RoaConfiguration { payload, comment })
    }
}


//--- PartialOrd and Ord

impl PartialOrd for RoaConfiguration {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RoaConfiguration {
    fn cmp(&self, other: &Self) -> Ordering {
        self.payload.cmp(&other.payload)
    }
}


//--- Display

impl fmt::Display for RoaConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.payload)?;
        if let Some(comment) = &self.comment {
            write!(f, " # {}", comment)?;
        }
        Ok(())
    }
}


//------------ RoaInfo -------------------------------------------------------

/// Information about a ROA *object.*
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaInfo {
    /// The route or routes authorized by this ROA
    pub authorizations: Vec<RoaPayloadJsonMapKey>,

    /// The validity time for this ROA.
    pub validity: Validity,

    /// The serial number (needed for revocation)
    pub serial: Serial,

    /// The URI where this object is expected to be published
    pub uri: uri::Rsync,

    /// The actual ROA in base64 format.
    pub base64: Base64,

    /// The ROA's hash
    pub hash: Hash,
}

impl RoaInfo {
    /// Creates a new ROA info value.
    pub fn new(authorizations: Vec<RoaPayloadJsonMapKey>, roa: Roa) -> Self {
        let validity = roa.cert().validity();
        let serial = roa.cert().serial_number();
        let uri = roa.cert().signed_object().unwrap().clone(); // safe for our own ROAs
        let base64 = Base64::from(&roa);
        let hash = base64.to_hash();

        RoaInfo {
            authorizations,
            validity,
            serial,
            uri,
            base64,
            hash,
        }
    }

    /// Returns when the ROA object expires.
    pub fn expires(&self) -> Time {
        self.validity.not_after()
    }

    /// Returns a revocation entry for this ROA.
    pub fn revoke(&self) -> Revocation {
        Revocation::new(self.serial, self.validity.not_after())
    }
}


//------------ ConfiguredRoa -------------------------------------------------

/// Defines an existing ROA configuration.
///
/// This type is used in the API for listing/reporting.
///
/// It contains the user determined intended RoaConfiguration as well as
/// system determined things, like the roa objects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfiguredRoa {
    /// The intended ROA configuration.
    #[serde(flatten)]
    pub roa_configuration: RoaConfiguration,

    /// The ROA objects generated from the configuration.
    pub roa_objects: Vec<RoaInfo>,
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

impl fmt::Display for ConfiguredRoa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.roa_configuration)
    }
}


//------------ RoaConfigurations --------------------------------------------

/// A list of [`ConfiguredRoa`]s.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfiguredRoas(Vec<ConfiguredRoa>);

impl ConfiguredRoas {
    pub fn into_vec(self) -> Vec<ConfiguredRoa> {
        self.0
    }
}

impl fmt::Display for ConfiguredRoas {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for def in self.0.iter() {
            writeln!(f, "{}", def)?;
        }
        Ok(())
    }
}

//------------ RoaConfigurationUpdates ---------------------------------------

/// A delta of RoaDefinitions submitted through the API.
///
/// Multiple updates are sent as a single delta, because it's important that
/// all authorizations for a given prefix are published together in order to
/// avoid invalidating announcements.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaConfigurationUpdates {
    /// The ROA configurations to be added.
    pub added: Vec<RoaConfiguration>,

    /// The ROA payloads to be removed.
    pub removed: Vec<RoaPayload>,
}

impl RoaConfigurationUpdates {
    /// Returns whether the update is empty.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Ensures that an explicit (canonical) max length is used.
    pub fn set_explicit_max_length(&mut self) {
        self.added.iter_mut().for_each(|x| x.set_explicit_max_length());
        self.removed.iter_mut().for_each(|x| x.set_explicit_max_length());
    }

    /// Reports the resources included in these updates.
    pub fn affected_prefixes(&self) -> ResourceSet {
        let mut resources = ResourceSet::default();
        for roa_config in &self.added {
            resources = resources.union(&roa_config.payload.prefix.into());
        }
        for roa_payload in &self.removed {
            resources = resources.union(&roa_payload.prefix.into());
        }
        resources
    }
}

impl From<BgpAnalysisSuggestion> for RoaConfigurationUpdates {
    fn from(suggestion: BgpAnalysisSuggestion) -> Self {
        let mut added: Vec<RoaConfiguration> = vec![];
        let mut removed: Vec<RoaPayload> = vec![];

        for announcement in suggestion.not_found
            .into_iter()
            .chain(suggestion.invalid_asn.into_iter())
            .chain(suggestion.invalid_length.into_iter())
        {
            added.push(RoaConfiguration {
                payload: announcement.into(),
                comment: None
            });
        }

        for stale in suggestion.stale {
            removed.push(stale.roa_configuration.payload);
        }

        for suggestion in suggestion.too_permissive.into_iter() {
            removed.push(suggestion.current.roa_configuration.payload);
            for payload in suggestion.new.into_iter() {
                added.push(RoaConfiguration { payload, comment: None });
            }
        }

        for as0_redundant in suggestion.as0_redundant.into_iter() {
            removed.push(as0_redundant.roa_configuration.payload);
        }

        for redundant in suggestion.redundant.into_iter() {
            removed.push(redundant.roa_configuration.payload);
        }

        RoaConfigurationUpdates { added, removed }
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


//------------ TypedPrefix ---------------------------------------------------

/// A prefix that knows which family it belongs to.
///
/// This type serializes into the string representation of the prefix.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub enum TypedPrefix {
    /// An IPv4 prefix.
    V4(Ipv4Prefix),

    /// An IPv6 prefix.
    V6(Ipv6Prefix),
}

impl TypedPrefix {
    /// Converts the types prefix into an untyped prefix.
    pub fn prefix(self) -> Prefix {
        match self {
            Self::V4(prefix) => prefix.into(),
            Self::V6(prefix) => prefix.into(),
        }
    }

    /// Returns the IP address part of the prefix.
    pub fn ip_addr(&self) -> IpAddr {
        match self {
            Self::V4(v4) => IpAddr::V4(v4.0.to_v4()),
            Self::V6(v6) => IpAddr::V6(v6.0.to_v6()),
        }
    }

    /// Returns the prefix length of the prefix.
    pub fn addr_len(&self) -> u8 {
        self.prefix().addr_len()
    }

    /// Returns whether `other` is of the same address family.
    fn matches_type(self, other: TypedPrefix) -> bool {
        match self {
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

    /// Returns whether the prefix is the same or less specific.
    pub fn matching_or_less_specific(self, other: TypedPrefix) -> bool {
        self.matches_type(other)
            && self.prefix().min().le(&other.prefix().min())
            && self.prefix().max().ge(&other.prefix().max())
    }
}


//--- From and FromStr

impl From<Ipv4Prefix> for TypedPrefix {
    fn from(prefix: Ipv4Prefix) -> Self {
        TypedPrefix::V4(prefix)
    }
}

impl From<Ipv6Prefix> for TypedPrefix {
    fn from(prefix: Ipv6Prefix) -> Self {
        TypedPrefix::V6(prefix)
    }
}

impl From<TypedPrefix> for ResourceSet {
    fn from(tp: TypedPrefix) -> ResourceSet {
        match tp {
            TypedPrefix::V4(v4) => {
                let mut builder = IpBlocksBuilder::new();
                builder.push(v4.0);
                let blocks = builder.finalize();

                ResourceSet::new(
                    AsBlocks::empty(),
                    blocks.into(),
                    IpBlocks::empty().into(),
                )
            }
            TypedPrefix::V6(v6) => {
                let mut builder = IpBlocksBuilder::new();
                builder.push(v6.0);
                let blocks = builder.finalize();

                ResourceSet::new(
                    AsBlocks::empty(),
                    IpBlocks::empty().into(),
                    blocks.into(),
                )
            }
        }
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


//--- PartialOrd and Ord

impl PartialOrd for TypedPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TypedPrefix {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.prefix().addr().cmp(&other.prefix().addr());
        if ordering == Ordering::Equal {
            ordering = self.addr_len().cmp(&other.addr_len())
        }
        ordering
    }
}


//--- Display and Debug

impl fmt::Display for TypedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TypedPrefix::V4(pfx) => pfx.fmt(f),
            TypedPrefix::V6(pfx) => pfx.fmt(f),
        }
    }
}

impl fmt::Debug for TypedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}


//--- Deserialize and Serialize

impl<'de> Deserialize<'de> for TypedPrefix {
    fn deserialize<D>(d: D) -> Result<TypedPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        TypedPrefix::from_str(string.as_str()).map_err(de::Error::custom)
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


//------------ Ipv4Prefix ----------------------------------------------------

/// An IPv4 prefix.
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

impl From<Prefix> for Ipv4Prefix {
    fn from(prefix: Prefix) -> Self {
        Ipv4Prefix(prefix)
    }
}

impl From<Ipv4Prefix> for Prefix {
    fn from(prefix: Ipv4Prefix) -> Self {
        prefix.0
    }
}

//------------ Ipv6Prefix ----------------------------------------------------

/// An IPv6 prefix.
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

impl From<Prefix> for Ipv6Prefix {
    fn from(prefix: Prefix) -> Self {
        Ipv6Prefix(prefix)
    }
}

impl From<Ipv6Prefix> for Prefix {
    fn from(prefix: Ipv6Prefix) -> Self {
        prefix.0
    }
}


//------------ AsNumber ------------------------------------------------------

/// An autonomous system number.
#[derive(
    Clone, Copy, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize,
)]
pub struct AsNumber(u32);

impl AsNumber {
    /// The special autonomous system AS0.
    pub const AS0: Self = Self::from_u32(0);

    /// Creates an AS number from the integer.
    pub const fn from_u32(number: u32) -> Self {
        AsNumber(number)
    }
}


//--- From and FromStr

impl From<AsNumber> for Asn {
    fn from(asn: AsNumber) -> Self {
        Asn::from(asn.0)
    }
}

impl FromStr for AsNumber {
    type Err = AuthorizationFmtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let number =
            u32::from_str(s).map_err(|_| AuthorizationFmtError::asn(s))?;
        Ok(AsNumber(number))
    }
}


//--- Display and Debug

impl fmt::Display for AsNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for AsNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self)
    }
}


//============ Error Types ===================================================


//------------ AuthorizationFmtError -----------------------------------------

/// An error happened when parsing a ROA
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationFmtError {
    /// The prefix string is invalid.
    Pfx(String),

    /// An ASN is invalid.
    Asn(String),

    /// An authorization string is invalid.
    Auth(String),

    /// A delta string is invalid.
    Delta(String),
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

    fn delta(s: &str) -> Self {
        AuthorizationFmtError::Delta(s.to_string())
    }
}

impl fmt::Display for AuthorizationFmtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthorizationFmtError::Pfx(s) => {
                write!(f, "Invalid prefix string: {}", s)
            }
            AuthorizationFmtError::Asn(s) => {
                write!(f, "Invalid asn in string: {}", s)
            }
            AuthorizationFmtError::Auth(s) => {
                write!(f, "Invalid authorization string: {}", s)
            }
            AuthorizationFmtError::Delta(s) => {
                write!(f, "Invalid authorization delta string: {}", s)
            }
        }
    }
}

impl error::Error for AuthorizationFmtError { }


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use crate::test::{roa_configuration, roa_payload};
    use super::*;


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
            RoaConfigurationUpdates { added, removed }
        };

        let parsed = RoaConfigurationUpdates::from_str(delta).unwrap();
        assert_eq!(expected, parsed);

        let re_parsed =
            RoaConfigurationUpdates::from_str(&parsed.to_string()).unwrap();
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
        let expected =
            "{\"asn\":64496,\"prefix\":\"192.168.0.0/16\",\"max_length\":24}";
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
        parse_ser_de_print_configuration(
            "2001:db8::/32 => 64496 # comment with extra #",
        );
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

        let allowing_more_specific =
            roa_payload("192.168.0.0/16-24 => 64496");
        let more_specific = roa_payload("192.168.3.0/24 => 64496");
        let other_asn = roa_payload("192.168.3.0/24 => 64497");

        assert!(covering.includes(included_no_ml));
        assert!(covering.includes(included_more_specific));

        assert!(!covering.includes(more_specific));
        assert!(!covering.includes(allowing_more_specific));
        assert!(!covering.includes(other_asn));
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

