//! The BGP analyser.

use std::{error, fmt};
use std::collections::HashMap;
use std::ops::Range;
use std::str::FromStr;
use intervaltree::IntervalTree;
use rpki::repository::resources::{Addr, AddressRange, ResourceSet};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::api::bgp::{
    Announcement, BgpAnalysisEntry, BgpAnalysisReport, BgpAnalysisState,
    BgpAnalysisSuggestion, ReplacementRoaSuggestion,
};
use crate::api::roa::{
    AsNumber, ConfiguredRoa, Ipv4Prefix, Ipv6Prefix, RoaPayload, TypedPrefix,
};


//------------ BgpAnalyser -------------------------------------------------

/// The BGP analyser to check the consequence of ROAs in the global BGP.
pub struct BgpAnalyser {
    /// Should we actually use the BGP API.
    bgp_api_enabled: bool,

    /// The base URI of the BGP API.
    bgp_api_uri: String,

    /// The HTTP client to talk to the BGP API with.
    client: reqwest::Client,
}

impl BgpAnalyser {
    /// Creates a new BGP analyser from the BGP API details.
    pub fn new(
        bgp_api_enabled: bool,
        bgp_api_uri: String,
    ) -> Self {
        BgpAnalyser {
            bgp_api_enabled,
            bgp_api_uri,
            client: reqwest::Client::new(),
        }
    }

    /// Creates a BGP analyisis report for the given ROAs and resources.
    pub async fn analyse(
        &self,
        roas: &[ConfiguredRoa],
        resources_held: &ResourceSet,
        limited_scope: Option<ResourceSet>,
    ) -> BgpAnalysisReport {
        let mut entries = Vec::new();

        // Create a list of the ROAs that are contained in the held
        // resources but not in the limited scope. Everything that is in
        // neither goes directly into the `entries` as ‘not held.’
        let mut roas_held = Vec::new();
        for roa in roas {
            if let Some(limit) = limited_scope.as_ref() {
                if !limit.contains_roa_address(
                    &roa.roa_configuration.payload.as_roa_ip_address()
                ) {
                    continue
                }
            }

            if resources_held.contains_roa_address(
                &roa.roa_configuration.payload.as_roa_ip_address()
            ) {
                roas_held.push(roa.clone());
            }
            else {
                entries.push(BgpAnalysisEntry::roa_not_held(roa.clone()));
            }
        }

        if !self.bgp_api_enabled {
            // Nothing to analyse. Push all ROAs as ‘no announcement info.’
            entries.extend(
                roas_held.into_iter().map(|roa| {
                    BgpAnalysisEntry::roa_no_announcement_info(roa)
                })
            );
            return BgpAnalysisReport::new(entries);
        }

        // Now get all the necessary data from BGP API.
        //
        // Return early if this failed.
        let scope = IpRange::from_resource_set(
            match &limited_scope {
                Some(limit) => limit,
                None => resources_held,
            }
        );

        let mut scoped_announcements: Vec<Announcement> = vec![];
        for block in scope.into_iter() {
            let announcements = self.retrieve(block).await;
            if let Ok(mut announcements) = announcements {
                scoped_announcements.append(
                    announcements.as_mut());
            }
            else {
                entries.extend(
                    roas_held.into_iter().map(|roa| {
                        BgpAnalysisEntry::roa_no_announcement_info(roa)
                    })
                );
                return BgpAnalysisReport::new(entries);
            }
        }

        let roa_tree = IpRangeStore::create(
            roas_held.iter().map(|configured| {
                let payload = configured.roa_configuration.payload;
                (payload.prefix.into(), payload)
            })
        );
        let validated: Vec<ValidatedAnnouncement> = scoped_announcements
            .into_iter()
            .map(|a| roa_tree.validate_announcement(a))
            .collect();

        // Check all ROAs.. and report ROA state in relation to validated
        // announcements
        let validated_tree = IpRangeStore::create(
            validated.iter().map(|v| (v.announcement.prefix.into(), v.clone()))
        );
        for roa in roas_held {
            let covered = validated_tree.matching_or_more_specific(
                roa.roa_configuration.payload.prefix
            );

            let other_roas_covering_this_prefix: Vec<_> = roa_tree
                .matching_or_less_specific(
                    roa.roa_configuration.payload.prefix
                )
                .into_iter()
                .filter(|other| roa.roa_configuration.payload != **other)
                .cloned()
                .collect();

            let other_roas_including_this_definition: Vec<_> =
                other_roas_covering_this_prefix
                    .iter()
                    .filter(|other| {
                        other.asn == roa.roa_configuration.payload.asn
                            && other.prefix.addr_len()
                                <= roa.roa_configuration.payload
                                        .prefix.addr_len()
                            && other.effective_max_length()
                                >= roa.roa_configuration.payload
                                        .effective_max_length()
                    })
                    .cloned()
                    .collect();

            let authorizes: Vec<Announcement> = covered
                .iter()
                .filter(|va| {
                    // VALID announcements under THIS ROA
                    // Already covered so it's under this ROA prefix
                    // ASN must match
                    // Prefix length must be allowed under this ROA (it
                    // could be allowed by another ROA and therefore
                    // valid)
                    va.validity == AnnouncementValidity::Valid
                        && va.announcement.prefix.addr_len()
                            <= roa.roa_configuration.payload
                                    .effective_max_length()
                        && va.announcement.asn
                            == roa.roa_configuration.payload.asn
                })
                .map(|va| va.announcement)
                .collect();

            let disallows: Vec<Announcement> = covered
                .iter()
                .filter(|va| {
                    let validity = va.validity;
                    validity == AnnouncementValidity::InvalidLength
                        || validity == AnnouncementValidity::InvalidAsn
                })
                .map(|va| va.announcement)
                .collect();

            let authorizes_excess = {
                let max_length =
                    roa.roa_configuration.payload.effective_max_length();
                let nr_of_specific_ann = authorizes
                    .iter()
                    .filter(|ann| ann.prefix.addr_len() == max_length)
                    .count()
                    as u128;

                nr_of_specific_ann > 0
                    && nr_of_specific_ann
                            < roa.roa_configuration.payload
                                    .nr_of_specific_prefixes()
            };

            if roa.roa_configuration.payload.asn == AsNumber::AS0 {
                // see if this AS0 ROA is redundant, if it is mark it as
                // such
                if other_roas_covering_this_prefix.is_empty() {
                    // will disallow all covered announcements by
                    // definition (because AS0 announcements cannot exist)
                    let announcements = covered
                        .iter()
                        .map(|va| va.announcement)
                        .collect();
                    entries.push(BgpAnalysisEntry::roa_as0(
                        roa,
                        announcements,
                    ));
                } else {
                    entries.push(BgpAnalysisEntry::roa_as0_redundant(
                        roa,
                        other_roas_covering_this_prefix,
                    ));
                }
            } else if !other_roas_including_this_definition.is_empty() {
                entries.push(BgpAnalysisEntry::roa_redundant(
                    roa,
                    authorizes,
                    disallows,
                    other_roas_including_this_definition,
                ))
            } else if authorizes.is_empty() && disallows.is_empty() {
                entries.push(BgpAnalysisEntry::roa_unseen(roa))
            } else if authorizes_excess {
                entries.push(BgpAnalysisEntry::roa_too_permissive(
                    roa, authorizes, disallows,
                ))
            } else if authorizes.is_empty() {
                entries.push(BgpAnalysisEntry::roa_disallowing(
                    roa, disallows,
                ))
            } else {
                entries.push(BgpAnalysisEntry::roa_seen(
                    roa, authorizes, disallows,
                ))
            }
        }

        // Loop over all validated announcements and report
        for v in validated.into_iter() {
            match v.validity {
                AnnouncementValidity::Valid => {
                    entries.push(BgpAnalysisEntry::announcement_valid(
                        v.announcement,
                        v.authorizing.unwrap(), /* always set for valid
                                                * announcements */
                    ))
                }
                AnnouncementValidity::Disallowed => {
                    entries.push(
                        BgpAnalysisEntry::announcement_disallowed(
                            v.announcement,
                            v.disallowing,
                        ),
                    );
                }
                AnnouncementValidity::InvalidLength => {
                    entries.push(
                        BgpAnalysisEntry::announcement_invalid_length(
                            v.announcement,
                            v.disallowing,
                        ),
                    );
                }
                AnnouncementValidity::InvalidAsn => {
                    entries.push(
                        BgpAnalysisEntry::announcement_invalid_asn(
                            v.announcement,
                            v.disallowing,
                        ),
                    );
                }
                AnnouncementValidity::NotFound => {
                    entries.push(
                        BgpAnalysisEntry::announcement_not_found(
                            v.announcement,
                        ),
                    );
                }
            }
        }

        BgpAnalysisReport::new(entries)
    }

    /// Returns suggestions for the given ROAs and resources.
    pub async fn suggest(
        &self,
        roas: &[ConfiguredRoa],
        resources_held: &ResourceSet,
        limited_scope: Option<ResourceSet>,
    ) -> BgpAnalysisSuggestion {
        let mut suggestion = BgpAnalysisSuggestion::default();

        // perform analysis
        let entries = self
            .analyse(roas, resources_held, limited_scope)
            .await
            .into_entries();
        for entry in &entries {
            match entry.state() {
                BgpAnalysisState::RoaUnseen => {
                    suggestion.stale.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaTooPermissive => {
                    let replace_with = entry
                        .authorizes()
                        .iter()
                        .filter(|ann| {
                            !entries.iter().any(|other| {
                                other != entry
                                    && other.authorizes().contains(*ann)
                            })
                        })
                        .map(|auth| RoaPayload::from(*auth))
                        .collect();

                    suggestion.too_permissive.push(
                        ReplacementRoaSuggestion {
                            current: entry.configured_roa().clone(),
                            new: replace_with,
                        }
                    );
                }
                BgpAnalysisState::RoaSeen | BgpAnalysisState::RoaAs0 => {
                    suggestion.keep.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaDisallowing => {
                    suggestion.disallowing.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaRedundant => {
                    suggestion.redundant.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaNotHeld => {
                    suggestion.not_held.push(entry.configured_roa().clone())
                }
                BgpAnalysisState::RoaAs0Redundant => {
                    suggestion.as0_redundant.push(
                        entry.configured_roa().clone()
                    )
                }
                BgpAnalysisState::AnnouncementValid => {}
                BgpAnalysisState::AnnouncementNotFound => {
                    suggestion.not_found.push(entry.announcement())
                }
                BgpAnalysisState::AnnouncementInvalidAsn => {
                    suggestion.invalid_asn.push(entry.announcement())
                }
                BgpAnalysisState::AnnouncementInvalidLength => {
                    suggestion.invalid_length.push(entry.announcement())
                }
                BgpAnalysisState::AnnouncementDisallowed => {
                    suggestion.keep_disallowing.push(entry.announcement())
                }
                BgpAnalysisState::RoaNoAnnouncementInfo => {
                    suggestion.keep.push(entry.configured_roa().clone())
                }
            }
        }

        suggestion
    }

    /// Retrieves all announcements overlapping an IP range from BGP API.
    async fn retrieve(
        &self,
        block: IpRange,
    ) -> Result<Vec<Announcement>, BgpApiError> {
        let mut announcements: Vec<Announcement> = vec![];

        for prefix in block.to_prefixes() {
            let resp = self.get_url(self.format_url(prefix)).await?;
            match self.obtain_announcements(resp) {
                Some(mut ann) => announcements.append(&mut ann),
                None => return Err(BgpApiError::MalformedData),
            }
        }

        Ok(announcements)
    }

    /// Formats the URL to retrieve announcements for the given prefix.
    fn format_url(&self, prefix: TypedPrefix) -> String {
        format!("{}/api/v1/prefix/{:?}/{}/search",
            self.bgp_api_uri, prefix.ip_addr(), prefix.addr_len()
        )
    }

    /// Fetches the URL and parses the returned JSON.
    async fn get_url(&self, url: String) -> Result<Value, BgpApiError> {
        #[cfg(test)]
        if url.starts_with("test") {
            // When testing, the "test" URL is special. Also, unwrapping is
            // fine.
            let value = serde_json::from_str::<Value>(include_str!(
                "../test-resources/bgp/bgp-api.json")
            ).unwrap();
            let Value::Object(mut value) = value else {
                panic!("not an object")
            };
            return Ok(value.remove(url.as_str()).unwrap())
        }

        Ok(self.client.get(url.as_str()).send().await?.json().await?)
    }

    /// Obtain the announcements from the JSON tree.
    ///
    /// Returns `None` if the JSON structure was in any way unexpected.
    fn obtain_announcements(&self, json: Value) -> Option<Vec<Announcement>> {
        let mut anns: Vec<Announcement> = vec![];
        let prefix_str = json.get("result")?.get("prefix")?.as_str()?;
        for meta in json.get("result")?.get("meta")?.as_array()? {
            self.parse_meta(meta, prefix_str, &mut anns)?;
        }
        for relation in json.get("result")?.get("relations")?.as_array()? {
            if relation.get("type")?.as_str()? == "more-specific" {
                for member in relation.get("members")?.as_array()? {
                    self.parse_member(member, &mut anns)?;
                }
            }
        }
        Some(anns)
    }

    /// Parses the a single entry in the members array.
    ///
    /// Returns `None` if the JSON structure was in any way unexpected.
    fn parse_member(
        &self, member: &Value, anns: &mut Vec<Announcement>
    ) -> Option<()> {
        let prefix_str = member.get("prefix")?.as_str()?;
        for meta in member.get("meta")?.as_array()? {
            self.parse_meta(meta, prefix_str, anns)?;
        }
        Some(())
    }

    /// Parses the meta member of a result.
    ///
    /// Returns `None` if the JSON structure was in any way unexpected.
    fn parse_meta(
        &self, 
        meta: &Value, 
        prefix_str: &str, 
        anns: &mut Vec<Announcement>
    ) -> Option<()> {
        if meta.get("sourceType")?.as_str()? == "bgp" {
            for asn in meta.get("originASNs")?.as_array()? {
                // Strip off "AS" prefix
                let asn = AsNumber::from_str(asn.as_str()?.get(2..)?).ok()?;
                let prefix = TypedPrefix::from_str(prefix_str).ok()?;

                anns.push(Announcement { asn, prefix });
            }
        }
        Some(())
    }
}


//------------ ValidatedAnnouncement -----------------------------------------

/// A BGP announcement that has been validated agains ROAs.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ValidatedAnnouncement {
    /// The actual announcement.
    pub announcement: Announcement,

    /// The RPKI validity status.
    pub validity: AnnouncementValidity,

    /// The ROA payload that authorizes the announcement.
    pub authorizing: Option<RoaPayload>,

    /// The ROA payload that disallows the announcement.
    pub disallowing: Vec<RoaPayload>,
}


//------------ AnnouncementValidity ------------------------------------------

/// The RPKI validity of an announcement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AnnouncementValidity {
    /// The announcement is RPKI valid.
    Valid,

    /// The announcement is RPKI valid because of the prefix length.
    InvalidLength,

    /// The announcement is RPKI valid because of the originating ASN.
    InvalidAsn,

    /// The announcement is not allowed.
    Disallowed,

    /// The announcement is RPKI unknown.
    NotFound,
}


//------------ IpRange -----------------------------------------------------

/// A range of IP addresses.
//
//  We are using IPv4-mapped IPv6 addresses for IPv4 and can thus store
//  everything as the `u128` of an IPv6 address.
#[derive(Clone, Debug)]
pub struct IpRange(Range<u128>);

impl IpRange {
    /// Returns the IPv4 (left) and IPv6 (right) ranges as a tuple.
    pub fn from_resource_set(
        set: &ResourceSet,
    ) -> Vec<IpRange> {
        let mut res = vec![];
        for block in set.ipv4().iter() {
            res.push(IpRange(Range {
                start: block.min().to_v4().to_ipv6_mapped().into(),
                end: block.max().to_v4().to_ipv6_mapped().into(),
            }))
        }
        for block in set.ipv6().iter() {
            res.push(IpRange(Range {
                start: block.min().to_v6().into(),
                end: block.max().to_v6().into(),
            }))
        }
        res
    }

    /// Returns whether this range contains the other range.
    fn contains(&self, other: &Range<u128>) -> bool {
        self.0.start <= other.start && self.0.end >= other.end
    }

    /// Returns whether this range is contained by the other range.
    fn is_contained_by(&self, other: &Range<u128>) -> bool {
        other.start <= self.0.start && other.end >= self.0.end
    }

    /// Converts the range into a typed prefix.
    pub fn to_prefixes(&self) -> Vec<TypedPrefix> {
        let is_ipv4 = 
            (self.0.start & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000) == 
                0x0000_0000_0000_0000_0000_FFFF_0000_0000;

        let mut min = self.0.start;
        let mut max = self.0.end;

        if is_ipv4 {
            // Krill stores IPv4 internally as an IPv4-mapped IPv6 address,
            // rpki-rs stores IPv4 addresses in the top bytes, so that prefix
            // handling works regardless of the IP type.
            min <<= 96;
            max <<= 96;
        }

        let range = AddressRange::from((
            Addr::from_bits(min), 
            Addr::from_bits(max)
        ));

        match is_ipv4 {
            true => range.to_v4_prefixes()
                .map(|x| TypedPrefix::from(Ipv4Prefix::from(x))).collect(),
            false => range.to_v6_prefixes()
                .map(|x| TypedPrefix::from(Ipv6Prefix::from(x))).collect()
        }
    }
}

impl From<TypedPrefix> for IpRange {
    fn from(tp: TypedPrefix) -> Self {
        match tp {
            TypedPrefix::V4(pfx) => {
                let (min, max) = pfx.as_ref().range();
                let start = min.to_v4().to_ipv6_mapped().into();
                let end = max.to_v4().to_ipv6_mapped().into();
                IpRange(Range { start, end })
            }
            TypedPrefix::V6(pfx) => {
                let (min, max) = pfx.as_ref().range();
                let start = min.to_v6().into();
                let end = max.to_v6().into();
                IpRange(Range { start, end })
            }
        }
    }
}


//------------ IpRangeStore ---------------------------------------------

pub struct IpRangeStore<V> {
    tree: IntervalTree<u128, Vec<V>>,
}

impl<V> IpRangeStore<V> {
    pub fn create(items: impl IntoIterator<Item = (IpRange, V)>) -> Self {
        let mut values: HashMap<Range<u128>, Vec<V>> = HashMap::new();
        for (range, value) in items {
            values.entry(range.0).or_default().push(value);
        }
        IpRangeStore { tree: values.into_iter().collect() }
    }

    pub fn matching_or_more_specific(
        &self,
        range: impl Into<IpRange>,
    ) -> Vec<&V> {
        let range: IpRange = range.into();
        let mut res = vec![];
        for el in self.tree.query(range.0.clone()) {
            if range.contains(&el.range) {
                for v in &el.value {
                    res.push(v)
                }
            }
        }
        res
    }

    pub fn matching_or_less_specific(
        &self,
        range: impl Into<IpRange>,
    ) -> Vec<&V> {
        let range: IpRange = range.into();
        let mut res = vec![];
        for el in self.tree.query(range.0.clone()) {
            if range.is_contained_by(&el.range) {
                for v in &el.value {
                    res.push(v)
                }
            }
        }
        res
    }

    pub fn size(&self) -> usize {
        self.tree.iter().count()
    }

    pub fn all(&self) -> Vec<&V> {
        self.tree
            .iter()
            .flat_map(|el| el.value.as_slice())
            .collect()
    }
}

impl IpRangeStore<RoaPayload> {
    fn validate_announcement(
        &self, announcement: Announcement
    ) -> ValidatedAnnouncement {
        let covering = self.matching_or_less_specific(announcement.prefix);
        if covering.is_empty() {
            return ValidatedAnnouncement {
                announcement,
                validity: AnnouncementValidity::NotFound,
                authorizing: None,
                disallowing: vec![],
            }
        }

        let mut invalidating = vec![];
        let mut same_asn_found = false;
        let mut none_as0_found = false;
        for roa in covering {
            if roa.asn == announcement.asn {
                if roa.prefix.matching_or_less_specific(announcement.prefix)
                    && roa.effective_max_length()
                            >= announcement.prefix.addr_len()
                {
                    return ValidatedAnnouncement {
                        announcement,
                        validity: AnnouncementValidity::Valid,
                        authorizing: Some(*roa),
                        disallowing: vec![],
                    };
                }
                else {
                    same_asn_found = true;
                }
            }
            if roa.asn != AsNumber::AS0 {
                none_as0_found = true;
            }
            invalidating.push(*roa);
        }

        // Valid announcements already returned, we only have invalids left.
        let validity = if same_asn_found {
            AnnouncementValidity::InvalidLength
        }
        else if none_as0_found {
            AnnouncementValidity::InvalidAsn
        }
        else {
            AnnouncementValidity::Disallowed
        };

        ValidatedAnnouncement {
            announcement,
            validity,
            authorizing: None,
            disallowing: invalidating,
        }
    }
}


//============ Error Types ===================================================

//------------ BgpApiError ---------------------------------------------------

/// An error happened whil accessing the BGP API.
#[derive(Debug)]
pub enum BgpApiError {
    /// The HTTP request failed.
    Reqwest(reqwest::Error),

    /// Decoding the content failed.
    Serde(serde_json::Error),

    /// The data was malformed.
    MalformedData
}

impl From<reqwest::Error> for BgpApiError {
    fn from(e: reqwest::Error) -> BgpApiError {
        BgpApiError::Reqwest(e)
    }
}

impl From<serde_json::Error> for BgpApiError {
    fn from(e: serde_json::Error) -> BgpApiError {
        BgpApiError::Serde(e)
    }
}

impl fmt::Display for BgpApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Reqwest(err) => err.fmt(f),
            Self::Serde(err) => err.fmt(f),
            Self::MalformedData => f.write_str("malformed data")
        }
    }
}

impl error::Error for BgpApiError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use rpki::repository::resources::Prefix;
    use crate::api::bgp::BgpAnalysisState;
    use crate::api::roa::{
        Ipv4Prefix, Ipv6Prefix, RoaConfigurationUpdates
    };
    use crate::test::{configured_roa, roa_payload};
    use super::*;


    fn ann(s: &str) -> Announcement {
        Announcement::from_str(s).unwrap()
    }

    fn pfx(s: &str) -> TypedPrefix {
        TypedPrefix::from_str(s).unwrap()
    }

    fn range_pfx(s: &str) -> IpRange {
        IpRange::from(pfx(s))
    }

    fn make_test_tree() -> IpRangeStore<Announcement> {
        IpRangeStore::create(
            [
                ann("10.0.0.0/24 => 64496"),
                ann("10.0.1.0/24 => 64496"),
                ann("10.0.0.0/23 => 64496"),
                ann("10.0.0.0/20 => 64496"),
                ann("10.0.0.0/16 => 64496"),
            ].into_iter().map(|ann| (ann.prefix.into(), ann))
        )
    }

    #[tokio::test]
    async fn analyse_bgp() {
        let roa_too_permissive = configured_roa("10.0.0.0/22-23 => 64496");
        let roa_as0 = configured_roa("10.0.4.0/24 => 0");
        let roa_unseen_completely = configured_roa("10.0.3.0/24 => 64497");

        let roa_not_held = configured_roa("10.1.0.0/24 => 64497");

        let roa_authorizing_single =
            configured_roa("192.168.1.0/24 => 64497");
        let roa_unseen_redundant = configured_roa("192.168.1.0/24 => 64498");
        let roa_as0_redundant = configured_roa("192.168.1.0/24 => 0");

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/16, 192.168.0.0/16", "")
                .unwrap();
        let limit = None;

        let analyser = BgpAnalyser::new(true, "test".to_string());

        let report = analyser
            .analyse(
                &[
                    roa_too_permissive,
                    roa_as0,
                    roa_unseen_completely,
                    roa_not_held,
                    roa_authorizing_single,
                    roa_unseen_redundant,
                    roa_as0_redundant,
                ],
                &resources_held,
                limit,
            )
            .await;

        let expected: BgpAnalysisReport = serde_json::from_str(include_str!(
            "../test-resources/bgp/expected_full_report.json"
        ))
        .unwrap();

        assert_eq!(report, expected);
    }

    #[tokio::test]
    async fn analyse_bgp_disallowed_announcements() {
        let roa = configured_roa("10.0.0.0/22 => 0");

        let roas = &[roa];
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/8, 192.168.0.0/16", "")
                .unwrap();
        let report = analyser.analyse(roas, &resources_held, None).await;

        assert!(!report.contains_invalids());

        let mut disallowed = report
            .matching_announcements(BgpAnalysisState::AnnouncementDisallowed);
        disallowed.sort();

        let disallowed_1 = ann("10.0.0.0/22 => 64496");
        let disallowed_2 = ann("10.0.0.0/22 => 64497");
        let disallowed_3 = ann("10.0.0.0/24 => 64496");
        let disallowed_4 = ann("10.0.2.0/23 => 64496");
        let mut expected =
            vec![disallowed_1, disallowed_2, disallowed_3, disallowed_4];
        expected.sort();

        assert_eq!(disallowed, expected);

        // The suggestion should not try to add the disallowed announcements
        // because they were disallowed by an AS0 roa.
        let suggestion = analyser.suggest(roas, &resources_held, None).await;
        let updates = RoaConfigurationUpdates::from(suggestion);

        let added = &updates.added;
        for announcement in disallowed {
            assert!(!added.iter().any(|added_roa| {
                let added_payload = added_roa.payload;
                let announcement_payload = RoaPayload::from(announcement);
                added_payload.includes(announcement_payload)
            }));
        }
    }

    #[tokio::test]
    async fn analyse_bgp_no_announcements() {
        let roa1 = configured_roa("10.0.0.0/23-24 => 64496");
        let roa2 = configured_roa("10.0.3.0/24 => 64497");
        let roa3 = configured_roa("10.0.4.0/24 => 0");

        let roas = vec![roa1, roa2, roa3];

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/16", "").unwrap();

        let analyser = BgpAnalyser::new(false, "".to_string());
        let table = analyser.analyse(&roas, &resources_held, None).await;
        let table_entries = table.entries();
        assert_eq!(3, table_entries.len());

        let roas_no_info: Vec<ConfiguredRoa> = table_entries
            .iter()
            .filter(|e| e.state() == BgpAnalysisState::RoaNoAnnouncementInfo)
            .map(|e| e.configured_roa().clone())
            .collect();

        assert_eq!(roas_no_info, roas);
    }

    #[tokio::test]
    async fn make_bgp_analysis_suggestion() {
        let roa_too_permissive = configured_roa("10.0.0.0/22-23 => 64496");
        let roa_redundant = configured_roa("10.0.0.0/23 => 64496");
        let roa_as0 = configured_roa("10.0.4.0/24 => 0");
        let roa_unseen_completely = configured_roa("10.0.3.0/24 => 64497");
        let roa_authorizing_single =
            configured_roa("192.168.1.0/24 => 64497");
        let roa_unseen_redundant = configured_roa("192.168.1.0/24 => 64498");
        let roa_as0_redundant = configured_roa("192.168.1.0/24 => 0");

        let roas = &[
            roa_too_permissive,
            roa_redundant,
            roa_as0,
            roa_unseen_completely,
            roa_authorizing_single,
            roa_unseen_redundant,
            roa_as0_redundant,
        ];

        let analyser = BgpAnalyser::new(true, "test".to_string());

        let resources_held =
            ResourceSet::from_strs("", "10.0.0.0/8, 192.168.0.0/16", "")
                .unwrap();
        let limit =
            Some(ResourceSet::from_strs("", "10.0.0.0/22", "").unwrap());
        let suggestion_resource_subset =
            analyser.suggest(roas, &resources_held, limit).await;

        let expected: BgpAnalysisSuggestion =
            serde_json::from_str(include_str!(
            "../test-resources/bgp/expected_suggestion_some_roas.json"
        ))
            .unwrap();
        assert_eq!(suggestion_resource_subset, expected);

        let suggestion_all_roas_in_scope =
            analyser.suggest(roas, &resources_held, None).await;

        let expected: BgpAnalysisSuggestion =
            serde_json::from_str(include_str!(
            "../test-resources/bgp/expected_suggestion_all_roas.json"
        ))
            .unwrap();

        assert_eq!(suggestion_all_roas_in_scope, expected);
    }

    #[test]
    fn format_url() {
        let analyser = BgpAnalyser::new(
            true, "https://rest.bgp-api.net".to_string()
        );
        assert_eq!(
            "https://rest.bgp-api.net/api/v1/prefix/192.168.0.0/16/search", 
            analyser.format_url(TypedPrefix::from(Ipv4Prefix::from(
                Prefix::from_str("192.168.0.0/16").unwrap()
            )))
        );
        assert_eq!(
            "https://rest.bgp-api.net/api/v1/prefix/2001:db8::/32/search", 
            analyser.format_url(TypedPrefix::from(Ipv6Prefix::from(
                Prefix::from_str("2001:db8::/32").unwrap()
            )))
        );
    }

    #[tokio::test]
    async fn retrieve_announcements() {
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let ipv4s = "185.49.140.0/22";
        let ipv6s = "2a04:b900::/29";

        let ranges = IpRange::from_resource_set(
            &ResourceSet::from_strs("", ipv4s, "").unwrap()
        );
        for range in ranges {
            assert_eq!(3, analyser.retrieve(range).await.unwrap().len());
        }

        let ranges = IpRange::from_resource_set(
            &ResourceSet::from_strs("", "", ipv6s).unwrap()
        );
        for range in ranges {
            assert_eq!(6, analyser.retrieve(range).await.unwrap().len());
        }
    }

    #[tokio::test]
    async fn retrieve_broken_announcements() {
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let ipv4s = "1.1.1.1/32, 2.2.2.2/32, 3.3.3.3/32, 4.4.4.4/32";
        let set = ResourceSet::from_strs("", ipv4s, "").unwrap();
        
        let ranges = IpRange::from_resource_set(&set);

        for range in ranges {
            assert!(analyser.retrieve(range).await.is_err());
        }
    }

    #[tokio::test]
    async fn analyse_nlnet_labs_snapshot() {
        let analyser = BgpAnalyser::new(true, "test".to_string());

        let ipv4s = "185.49.140.0/22";
        let ipv6s = "2a04:b900::/29";
        let set = ResourceSet::from_strs("AS211321", ipv4s, ipv6s).unwrap();

        let roas = &[
            configured_roa("2a04:b906::/48-48 => 0"),
            configured_roa("2a04:b907::/48-48 => 0"),
            configured_roa("185.49.142.0/24-24 => 0"),
            configured_roa("2a04:b900::/30-32 => 8587"),
            configured_roa("185.49.140.0/23-23 => 8587"),
            configured_roa("2a04:b900::/30-30 => 8587"),
            configured_roa("2a04:b905::/48-48 => 14618"),
            configured_roa("2a04:b905::/48-48 => 16509"),
            configured_roa("2a04:b902::/32-32 => 16509"),
            configured_roa("2a04:b904::/48-48 => 211321"),
            configured_roa("2a04:b907::/47-47 => 211321"),
            configured_roa("185.49.142.0/23-23 => 211321"),
            configured_roa("2a04:b902::/48-48 => 211321"),
            configured_roa("185.49.143.0/24-24 => 211321"),
        ];

        let report = analyser.analyse(roas, &set, None).await;

        dbg!(&report);

        let entry_expect_roa = |x: &str, y| {
            let x = x.to_string();
            assert!(report.entries().iter().any(|s| 
                s.state() == y &&
                s.configured_roa().to_string() == x 
            ));
        };

        let entry_expect_ann = |x: &str, y: u32, z: BgpAnalysisState| {
            let x = x.to_string();
            assert!(report.entries().iter().any(|s|
                s.state() == z &&
                s.announcement().asn == AsNumber::from_u32(y) &&
                s.announcement().prefix.to_string() == x
            ));
        };

        entry_expect_roa(
            "2a04:b907::/48-48 => 0", BgpAnalysisState::RoaAs0Redundant
        );
        entry_expect_roa(
            "185.49.142.0/24-24 => 0", BgpAnalysisState::RoaAs0Redundant
        );
        entry_expect_roa(
            "2a04:b900::/30-30 => 8587", BgpAnalysisState::RoaRedundant
        );
        entry_expect_roa(
            "2a04:b905::/48-48 => 14618", BgpAnalysisState::RoaUnseen
        );
        entry_expect_roa(
            "2a04:b902::/32-32 => 16509", BgpAnalysisState::RoaUnseen
        );
        entry_expect_ann(
            "2a04:b907::/48", 211321,
            BgpAnalysisState::AnnouncementInvalidLength
        );
        entry_expect_ann(
            "185.49.142.0/24", 211321,
            BgpAnalysisState::AnnouncementInvalidLength
        );
        entry_expect_roa(
            "2a04:b902::/48-48 => 211321", BgpAnalysisState::RoaUnseen
        );
        entry_expect_roa(
            "185.49.143.0/24-24 => 211321", BgpAnalysisState::RoaUnseen
        );
    }

    #[test]
    fn validate_announcement() {
        let roas = [
            roa_payload("10.0.0.0/23-24 => 64496"), // authorizing 1
            roa_payload("10.0.0.0/23 => 64498"), // authorizing 2
            roa_payload("10.1.0.0/23-24 => 64496") // irrelevant,
        ];

        let ann_v1 = ann("10.0.0.0/24 => 64496");
        let ann_v2 = ann("10.0.1.0/24 => 64496");
        let ann_ia = ann("10.0.0.0/24 => 64497");
        let ann_il = ann("10.0.1.0/24 => 64498");
        let ann_nf = ann("10.2.0.0/24 => 64497");

        let roas = IpRangeStore::create(
            roas.into_iter().map(|roa| (roa.prefix.into(), roa))
        );

        fn assert_state(
            ann: &Announcement,
            roas: &IpRangeStore<RoaPayload>,
            expected: AnnouncementValidity,
        ) {
            assert_eq!(roas.validate_announcement(*ann).validity, expected);
        }

        assert_state(&ann_v1, &roas, AnnouncementValidity::Valid);
        assert_state(&ann_v2, &roas, AnnouncementValidity::Valid);
        assert_state(&ann_ia, &roas, AnnouncementValidity::InvalidAsn);
        assert_state(&ann_il, &roas, AnnouncementValidity::InvalidLength);
        assert_state(&ann_nf, &roas, AnnouncementValidity::NotFound);
    }

    #[test]
    fn range_contains() {
        let more_specific_1 = range_pfx("10.0.0.0/24");
        let more_specific_2 = range_pfx("10.0.1.0/24");
        let test_pfx = range_pfx("10.0.0.0/23");

        assert!(test_pfx.contains(&more_specific_1.0));
        assert!(test_pfx.contains(&more_specific_2.0));
    }

    #[test]
    fn typed_prefix_tree_more_specific() {
        let tree = make_test_tree();
        let search = TypedPrefix::from_str("10.0.0.0/23").unwrap();
        assert_eq!(3, tree.matching_or_more_specific(search).len());

        let search = TypedPrefix::from_str("10.0.2.0/24").unwrap();
        assert_eq!(0, tree.matching_or_more_specific(search).len());
    }

    #[test]
    fn typed_prefix_tree_less_specific() {
        let tree = make_test_tree();
        let search = TypedPrefix::from_str("10.0.0.0/23").unwrap();
        assert_eq!(3, tree.matching_or_less_specific(search).len());

        let search = TypedPrefix::from_str("10.0.0.0/24").unwrap();
        assert_eq!(4, tree.matching_or_less_specific(search).len());

        let search = TypedPrefix::from_str("10.0.0.0/16").unwrap();
        assert_eq!(1, tree.matching_or_less_specific(search).len());

        let search = TypedPrefix::from_str("10.0.0.0/15").unwrap();
        assert_eq!(0, tree.matching_or_less_specific(search).len());
    }

    #[test]
    fn set_to_ranges() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";
        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let ranges = IpRange::from_resource_set(&set);
        assert_eq!(4, ranges.len());
    }

    #[test]
    fn to_prefixes() {
        let ipv4s = "10.0.0.0/8, 192.168.0.0-192.168.2.255";
        let ipv6s = "::1-::3, 2001:db8::/32";
        let set = ResourceSet::from_strs("", ipv4s, ipv6s).unwrap();

        let ranges: Vec<Vec<TypedPrefix>> = 
            IpRange::from_resource_set(&set)
            .into_iter()
            .map(|x| x.to_prefixes())
            .collect();

        assert_eq!(1, ranges[0].len());
        assert_eq!(2, ranges[1].len());
        assert_eq!(2, ranges[2].len());
        assert_eq!(1, ranges[3].len());
    }
}
