//! The BGP analysis report. 

use std::fmt;
use std::collections::HashMap;
use std::cmp::Ordering;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::commons::api::ca::BgpStats;
use crate::commons::api::roa::{
    AsNumber, ConfiguredRoa, RoaPayload, TypedPrefix,
};


//------------ BgpAnalysisAdvice ---------------------------------------------

/// Advice for ROA changes based on BGP announcemenets seen.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpAnalysisAdvice {
    /// The effect of the suggestion.
    pub effect: BgpAnalysisReport,

    /// Suggestions from the report.
    pub suggestion: BgpAnalysisSuggestion,
}

impl fmt::Display for BgpAnalysisAdvice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Unsafe update, please review")?;
        writeln!(f)?;
        writeln!(f, "Effect would leave the following invalids:")?;

        let invalid_asns = self.effect.matching_announcements(
            BgpAnalysisState::AnnouncementInvalidAsn
        );
        if !invalid_asns.is_empty() {
            writeln!(f)?;
            writeln!(f, "  Announcements from invalid ASNs:")?;
            for invalid in invalid_asns {
                writeln!(f, "    {}\n", invalid)?;
            }
        }

        let invalid_length = self.effect.matching_announcements(
            BgpAnalysisState::AnnouncementInvalidLength,
        );
        if !invalid_length.is_empty() {
            writeln!(f)?;
            writeln!(f, "  Announcements too specific for their ASNs:\n")?;
            for invalid in invalid_length {
                writeln!(f, "    {}", invalid)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "You may want to consider this alternative:")?;
        writeln!(f, "{}", self.suggestion)?;

        Ok(())
    }
}

//------------ BgpAnalysisSuggestion ---------------------------------------

/// Suggestions for ROAs based on seen BGP announcements.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpAnalysisSuggestion {
    /// Lists the stale ROAs that can be removed.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub stale: Vec<ConfiguredRoa>,

    /// Lists announcements that are not currently covered.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub not_found: Vec<Announcement>,

    /// Lists announcements that are currently invalid due to an ASN.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub invalid_asn: Vec<Announcement>,

    /// Lists announcements that are too specific and therefore invalid.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub invalid_length: Vec<Announcement>,

    /// List replacements for ROAs that are too permissive.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub too_permissive: Vec<ReplacementRoaSuggestion>,

    /// Lists ROAs that only disallow announcements.
    ///
    /// They may indicate a mistake in the ASN. If intended, they should
    /// perhaps use AS0 instead.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub disallowing: Vec<ConfiguredRoa>,

    /// Lists ROAs that are made redundant by covering ROAs using max length.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub redundant: Vec<ConfiguredRoa>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub not_held: Vec<ConfiguredRoa>,

    /// Lists AS0 ROAs that are made redundant by other ROAs.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub as0_redundant: Vec<ConfiguredRoa>,

    /// Lists ROAs that should be kept.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub keep: Vec<ConfiguredRoa>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub keep_disallowing: Vec<Announcement>,
}

#[allow(clippy::cognitive_complexity)]
impl fmt::Display for BgpAnalysisSuggestion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.stale.is_empty() {
            writeln!(f, "Remove the following stale entries:")?;
            for auth in &self.stale {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.too_permissive.is_empty() {
            writeln!(f, "Replace the following too permissive entries:")?;
            for entry in &self.too_permissive {
                writeln!(f, "  Remove: {}", entry.current)?;
                for replace in &entry.new {
                    writeln!(f, "  Add: {}", replace)?;
                }
                writeln!(f)?;
            }
        }

        if !self.as0_redundant.is_empty() {
            writeln!(
                f,
                "Remove the following AS0 ROAs made redundant by \
                 ROAs for the same prefix and a real ASN:"
            )?;
            for auth in &self.as0_redundant {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.redundant.is_empty() {
            writeln!(
                f,
                "Remove the following ROAs made redundant by a covering ROA \
                 using max length:"
            )?;
            for auth in &self.redundant {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.disallowing.is_empty() {
            writeln!(
                f,
                "Remove the following ROAs which only disallow \
                announcements (did you use the wrong ASN?), if this is \
                intended you may want to use AS0 instead:"
            )?;
            for auth in &self.disallowing {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.keep.is_empty() {
            writeln!(f, "Keep the following authorizations:")?;
            for auth in &self.keep {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.not_found.is_empty() {
            writeln!(f,
                "Authorize these announcements which are currently 
                 not covered:"
            )?;
            for auth in &self.not_found {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.invalid_length.is_empty() {
            writeln!(
                f,
                "Authorize these announcements which are currently \
                 invalid because they are too specific:"
            )?;
            for auth in &self.invalid_length {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.invalid_asn.is_empty() {
            writeln!(
                f,
                "Authorize these announcements which are currently \
                 invalid because they are not allowed for these ASNs:"
            )?;
            for auth in &self.invalid_asn {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}


//------------ ReplacementRoaSuggestion ------------------------------------

/// A suggestion to replace an existing ROA with a different ROA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplacementRoaSuggestion {
    pub current: ConfiguredRoa,
    pub new: Vec<RoaPayload>,
}


//------------ BgpAnalysisReport -------------------------------------------

/// A BGP analysis report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpAnalysisReport(Vec<BgpAnalysisEntry>);

impl BgpAnalysisReport {
    /// Creates a new report from a list of entries.
    pub fn new(mut roas: Vec<BgpAnalysisEntry>) -> Self {
        roas.sort();
        BgpAnalysisReport(roas)
    }

    /// Returns a reference to the list of entries.
    pub fn entries(&self) -> &[BgpAnalysisEntry] {
        &self.0
    }

    /// Converts the report into a list of entries.
    pub fn into_entries(self) -> Vec<BgpAnalysisEntry> {
        self.0
    }

    /// Returns the announcements in the given RPKI state.
    pub fn matching_announcements(
        &self,
        state: BgpAnalysisState,
    ) -> Vec<Announcement> {
        self.matching_entries(state)
            .into_iter()
            .map(|e| e.announcement())
            .collect()
    }

    /// Returns the entries matching the given RPKI state.
    pub fn matching_entries(
        &self,
        state: BgpAnalysisState,
    ) -> Vec<&BgpAnalysisEntry> {
        self.0.iter().filter(|e| e.state == state).collect()
    }

    /// Returns whether the report contains invalid announcements.
    pub fn contains_invalids(&self) -> bool {
        self.0.iter().any(|el| el.state().is_invalid())
    }
}

impl From<BgpAnalysisReport> for BgpStats {
    fn from(r: BgpAnalysisReport) -> BgpStats {
        let mut stats = BgpStats::default();
        for e in r.0.iter() {
            match e.state {
                BgpAnalysisState::AnnouncementValid => {
                    stats.announcements_valid += 1;
                }
                BgpAnalysisState::AnnouncementInvalidAsn => {
                    stats.announcements_invalid_asn += 1;
                }
                BgpAnalysisState::AnnouncementInvalidLength => {
                    stats.announcements_invalid_length += 1;
                }
                BgpAnalysisState::AnnouncementDisallowed => {
                    stats.announcements_disallowed += 1;
                }
                BgpAnalysisState::AnnouncementNotFound => {
                    stats.announcements_not_found += 1;
                }
                BgpAnalysisState::RoaUnseen => {
                    stats.roas_total += 1;
                    stats.roas_stale += 1;
                }
                BgpAnalysisState::RoaTooPermissive => {
                    stats.roas_total += 1;
                    stats.roas_too_permissive += 1;
                }
                BgpAnalysisState::RoaRedundant
                | BgpAnalysisState::RoaAs0Redundant => {
                    stats.roas_total += 1;
                    stats.roas_redundant += 1;
                }
                BgpAnalysisState::RoaNotHeld => {
                    stats.roas_total += 1;
                    stats.roas_not_held += 1;
                }
                BgpAnalysisState::RoaDisallowing => {
                    stats.roas_total += 1;
                    stats.roas_disallowing += 1;
                }
                BgpAnalysisState::RoaAs0
                | BgpAnalysisState::RoaNoAnnouncementInfo
                | BgpAnalysisState::RoaSeen => {
                    stats.roas_total += 1
                }
            }
        }
        stats
    }
}

#[allow(clippy::cognitive_complexity)]
impl fmt::Display for BgpAnalysisReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let entries = self.entries();

        let mut entry_map: HashMap<BgpAnalysisState, Vec<&BgpAnalysisEntry>>
            = HashMap::new();
        for entry in entries.iter() {
            let state = entry.state();
            entry_map.entry(state).or_default();
            entry_map.get_mut(&state).unwrap().push(entry);
        }

        if entry_map.contains_key(&BgpAnalysisState::RoaNoAnnouncementInfo) {
            write!(f, "no BGP announcements known")
        }
        else {
            if let Some(authorizing) = entry_map.get(
                &BgpAnalysisState::RoaSeen
            ) {
                writeln!(
                    f, "ROA configurations covering seen announcements:"
                )?;
                for roa in authorizing {
                    writeln!(f)?;
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                    writeln!(f)?;
                    writeln!(f, "\t\tAuthorizes announcement(s):")?;
                    for ann in roa.authorizes.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }

                    if !roa.disallows.is_empty() {
                        writeln!(f)?;
                        writeln!(f, "\t\tDisallows announcement(s):")?;
                        for ann in roa.disallows.iter() {
                            writeln!(f, "\t\t{}", ann)?;
                        }
                    }
                }
                writeln!(f)?;
            }

            if let Some(redundant) =
                entry_map.get(&BgpAnalysisState::RoaRedundant)
            {
                writeln!(
                    f,
                    "ROA configurations which are *redundant* - they are \
                     already included in full by other configurations:"
                )?;
                for roa in redundant {
                    writeln!(f)?;
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                    writeln!(f)?;
                    writeln!(f, "\t\tAuthorizes announcement(s):")?;
                    for ann in roa.authorizes.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }

                    if !roa.disallows.is_empty() {
                        writeln!(f)?;
                        writeln!(f, "\t\tDisallows announcement(s):")?;
                        for ann in roa.disallows.iter() {
                            writeln!(f, "\t\t{}", ann)?;
                        }
                    }

                    writeln!(f)?;
                    writeln!(f, "\t\tMade redundant by:")?;
                    for redundant_by in roa.made_redundant_by.iter() {
                        writeln!(f, "\t\t{}", redundant_by)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(not_seen) =
                entry_map.get(&BgpAnalysisState::RoaUnseen)
            {
                writeln!(
                    f,
                    "ROA configurations for which no announcements are seen \
                     (you may wish to remove these):"
                )?;
                writeln!(f)?;
                for roa in not_seen {
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                }
                writeln!(f)?;
            }

            if let Some(not_held) =
                entry_map.get(&BgpAnalysisState::RoaNotHeld)
            {
                writeln!(
                    f,
                    "ROA configurations for which no ROAs can be made -\
                     you do not have the prefix on your certificate(s):"
                )?;
                writeln!(f)?;
                for roa in not_held {
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                }
                writeln!(f)?;
            }

            if let Some(disallowing) =
                entry_map.get(&BgpAnalysisState::RoaDisallowing)
            {
                writeln!(
                    f,
                    "ROA configurations only disallowing seen \
                    announcements. You may want to use AS0 ROAs instead:"
                )?;
                for roa in disallowing {
                    writeln!(f)?;
                    writeln!(
                        f,
                        "\ttConfiguration: {}",
                        roa.configured_roa()
                    )?;
                    writeln!(f)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tDisallows:")?;
                    for ann in roa.disallows.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(too_permissive) =
                entry_map.get(&BgpAnalysisState::RoaTooPermissive)
            {
                writeln!(
                    f,
                    "ROA configurations which may be too permissive:"
                )?;

                for roa in too_permissive {
                    writeln!(f)?;
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                    writeln!(f)?;
                    writeln!(f, "\t\tAuthorizes announcement(s):")?;
                    for ann in roa.authorizes.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }

                    if !roa.disallows.is_empty() {
                        writeln!(f)?;
                        writeln!(f, "\t\tDisallows announcement(s):")?;
                        for ann in roa.disallows.iter() {
                            writeln!(f, "\t\t{}", ann)?;
                        }
                    }
                }
                writeln!(f)?;
            }

            if let Some(as0) = entry_map.get(&BgpAnalysisState::RoaAs0) {
                writeln!(
                    f,
                    "AS0 ROA configurations disallowing announcements for \
                     prefixes"
                )?;
                writeln!(f)?;
                for roa in as0 {
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                }
                writeln!(f)?;
            }

            if let Some(as0_redundant) =
                entry_map.get(&BgpAnalysisState::RoaAs0Redundant)
            {
                writeln!(
                    f,
                    "AS0 ROA configurations which are made redundant by \
                    configuration(s) for the prefix from real ASNs"
                )?;
                writeln!(f)?;
                for roa in as0_redundant {
                    writeln!(f, "\tConfiguration: {}", roa.configured_roa())?;
                    writeln!(f)?;
                    writeln!(
                        f,
                        "\t\tMade redundant by ROA configuration(s):"
                    )?;
                    for redundant_by in &roa.made_redundant_by {
                        writeln!(f, "\t\t{}", redundant_by)?;
                    }
                    writeln!(f)?;
                }
            }

            if let Some(valid) =
                entry_map.get(&BgpAnalysisState::AnnouncementValid)
            {
                writeln!(f, "Announcements which are valid:")?;
                writeln!(f)?;
                for ann in valid {
                    writeln!(f, "\tAnnouncement: {}", ann.announcement())?;
                }
                writeln!(f)?;
            }

            if let Some(invalid_length) =
                entry_map.get(&BgpAnalysisState::AnnouncementInvalidLength)
            {
                writeln!(
                    f,
                    "Announcements from an authorized ASN, which are too \
                    specific (not allowed by max length):"
                )?;
                for ann in invalid_length {
                    writeln!(f)?;
                    writeln!(f, "\tAnnouncement: {}", ann.announcement())?;
                    writeln!(f)?;
                    writeln!(f, "\t\tDisallowed by ROA configuration(s):")?;
                    for roa in ann.disallowed_by.iter() {
                        writeln!(f, "\t\t{}", roa)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(invalid_asn) =
                entry_map.get(&BgpAnalysisState::AnnouncementInvalidAsn)
            {
                writeln!(f, "Announcements from an unauthorized ASN:")?;
                for ann in invalid_asn {
                    writeln!(f)?;
                    writeln!(f, "\tAnnouncement: {}", ann.announcement())?;
                    writeln!(f)?;
                    writeln!(f, "\t\tDisallowed by ROA configuration(s):")?;
                    for roa in ann.disallowed_by.iter() {
                        writeln!(f, "\t\t{}", roa)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(disallowed) =
                entry_map.get(&BgpAnalysisState::AnnouncementDisallowed)
            {
                writeln!(f, "Announcements disallowed by 'AS0' ROAs:")?;
                writeln!(f)?;
                for ann in disallowed {
                    writeln!(f, "\tAnnouncement: {}", ann.announcement())?;
                }
                writeln!(f)?;
            }

            if let Some(not_found) =
                entry_map.get(&BgpAnalysisState::AnnouncementNotFound)
            {
                writeln!(
                    f,
                    "Announcements which are 'not found' (not covered by \
                     any of your ROA configurations):"
                )?;
                writeln!(f)?;
                for ann in not_found {
                    writeln!(f, "\tAnnouncement: {}", ann.announcement())?;
                }
                writeln!(f)?;
            }

            Ok(())
        }
    }
}


//------------ BgpAnalysisEntry --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BgpAnalysisEntry {
    #[serde(flatten)]
    pub roa_or_announcement: ConfiguredRoaOrAnnouncement,
    
    pub state: BgpAnalysisState,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_by: Option<RoaPayload>,
    
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub disallowed_by: Vec<RoaPayload>,
    
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub made_redundant_by: Vec<RoaPayload>,
    
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub authorizes: Vec<Announcement>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub disallows: Vec<Announcement>,
}

impl BgpAnalysisEntry {
    /// Returns a reference to the ConfiguredRoa for this entry.
    ///
    /// Panics if it
    /// was an announcement. Only safe to call after checking the state.
    pub fn configured_roa(&self) -> &ConfiguredRoa {
        match &self.roa_or_announcement {
            ConfiguredRoaOrAnnouncement::Roa(roa) => roa,
            _ => panic!(
                "Trying to get a ROA for an entry of state: {:?}",
                self.state
            ),
        }
    }

    pub fn announcement(&self) -> Announcement {
        match &self.roa_or_announcement {
            ConfiguredRoaOrAnnouncement::Announcement(announcement) => {
                *announcement
            }
            _ => panic!(
                "Trying to get an announcement for an entry of state: {:?}",
                self.state
            ),
        }
    }

    pub fn state(&self) -> BgpAnalysisState {
        self.state
    }

    pub fn allowed_by(&self) -> Option<&RoaPayload> {
        self.allowed_by.as_ref()
    }

    pub fn disallowed_by(&self) -> &Vec<RoaPayload> {
        &self.disallowed_by
    }

    pub fn made_redundant_by(&self) -> &Vec<RoaPayload> {
        &self.made_redundant_by
    }

    pub fn authorizes(&self) -> &Vec<Announcement> {
        &self.authorizes
    }

    pub fn disallows(&self) -> &Vec<Announcement> {
        &self.disallows
    }

    pub fn roa_seen(
        configured_roa: ConfiguredRoa,
        mut authorizes: Vec<Announcement>,
        mut disallows: Vec<Announcement>,
    ) -> Self {
        authorizes.sort();
        disallows.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaSeen,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes,
            disallows,
        }
    }

    pub fn roa_disallowing(
        configured_roa: ConfiguredRoa,
        mut disallows: Vec<Announcement>,
    ) -> Self {
        disallows.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaDisallowing,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows,
        }
    }

    pub fn roa_as0(
        configured_roa: ConfiguredRoa,
        mut disallows: Vec<Announcement>,
    ) -> Self {
        disallows.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaAs0,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows,
        }
    }

    pub fn roa_as0_redundant(
        configured_roa: ConfiguredRoa,
        mut made_redundant_by: Vec<RoaPayload>,
    ) -> Self {
        made_redundant_by.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaAs0Redundant,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by,
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_redundant(
        configured_roa: ConfiguredRoa,
        mut authorizes: Vec<Announcement>,
        mut disallows: Vec<Announcement>,
        mut made_redundant_by: Vec<RoaPayload>,
    ) -> Self {
        authorizes.sort();
        disallows.sort();
        made_redundant_by.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaRedundant,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by,
            authorizes,
            disallows,
        }
    }

    pub fn roa_too_permissive(
        configured_roa: ConfiguredRoa,
        mut authorizes: Vec<Announcement>,
        mut disallows: Vec<Announcement>,
    ) -> Self {
        authorizes.sort();
        disallows.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaTooPermissive,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes,
            disallows,
        }
    }

    pub fn roa_unseen(configured_roa: ConfiguredRoa) -> Self {
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaUnseen,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_not_held(configured_roa: ConfiguredRoa) -> Self {
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaNotHeld,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_no_announcement_info(configured_roa: ConfiguredRoa) -> Self {
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Roa(
                configured_roa,
            ),
            state: BgpAnalysisState::RoaNoAnnouncementInfo,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_valid(
        announcement: Announcement,
        allowed_by: RoaPayload,
    ) -> Self {
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Announcement(
                announcement,
            ),
            state: BgpAnalysisState::AnnouncementValid,
            allowed_by: Some(allowed_by),
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_asn(
        announcement: Announcement,
        disallowed_by: Vec<RoaPayload>,
    ) -> Self {
        Self::announcement_invalid(
            announcement,
            BgpAnalysisState::AnnouncementInvalidAsn,
            disallowed_by,
        )
    }

    pub fn announcement_invalid_length(
        announcement: Announcement,
        disallowed_by: Vec<RoaPayload>,
    ) -> Self {
        Self::announcement_invalid(
            announcement,
            BgpAnalysisState::AnnouncementInvalidLength,
            disallowed_by,
        )
    }

    pub fn announcement_disallowed(
        announcement: Announcement,
        disallowed_by: Vec<RoaPayload>,
    ) -> Self {
        Self::announcement_invalid(
            announcement,
            BgpAnalysisState::AnnouncementDisallowed,
            disallowed_by,
        )
    }

    fn announcement_invalid(
        announcement: Announcement,
        state: BgpAnalysisState,
        mut disallowed_by: Vec<RoaPayload>,
    ) -> Self {
        disallowed_by.sort();
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Announcement(
                announcement,
            ),
            state,
            allowed_by: None,
            disallowed_by,
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_not_found(announcement: Announcement) -> Self {
        BgpAnalysisEntry {
            roa_or_announcement: ConfiguredRoaOrAnnouncement::Announcement(
                announcement,
            ),
            state: BgpAnalysisState::AnnouncementNotFound,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }
}

impl Ord for BgpAnalysisEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.state.cmp(&other.state);
        if ordering == Ordering::Equal {
            ordering =
                self.roa_or_announcement.cmp(&other.roa_or_announcement);
        }
        ordering
    }
}

impl PartialOrd for BgpAnalysisEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


//------------ ConfiguredRoaOrAnnouncement ---------------------------------

/// This type is used to allow us to mix both configured ROAs
/// and announcements in a single vector for display in the UI
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ConfiguredRoaOrAnnouncement {
    Roa(ConfiguredRoa),
    Announcement(Announcement),
}

impl ConfiguredRoaOrAnnouncement {
    // Not using impl From because this is for sorting use
    // only.
    fn as_payload(&self) -> RoaPayload {
        match self {
            ConfiguredRoaOrAnnouncement::Announcement(ann) => {
                RoaPayload {
                    asn: ann.asn, prefix: ann.prefix, max_length: None
                }
            }
            ConfiguredRoaOrAnnouncement::Roa(roa) => {
                roa.roa_configuration.payload
            }
        }
    }
}

impl Ord for ConfiguredRoaOrAnnouncement {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_payload().cmp(&other.as_payload())
    }
}

impl PartialOrd for ConfiguredRoaOrAnnouncement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//------------ BgpAnalysisState --------------------------------------------

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    PartialEq,
    Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BgpAnalysisState {
    RoaSeen,
    RoaRedundant,
    RoaUnseen,
    RoaDisallowing,
    RoaTooPermissive,
    RoaAs0,
    RoaAs0Redundant,
    RoaNotHeld,
    AnnouncementValid,
    AnnouncementInvalidLength,
    AnnouncementInvalidAsn,
    AnnouncementDisallowed,
    AnnouncementNotFound,
    RoaNoAnnouncementInfo,
}

impl BgpAnalysisState {
    pub fn is_invalid(self) -> bool {
        matches!(
            self,
            BgpAnalysisState::AnnouncementInvalidAsn
                | BgpAnalysisState::AnnouncementInvalidLength
        )
    }
}


//------------ Announcement --------------------------------------------------

/// A BGP announcement consisting of the origin ASN and the prefix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Announcement {
    /// The originating autonomous system.
    pub asn: AsNumber,

    /// The announced prefix.
    pub prefix: TypedPrefix,
}


//--- From and FromStr

impl From<Announcement> for RoaPayload {
    fn from(a: Announcement) -> Self {
        RoaPayload { asn: a.asn, prefix: a.prefix, max_length: None }
    }
}

impl From<RoaPayload> for Announcement {
    fn from(d: RoaPayload) -> Self {
        Announcement {
            asn: d.asn,
            prefix: d.prefix,
        }
    }
}

impl FromStr for Announcement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let as_roa = RoaPayload::from_str(s).map_err(|e| {
            format!("Can't parse: {}, Error: {}", s, e)
        })?;
        if as_roa.max_length.is_some() {
            Err(format!(
                "Cannot parse announcement (max length not allowed): {}",
                s
            ))
        }
        else {
            Ok(as_roa.into())
        }
    }
}


//--- PartialOrd and Ord

impl PartialOrd for Announcement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Announcement {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.prefix.cmp(&other.prefix);
        if ordering == Ordering::Equal {
            ordering = self.asn.cmp(&other.asn);
        }
        ordering
    }
}


//--- Display

impl fmt::Display for Announcement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} => {}", self.prefix, self.asn)
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_bgp_report_full() {
        let json = include_str!(
            "../../../test-resources/bgp/expected_full_report.json"
        );
        let report: BgpAnalysisReport = serde_json::from_str(json).unwrap();

        let expected = include_str!(
            "../../../test-resources/bgp/expected_full_report.txt"
        );
        let found = report.to_string();

        assert_eq!(found, expected);
    }
}
