use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::commons::api::{BgpStats, RoaDefinition, RoaDefinitionUpdates};
use crate::commons::bgp::Announcement;

//------------ BgpAnalysisAdvice -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BgpAnalysisAdvice {
    effect: BgpAnalysisReport,
    suggestion: BgpAnalysisSuggestion,
}

impl BgpAnalysisAdvice {
    pub fn new(effect: BgpAnalysisReport, suggestion: BgpAnalysisSuggestion) -> Self {
        BgpAnalysisAdvice { effect, suggestion }
    }

    pub fn effect(&self) -> &BgpAnalysisReport {
        &self.effect
    }

    pub fn suggestion(&self) -> &BgpAnalysisSuggestion {
        &self.suggestion
    }
}

impl fmt::Display for BgpAnalysisAdvice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Unsafe update, please review")?;
        writeln!(f)?;
        writeln!(f, "Effect would leave the following invalids:")?;

        let invalid_asns = self.effect().matching_defs(BgpAnalysisState::AnnouncementInvalidAsn);
        if !invalid_asns.is_empty() {
            writeln!(f)?;
            writeln!(f, "  Announcements from invalid ASNs:")?;
            for invalid in invalid_asns {
                writeln!(f, "    {}\n", invalid)?;
            }
        }

        let invalid_length = self.effect().matching_defs(BgpAnalysisState::AnnouncementInvalidLength);
        if !invalid_length.is_empty() {
            writeln!(f)?;
            writeln!(f, "  Announcements too specific for their ASNs:\n")?;
            for invalid in invalid_length {
                writeln!(f, "    {}", invalid)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "You may want to consider this alternative:")?;
        writeln!(f, "{}", self.suggestion())?;

        Ok(())
    }
}

//------------ BgpAnalysisSuggestion ---------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BgpAnalysisSuggestion {
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    stale: Vec<RoaDefinition>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    not_found: Vec<Announcement>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    invalid_asn: Vec<Announcement>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    invalid_length: Vec<Announcement>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    too_permissive: Vec<ReplacementRoaSuggestion>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    as0_redundant: Vec<RoaDefinition>,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    keep: Vec<RoaDefinition>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ReplacementRoaSuggestion {
    current: RoaDefinition,
    new: Vec<RoaDefinition>,
}

impl From<BgpAnalysisSuggestion> for RoaDefinitionUpdates {
    fn from(suggestion: BgpAnalysisSuggestion) -> Self {
        let (stale, not_found, invalid_asn, invalid_length, too_permissive, as0_redundant) = (
            suggestion.stale,
            suggestion.not_found,
            suggestion.invalid_asn,
            suggestion.invalid_length,
            suggestion.too_permissive,
            suggestion.as0_redundant,
        );

        let mut added: HashSet<RoaDefinition> = HashSet::new();
        let mut removed: HashSet<RoaDefinition> = HashSet::new();

        for auth in not_found
            .into_iter()
            .chain(invalid_asn.into_iter())
            .chain(invalid_length.into_iter())
        {
            added.insert(auth.into());
        }

        for auth in stale.into_iter() {
            removed.insert(auth);
        }

        for suggestion in too_permissive.into_iter() {
            removed.insert(suggestion.current);
            for auth in suggestion.new.into_iter() {
                added.insert(auth);
            }
        }

        for auth in as0_redundant.into_iter() {
            removed.insert(auth);
        }

        RoaDefinitionUpdates::new(added, removed)
    }
}

impl Default for BgpAnalysisSuggestion {
    fn default() -> Self {
        BgpAnalysisSuggestion {
            stale: vec![],
            not_found: vec![],
            invalid_asn: vec![],
            invalid_length: vec![],
            too_permissive: vec![],
            keep: vec![],
            as0_redundant: vec![],
        }
    }
}

impl BgpAnalysisSuggestion {
    pub fn add_stale(&mut self, authorization: RoaDefinition) {
        self.stale.push(authorization);
    }

    pub fn add_too_permissive(&mut self, current: RoaDefinition, new: Vec<RoaDefinition>) {
        let replacement = ReplacementRoaSuggestion { current, new };
        self.too_permissive.push(replacement);
    }

    pub fn add_not_found(&mut self, announcement: Announcement) {
        self.not_found.push(announcement);
    }

    pub fn add_invalid_asn(&mut self, announcement: Announcement) {
        self.invalid_asn.push(announcement);
    }

    pub fn add_invalid_length(&mut self, announcement: Announcement) {
        self.invalid_length.push(announcement);
    }

    pub fn add_as0_redundant(&mut self, authorization: RoaDefinition) {
        self.as0_redundant.push(authorization);
    }

    pub fn add_keep(&mut self, authorization: RoaDefinition) {
        self.keep.push(authorization);
    }
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
                "Remove the following AS0 ROAs made redundant by ROAs for the same prefix and a real ASN:"
            )?;
            for auth in &self.as0_redundant {
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
            writeln!(f, "Authorize these announcements which are currently not covered:")?;
            for auth in &self.not_found {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.invalid_length.is_empty() {
            writeln!(
                f,
                "Authorize these announcements which are currently invalid because they are too specific:"
            )?;
            for auth in &self.invalid_length {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        if !self.invalid_asn.is_empty() {
            writeln!(
                f,
                "Authorize these announcements which are currently invalid because they are not allowed for these ASNs:"
            )?;
            for auth in &self.invalid_asn {
                writeln!(f, "  {}", auth)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

//------------ BgpAnalysisReport -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BgpAnalysisReport(Vec<BgpAnalysisEntry>);

impl BgpAnalysisReport {
    pub fn new(mut roas: Vec<BgpAnalysisEntry>) -> Self {
        roas.sort();
        BgpAnalysisReport(roas)
    }

    pub fn entries(&self) -> &Vec<BgpAnalysisEntry> {
        &self.0
    }

    pub fn into_entries(self) -> Vec<BgpAnalysisEntry> {
        self.0
    }

    pub fn matching_defs(&self, state: BgpAnalysisState) -> Vec<&RoaDefinition> {
        self.matching_entries(state)
            .into_iter()
            .map(|e| &e.definition)
            .collect()
    }

    pub fn matching_entries(&self, state: BgpAnalysisState) -> Vec<&BgpAnalysisEntry> {
        self.0.iter().filter(|e| e.state == state).collect()
    }

    pub fn contains_invalids(&self) -> bool {
        self.0.iter().any(|el| el.state().is_invalid())
    }
}

impl From<BgpAnalysisReport> for BgpStats {
    fn from(r: BgpAnalysisReport) -> BgpStats {
        let mut stats = BgpStats::default();
        for e in r.0.iter() {
            match e.state {
                BgpAnalysisState::AnnouncementValid => stats.increment_valid(),
                BgpAnalysisState::AnnouncementInvalidAsn => stats.increment_invalid_asn(),
                BgpAnalysisState::AnnouncementInvalidLength => stats.increment_invalid_length(),
                BgpAnalysisState::AnnouncementNotFound => stats.increment_not_found(),
                BgpAnalysisState::RoaUnseen => {
                    stats.increment_roas_total();
                    stats.increment_roas_stale();
                }
                BgpAnalysisState::RoaTooPermissive => {
                    stats.increment_roas_total();
                    stats.increment_roas_too_permissive();
                }
                BgpAnalysisState::RoaAs0Redundant => {
                    stats.increment_roas_total();
                    stats.increment_roas_redundant();
                }
                BgpAnalysisState::RoaAs0 | BgpAnalysisState::RoaNoAnnouncementInfo | BgpAnalysisState::RoaSeen => {
                    stats.increment_roas_total()
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

        let mut entry_map: HashMap<BgpAnalysisState, Vec<&BgpAnalysisEntry>> = HashMap::new();
        for entry in entries.iter() {
            let state = entry.state();
            entry_map.entry(state).or_insert_with(|| vec![]);
            entry_map.get_mut(&state).unwrap().push(entry);
        }

        if entry_map.contains_key(&BgpAnalysisState::RoaNoAnnouncementInfo) {
            write!(f, "no BGP announcements known")
        } else {
            if let Some(authorizing) = entry_map.get(&BgpAnalysisState::RoaSeen) {
                writeln!(f, "Authorizations covering announcements seen:")?;
                for roa in authorizing {
                    writeln!(f)?;
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tAuthorizes:")?;
                    for ann in roa.authorizes.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }

                    if !roa.disallows.is_empty() {
                        writeln!(f)?;
                        writeln!(f, "\t\tDisallows:")?;
                        for ann in roa.disallows.iter() {
                            writeln!(f, "\t\t{}", ann)?;
                        }
                    }
                }
                writeln!(f)?;
            }

            if let Some(too_permissive) = entry_map.get(&BgpAnalysisState::RoaTooPermissive) {
                writeln!(f, "Authorizations which may be too permissive:")?;

                for roa in too_permissive {
                    writeln!(f)?;
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tAuthorizes visible announcements:")?;
                    for ann in roa.authorizes.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }

                    writeln!(f)?;
                    writeln!(f, "\t\tAuthorizes additional *invisible* announcements:")?;
                    for ann in roa.authorizes_excess.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }

                    if !roa.disallows.is_empty() {
                        writeln!(f)?;
                        writeln!(f, "\t\tDisallows:")?;
                        for ann in roa.disallows.iter() {
                            writeln!(f, "\t\t{}", ann)?;
                        }
                    }
                }
                writeln!(f)?;
            }

            if let Some(unseens) = entry_map.get(&BgpAnalysisState::RoaUnseen) {
                writeln!(
                    f,
                    "Authorizations for which no announcements are seen (you may wish to remove these):"
                )?;
                writeln!(f)?;
                for roa in unseens {
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                }
                writeln!(f)?;
            }

            if let Some(as0) = entry_map.get(&BgpAnalysisState::RoaAs0) {
                writeln!(f, "AS0 Authorizations disallowing announcements for prefixes")?;
                writeln!(f)?;
                for roa in as0 {
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                }
                writeln!(f)?;
            }

            if let Some(as0_redundant) = entry_map.get(&BgpAnalysisState::RoaAs0Redundant) {
                writeln!(
                    f,
                    "AS0 Authorization which are made redundant by authorizations for the prefix from real ASNs"
                )?;
                writeln!(f)?;
                for roa in as0_redundant {
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tMade redundant by:")?;
                    for redundant_by in &roa.made_redundant_by {
                        writeln!(f, "\t\t{}", redundant_by)?;
                    }
                    writeln!(f)?;
                }
            }

            if let Some(valids) = entry_map.get(&BgpAnalysisState::AnnouncementValid) {
                writeln!(f, "Announcements which are valid:")?;
                writeln!(f)?;
                for ann in valids {
                    writeln!(f, "\tAnnouncement: {}", ann.definition)?;
                }
                writeln!(f)?;
            }

            if let Some(invalid_asn) = entry_map.get(&BgpAnalysisState::AnnouncementInvalidAsn) {
                writeln!(f, "Announcements from an unauthorized ASN:")?;
                for ann in invalid_asn {
                    writeln!(f)?;
                    writeln!(f, "\tAnnouncement: {}", ann.definition)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tDisallowed by authorization(s):")?;
                    for roa in ann.disallowed_by.iter() {
                        writeln!(f, "\t\t{}", roa)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(invalid_length) = entry_map.get(&BgpAnalysisState::AnnouncementInvalidLength) {
                writeln!(
                    f,
                    "Announcements from an authorized ASN, which are too specific (not allowed by max length):"
                )?;
                for ann in invalid_length {
                    writeln!(f)?;
                    writeln!(f, "\tAnnouncement: {}", ann.definition)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tDisallowed by authorization(s):")?;
                    for roa in ann.disallowed_by.iter() {
                        writeln!(f, "\t\t{}", roa)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(not_found) = entry_map.get(&BgpAnalysisState::AnnouncementNotFound) {
                writeln!(
                    f,
                    "Announcements which are 'not found' (not covered by any of your authorizations):"
                )?;
                writeln!(f)?;
                for ann in not_found {
                    writeln!(f, "\tAnnouncement: {}", ann.definition)?;
                }
                writeln!(f)?;
            }

            Ok(())
        }
    }
}

//------------ BgpAnalysisEntry --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BgpAnalysisEntry {
    #[serde(flatten)]
    definition: RoaDefinition,
    state: BgpAnalysisState,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_by: Option<RoaDefinition>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    disallowed_by: Vec<RoaDefinition>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    made_redundant_by: Vec<RoaDefinition>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    authorizes: Vec<Announcement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    authorizes_excess: Vec<Announcement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    disallows: Vec<Announcement>,
}

impl BgpAnalysisEntry {
    pub fn definition(&self) -> &RoaDefinition {
        &self.definition
    }

    pub fn into_definition(self) -> RoaDefinition {
        self.definition
    }

    pub fn into_announcement(self) -> Announcement {
        self.definition.into()
    }

    pub fn state(&self) -> BgpAnalysisState {
        self.state
    }

    pub fn allowed_by(&self) -> Option<&RoaDefinition> {
        self.allowed_by.as_ref()
    }

    pub fn disallowed_by(&self) -> &Vec<RoaDefinition> {
        &self.disallowed_by
    }

    pub fn made_redundant_by(&self) -> &Vec<RoaDefinition> {
        &self.made_redundant_by
    }

    pub fn authorizes(&self) -> &Vec<Announcement> {
        &self.authorizes
    }

    pub fn disallows(&self) -> &Vec<Announcement> {
        &self.disallows
    }

    pub fn roa_seen(
        definition: RoaDefinition,
        mut authorizes: Vec<Announcement>,
        mut disallows: Vec<Announcement>,
    ) -> Self {
        authorizes.sort();
        disallows.sort();
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaSeen,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes,
            authorizes_excess: vec![],
            disallows,
        }
    }

    pub fn roa_as0(definition: RoaDefinition, mut disallows: Vec<Announcement>) -> Self {
        disallows.sort();
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaAs0,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows,
        }
    }

    pub fn roa_as0_redundant(definition: RoaDefinition, mut made_redundant_by: Vec<RoaDefinition>) -> Self {
        made_redundant_by.sort();
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaAs0Redundant,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by,
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_too_permissive(
        definition: RoaDefinition,
        mut authorizes: Vec<Announcement>,
        mut disallows: Vec<Announcement>,
        mut authorizes_excess: Vec<Announcement>,
    ) -> Self {
        authorizes.sort();
        disallows.sort();
        authorizes_excess.sort();
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaTooPermissive,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes,
            authorizes_excess,
            disallows,
        }
    }

    pub fn roa_unseen(definition: RoaDefinition) -> Self {
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaUnseen,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_no_announcement_info(definition: RoaDefinition) -> Self {
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaNoAnnouncementInfo,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_valid(announcement: Announcement, allowed_by: RoaDefinition) -> Self {
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementValid,
            allowed_by: Some(allowed_by),
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_asn(announcement: Announcement, mut disallowed_by: Vec<RoaDefinition>) -> Self {
        disallowed_by.sort();
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementInvalidAsn,
            allowed_by: None,
            disallowed_by,
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_length(announcement: Announcement, mut disallowed_by: Vec<RoaDefinition>) -> Self {
        disallowed_by.sort();
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementInvalidLength,
            allowed_by: None,
            disallowed_by,
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_not_found(announcement: Announcement) -> Self {
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementNotFound,
            allowed_by: None,
            disallowed_by: vec![],
            made_redundant_by: vec![],
            authorizes: vec![],
            authorizes_excess: vec![],
            disallows: vec![],
        }
    }
}

impl Ord for BgpAnalysisEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut ordering = self.state.cmp(&other.state);
        if ordering == Ordering::Equal {
            ordering = self.definition.cmp(&other.definition);
        }
        ordering
    }
}

impl PartialOrd for BgpAnalysisEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

//------------ BgpAnalysisState --------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BgpAnalysisState {
    RoaSeen,
    RoaUnseen,
    RoaTooPermissive,
    RoaAs0,
    RoaAs0Redundant,
    AnnouncementValid,
    AnnouncementInvalidLength,
    AnnouncementInvalidAsn,
    AnnouncementNotFound,
    RoaNoAnnouncementInfo,
}

impl BgpAnalysisState {
    pub fn is_invalid(self) -> bool {
        match self {
            BgpAnalysisState::AnnouncementInvalidAsn | BgpAnalysisState::AnnouncementInvalidLength => true,
            _ => false,
        }
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_bgp_report_full() {
        let json = include_str!("../../../test-resources/bgp/expected_full_report.json");
        let report: BgpAnalysisReport = serde_json::from_str(json).unwrap();

        let expected = include_str!("../../../test-resources/bgp/expected_full_report.txt");

        assert_eq!(report.to_string(), expected);
    }
}
