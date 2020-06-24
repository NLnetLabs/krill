use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;

use crate::commons::api::{BgpStats, RoaDefinition};
use crate::commons::bgp::Announcement;

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

    pub fn matching_defs(&self, state: BgpAnalysisState) -> Vec<&RoaDefinition> {
        self.matching_entries(state)
            .into_iter()
            .map(|e| &e.definition)
            .collect()
    }

    pub fn matching_entries(&self, state: BgpAnalysisState) -> Vec<&BgpAnalysisEntry> {
        self.0.iter().filter(|e| e.state == state).collect()
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
                BgpAnalysisState::RoaUnseen => stats.increment_unseen(),
                _ => {} // nothing to see, move along
            }
        }
        stats
    }
}

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

            if let Some(invalid_length) =
                entry_map.get(&BgpAnalysisState::AnnouncementInvalidLength)
            {
                writeln!(f, "Announcements from an authorized ASN, which are too specific (not allowed by max length):")?;
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
                writeln!(f, "Announcements which are 'not found' (not covered by any of your authorizations):")?;
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
    authorizes: Vec<Announcement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    disallows: Vec<Announcement>,
}

impl BgpAnalysisEntry {
    pub fn definition(&self) -> &RoaDefinition {
        &self.definition
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
            authorizes,
            disallows,
        }
    }

    pub fn roa_unseen(definition: RoaDefinition) -> Self {
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaUnseen,
            allowed_by: None,
            disallowed_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_no_announcement_info(definition: RoaDefinition) -> Self {
        BgpAnalysisEntry {
            definition,
            state: BgpAnalysisState::RoaNoAnnouncementInfo,
            allowed_by: None,
            disallowed_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_valid(announcement: Announcement, allowed_by: RoaDefinition) -> Self {
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementValid,
            allowed_by: Some(allowed_by),
            disallowed_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_asn(
        announcement: Announcement,
        mut disallowed_by: Vec<RoaDefinition>,
    ) -> Self {
        disallowed_by.sort();
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementInvalidAsn,
            allowed_by: None,
            disallowed_by,
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_length(
        announcement: Announcement,
        mut disallowed_by: Vec<RoaDefinition>,
    ) -> Self {
        disallowed_by.sort();
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementInvalidLength,
            allowed_by: None,
            disallowed_by,
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_not_found(announcement: Announcement) -> Self {
        BgpAnalysisEntry {
            definition: RoaDefinition::from(announcement),
            state: BgpAnalysisState::AnnouncementNotFound,
            allowed_by: None,
            disallowed_by: vec![],
            authorizes: vec![],
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
    AnnouncementValid,
    AnnouncementInvalidLength,
    AnnouncementInvalidAsn,
    AnnouncementNotFound,
    RoaNoAnnouncementInfo,
}

//------------ AnnouncementReport ------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AnnouncementReport(Vec<AnnouncementReportEntry>);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AnnouncementReportEntry {
    definition: RoaDefinition,
    state: AnnouncementReportState,
}

impl fmt::Display for AnnouncementReportEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state_str = match self.state {
            AnnouncementReportState::Valid => "announcement 'valid'",
            AnnouncementReportState::InvalidAsn => "announcement 'invalid': unauthorized asn",
            AnnouncementReportState::InvalidLength => {
                "announcement 'invalid': more specific than allowed"
            }
            AnnouncementReportState::NotFound => {
                "announcement 'not found': not covered by your ROAs"
            }
            AnnouncementReportState::Unseen => {
                "ROA does not cover any known announcement (obsolete or backup?)"
            }
            AnnouncementReportState::NoInfo => "ROA exists, but no bgp info currently available",
        };
        write!(f, "{}\t{}", self.definition, state_str)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementReportState {
    Valid,
    InvalidAsn,
    InvalidLength,
    NotFound,
    Unseen,
    NoInfo,
}

impl From<BgpAnalysisReport> for AnnouncementReport {
    fn from(table: BgpAnalysisReport) -> Self {
        let mut entries: Vec<AnnouncementReportEntry> = vec![];
        for def in table.matching_defs(BgpAnalysisState::AnnouncementValid) {
            entries.push(AnnouncementReportEntry {
                definition: *def,
                state: AnnouncementReportState::Valid,
            })
        }

        for def in table.matching_defs(BgpAnalysisState::AnnouncementInvalidAsn) {
            entries.push(AnnouncementReportEntry {
                definition: *def,
                state: AnnouncementReportState::InvalidAsn,
            })
        }

        for def in table.matching_defs(BgpAnalysisState::AnnouncementInvalidLength) {
            entries.push(AnnouncementReportEntry {
                definition: *def,
                state: AnnouncementReportState::InvalidLength,
            })
        }

        for def in table.matching_defs(BgpAnalysisState::AnnouncementNotFound) {
            entries.push(AnnouncementReportEntry {
                definition: *def,
                state: AnnouncementReportState::NotFound,
            })
        }
        for def in table.matching_defs(BgpAnalysisState::RoaUnseen) {
            entries.push(AnnouncementReportEntry {
                definition: *def,
                state: AnnouncementReportState::Unseen,
            })
        }
        for def in table.matching_defs(BgpAnalysisState::RoaNoAnnouncementInfo) {
            entries.push(AnnouncementReportEntry {
                definition: *def,
                state: AnnouncementReportState::NoInfo,
            })
        }
        AnnouncementReport(entries)
    }
}

impl fmt::Display for AnnouncementReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for e in self.0.iter() {
            writeln!(f, "{}", e)?;
        }
        Ok(())
    }
}

//------------ RoaReport ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaReport(Vec<RoaReportEntry>);

impl fmt::Display for RoaReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for e in self.0.iter() {
            writeln!(f, "{}", e)?;
        }
        Ok(())
    }
}

impl From<BgpAnalysisReport> for RoaReport {
    fn from(table: BgpAnalysisReport) -> Self {
        let mut entries: Vec<RoaReportEntry> = vec![];

        for entry in table.0 {
            match &entry.state {
                BgpAnalysisState::RoaSeen => entries.push(RoaReportEntry {
                    definition: entry.definition,
                    state: RoaReportEntryState::Covering,
                    authorizes: entry.authorizes,
                    disallows: entry.disallows,
                }),
                BgpAnalysisState::RoaUnseen => entries.push(RoaReportEntry {
                    definition: entry.definition,
                    state: RoaReportEntryState::Unseen,
                    authorizes: entry.authorizes,
                    disallows: entry.disallows,
                }),
                BgpAnalysisState::RoaNoAnnouncementInfo => entries.push(RoaReportEntry {
                    definition: entry.definition,
                    state: RoaReportEntryState::NoInfo,
                    authorizes: entry.authorizes,
                    disallows: entry.disallows,
                }),
                BgpAnalysisState::AnnouncementNotFound => entries.push(RoaReportEntry {
                    definition: entry.definition,
                    state: RoaReportEntryState::NotFound,
                    authorizes: entry.authorizes,
                    disallows: entry.disallows,
                }),
                _ => {}
            }
        }

        RoaReport(entries)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaReportEntry {
    definition: RoaDefinition,
    state: RoaReportEntryState,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    authorizes: Vec<Announcement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    disallows: Vec<Announcement>,
}

impl fmt::Display for RoaReportEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state_str = match self.state {
            RoaReportEntryState::Covering | RoaReportEntryState::Unseen => format!(
                "roa authorizes {}, disallows {} announcements",
                self.authorizes.len(),
                self.disallows.len()
            ),
            RoaReportEntryState::NotFound => {
                "announcement 'not found': not covered by your ROAs".to_string()
            }
            RoaReportEntryState::NoInfo => {
                "ROA exists, but no bgp info currently available".to_string()
            }
        };
        write!(f, "{}\t{}", self.definition, state_str)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoaReportEntryState {
    Covering,
    Unseen,
    NotFound,
    NoInfo,
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

    #[test]
    fn print_bgp_report_announcements() {
        let json = include_str!("../../../test-resources/bgp/expected_full_report.json");
        let report: BgpAnalysisReport = serde_json::from_str(json).unwrap();
        let report: AnnouncementReport = report.into();

        let expected_json =
            include_str!("../../../test-resources/bgp/expected_announcement_report.json");
        let expected: AnnouncementReport = serde_json::from_str(expected_json).unwrap();

        assert_eq!(report, expected);

        let expected_text =
            include_str!("../../../test-resources/bgp/expected_announcement_report.txt");
        assert_eq!(report.to_string(), expected_text);
    }

    #[test]
    fn print_bgp_report_roas() {
        let json = include_str!("../../../test-resources/bgp/expected_full_report.json");
        let report: BgpAnalysisReport = serde_json::from_str(json).unwrap();
        let report: RoaReport = report.into();

        let expected_json = include_str!("../../../test-resources/bgp/expected_roa_report.json");
        let expected: RoaReport = serde_json::from_str(expected_json).unwrap();

        assert_eq!(report, expected);

        let expected_text = include_str!("../../../test-resources/bgp/expected_roa_report.txt");
        assert_eq!(report.to_string(), expected_text);
    }
}
