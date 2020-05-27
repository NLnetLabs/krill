use std::collections::HashMap;
use std::fmt;

use crate::commons::api::RoaDefinition;
use crate::commons::bgp::Announcement;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoaTableEntryState {
    RoaAuthorizing,
    RoaDisallowing,
    RoaStale,
    AnnouncementInvalidLength,
    AnnouncementInvalidAsn,
    AnnouncementNotFound,
    RoaNoAnnouncementInfo,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaTableEntry {
    #[serde(flatten)]
    definition: RoaDefinition,
    state: RoaTableEntryState,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    disallowed_by: Vec<RoaDefinition>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    authorizes: Vec<Announcement>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    disallows: Vec<Announcement>,
}

impl RoaTableEntry {
    pub fn state(&self) -> RoaTableEntryState {
        self.state
    }

    pub fn definition(&self) -> &RoaDefinition {
        &self.definition
    }

    pub fn roa_authorizing(
        definition: RoaDefinition,
        authorizes: Vec<Announcement>,
        disallows: Vec<Announcement>,
    ) -> Self {
        RoaTableEntry {
            definition,
            state: RoaTableEntryState::RoaAuthorizing,
            disallowed_by: vec![],
            authorizes,
            disallows,
        }
    }

    pub fn roa_disallowing(definition: RoaDefinition, disallows: Vec<Announcement>) -> Self {
        RoaTableEntry {
            definition,
            state: RoaTableEntryState::RoaDisallowing,
            disallowed_by: vec![],
            authorizes: vec![],
            disallows,
        }
    }

    pub fn roa_stale(definition: RoaDefinition) -> Self {
        RoaTableEntry {
            definition,
            state: RoaTableEntryState::RoaStale,
            disallowed_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn roa_no_announcement_info(definition: RoaDefinition) -> Self {
        RoaTableEntry {
            definition,
            state: RoaTableEntryState::RoaNoAnnouncementInfo,
            disallowed_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_asn(
        announcement: Announcement,
        disallowed_by: Vec<RoaDefinition>,
    ) -> Self {
        RoaTableEntry {
            definition: RoaDefinition::from(announcement),
            state: RoaTableEntryState::AnnouncementInvalidAsn,
            disallowed_by,
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_invalid_length(
        announcement: Announcement,
        disallowed_by: Vec<RoaDefinition>,
    ) -> Self {
        RoaTableEntry {
            definition: RoaDefinition::from(announcement),
            state: RoaTableEntryState::AnnouncementInvalidLength,
            disallowed_by,
            authorizes: vec![],
            disallows: vec![],
        }
    }

    pub fn announcement_not_found(announcement: Announcement) -> Self {
        RoaTableEntry {
            definition: RoaDefinition::from(announcement),
            state: RoaTableEntryState::AnnouncementNotFound,
            disallowed_by: vec![],
            authorizes: vec![],
            disallows: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaTable(Vec<RoaTableEntry>);

impl RoaTable {
    pub fn new(roas: Vec<RoaTableEntry>) -> Self {
        RoaTable(roas)
    }

    pub fn entries(&self) -> &Vec<RoaTableEntry> {
        &self.0
    }

    fn matching_defs(&self, state: RoaTableEntryState) -> Vec<&RoaDefinition> {
        self.matching_entries(state)
            .into_iter()
            .map(|e| &e.definition)
            .collect()
    }

    fn matching_entries(&self, state: RoaTableEntryState) -> Vec<&RoaTableEntry> {
        self.0.iter().filter(|e| e.state == state).collect()
    }
}

impl fmt::Display for RoaTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let entries = self.entries();

        let mut entry_map: HashMap<RoaTableEntryState, Vec<&RoaTableEntry>> = HashMap::new();
        for entry in entries.into_iter() {
            let state = entry.state();
            if !entry_map.contains_key(&state) {
                entry_map.insert(state, vec![]);
            }
            entry_map.get_mut(&state).unwrap().push(entry);
        }

        if entry_map.contains_key(&RoaTableEntryState::RoaNoAnnouncementInfo) {
            write!(f, "no BGP announcements known")
        } else {
            if let Some(valids) = entry_map.get(&RoaTableEntryState::RoaAuthorizing) {
                writeln!(f, "Authorizations causing VALID announcements:")?;
                for roa in valids {
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

            if let Some(invalids) = entry_map.get(&RoaTableEntryState::RoaDisallowing) {
                writeln!(f, "Authorizations causing INVALID announcements only:")?;
                for roa in invalids {
                    writeln!(f)?;
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                    writeln!(f)?;
                    writeln!(f, "\t\tDisallows:")?;
                    for ann in roa.disallows.iter() {
                        writeln!(f, "\t\t{}", ann)?;
                    }
                }
                writeln!(f)?;
            }

            if let Some(stales) = entry_map.get(&RoaTableEntryState::RoaStale) {
                writeln!(
                    f,
                    "Authorizations for which no announcements are found (possibly stale):"
                )?;
                writeln!(f)?;
                for roa in stales {
                    writeln!(f, "\tDefinition: {}", roa.definition)?;
                }
                writeln!(f)?;
            }

            if let Some(invalid_asn) = entry_map.get(&RoaTableEntryState::AnnouncementInvalidAsn) {
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
                entry_map.get(&RoaTableEntryState::AnnouncementInvalidLength)
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

            if let Some(not_found) = entry_map.get(&RoaTableEntryState::AnnouncementNotFound) {
                writeln!(f, "Announcements which are 'not found' (not covered by any of your authorizations):")?;
                for ann in not_found {
                    writeln!(f, "\tAnnouncement: {}", ann.definition)?;
                }
                writeln!(f)?;
            }

            Ok(())
        }
    }
}

//------------ RoaSummary --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaSummary(Vec<RoaSummmaryEntry>);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RoaSummmaryEntry {
    definition: RoaDefinition,
    state: RoaSummaryState,
}

impl fmt::Display for RoaSummmaryEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let state_str = match self.state {
            RoaSummaryState::Valid => "announcement 'valid'",
            RoaSummaryState::InvalidAsn => "announcement 'invalid': unauthorized asn",
            RoaSummaryState::InvalidLength => "announcement 'invalid': more specific than allowed",
            RoaSummaryState::NotFound => "announcement 'not found': not covered by your ROAs",
            RoaSummaryState::Stale => {
                "ROA does not cover any known announcement (stale or backup?)"
            }
            RoaSummaryState::NoInfo => "ROA exists, but no bgp info currently available",
        };
        write!(f, "{}\t{}", self.definition, state_str)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoaSummaryState {
    Valid,
    InvalidAsn,
    InvalidLength,
    NotFound,
    Stale,
    NoInfo,
}

impl From<RoaTable> for RoaSummary {
    fn from(table: RoaTable) -> Self {
        let mut entries: Vec<RoaSummmaryEntry> = vec![];
        for valid in table
            .matching_entries(RoaTableEntryState::RoaAuthorizing)
            .into_iter()
            .flat_map(|e| &e.authorizes)
        {
            entries.push(RoaSummmaryEntry {
                definition: valid.clone().into(),
                state: RoaSummaryState::Valid,
            })
        }

        for def in table.matching_defs(RoaTableEntryState::AnnouncementInvalidAsn) {
            entries.push(RoaSummmaryEntry {
                definition: def.clone(),
                state: RoaSummaryState::InvalidAsn,
            })
        }

        for def in table.matching_defs(RoaTableEntryState::AnnouncementInvalidLength) {
            entries.push(RoaSummmaryEntry {
                definition: def.clone(),
                state: RoaSummaryState::InvalidLength,
            })
        }

        for def in table.matching_defs(RoaTableEntryState::AnnouncementNotFound) {
            entries.push(RoaSummmaryEntry {
                definition: def.clone(),
                state: RoaSummaryState::NotFound,
            })
        }
        for def in table.matching_defs(RoaTableEntryState::RoaStale) {
            entries.push(RoaSummmaryEntry {
                definition: def.clone(),
                state: RoaSummaryState::Stale,
            })
        }
        for def in table.matching_defs(RoaTableEntryState::RoaNoAnnouncementInfo) {
            entries.push(RoaSummmaryEntry {
                definition: def.clone(),
                state: RoaSummaryState::NoInfo,
            })
        }
        RoaSummary(entries)
    }
}

impl fmt::Display for RoaSummary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for e in self.0.iter() {
            writeln!(f, "{}", e)?;
        }
        Ok(())
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::commons::bgp::{RoaSummary, RoaTable};

    // #[test]
    // fn print_roa_table() {
    //     let json = include_str!("../../../test-resources/bgp/expected_roa_table.json");
    //     let table: RoaTable = serde_json::from_str(json).unwrap();
    //
    //     println!("{}", table)
    // }
    //
    // #[test]
    // fn print_roa_table_summary() {
    //     let json = include_str!("../../../test-resources/bgp/expected_roa_table.json");
    //     let table: RoaTable = serde_json::from_str(json).unwrap();
    //     let summary: RoaSummary = table.into();
    //
    //     println!("{}", summary)
    // }
}
