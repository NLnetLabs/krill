use crate::commons::api::RoaDefinition;
use crate::commons::bgp::Announcement;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoaTableEntryState {
    RoaAuthorizing,
    RoaStale,
    RoaDisallowing,
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
}

//------------ Tests -------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn announcement(s: &str) -> Announcement {
        let def = definition(s);
        Announcement::from(def)
    }

    fn definition(s: &str) -> RoaDefinition {
        RoaDefinition::from_str(s).unwrap()
    }

    #[test]
    fn roa_table_json() {
        let roa_authorizing = definition("10.0.0.0/23-24 => 64496");
        let ann_authz_1 = announcement("10.0.0.0/24 => 64496");
        let ann_authz_2 = announcement("10.0.1.0/24 => 64496");
        let ann_invalid_1 = announcement("10.0.0.0/24 => 64497");
        let ann_invalid_2 = announcement("10.0.1.0/24 => 64497");
        let ann_invalid_3 = announcement("10.0.4.0/24 => 64497");

        let ann_not_found = announcement("10.0.2.0/24 => 64497");
        let roa_stale = definition("10.0.3.0/24 => 64497");
        let roa_disallowing = definition("10.0.4.0/24 => 0");

        let mut entries = vec![];
        entries.push(RoaTableEntry::roa_authorizing(
            roa_authorizing,
            vec![ann_authz_1, ann_authz_2],
            vec![ann_invalid_1.clone(), ann_invalid_2.clone()],
        ));
        entries.push(RoaTableEntry::announcement_invalid_length(
            ann_invalid_1,
            vec![roa_authorizing],
        ));
        entries.push(RoaTableEntry::announcement_invalid_length(
            ann_invalid_2,
            vec![roa_authorizing],
        ));
        entries.push(RoaTableEntry::announcement_invalid_length(
            ann_invalid_3.clone(),
            vec![roa_disallowing],
        ));
        entries.push(RoaTableEntry::announcement_not_found(ann_not_found));
        entries.push(RoaTableEntry::roa_stale(roa_stale));
        entries.push(RoaTableEntry::roa_disallowing(
            roa_disallowing,
            vec![ann_invalid_3],
        ));

        let table = RoaTable(entries);

        eprintln!("{}", serde_json::to_string_pretty(&table).unwrap());
    }
}
