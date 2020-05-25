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

// tested as part of tests in analyser.rs
