mod cas_migration;
use rpki::ca::publication::Base64;
use rpki::repository::x509::Time;

use crate::commons::api::AspaDefinition;
use crate::commons::api::CustomerAsn;

pub use self::cas_migration::*;

mod pubd_migration;
pub use self::pubd_migration::*;

mod old_commands;
pub use self::old_commands::*;

mod old_events;
pub use self::old_events::*;

use super::pre_0_14_0::Pre0_14_0ProviderAs;

//------------ Pre0_14_0AspaDefinition ----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0AspaDefinition {
    pub customer: Pre0_14_0ProviderAs, // string notation was used <0.10
    pub providers: Vec<Pre0_14_0ProviderAs>,
}

impl From<Pre0_10_0AspaDefinition> for AspaDefinition {
    fn from(old: Pre0_10_0AspaDefinition) -> Self {
        AspaDefinition::new(
            old.customer.provider,
            old.providers.into_iter().map(|o| o.provider).collect(),
        )
    }
}

//------------ Pre_0_10_0AspaInfo ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0AspaInfo {
    pub definition: Pre0_10_0AspaDefinition,
    pub aspa: Base64, // Can't be parsed anymore
    pub since: Time,  // Creation time
}

//------------ Pre_0_10_0AspaObjectsUpdates -----------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0AspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub updated: Vec<Pre0_10_0AspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<CustomerAsn>,
}
