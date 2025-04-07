/// Definition of ASPA-related types before 0.10.0.
use rpki::ca::publication::Base64;
use rpki::repository::x509::Time;
use serde::{Deserialize, Serialize};
use crate::api::aspa::AspaDefinition;
use crate::server::ca::upgrades::pre_0_14_0::aspa::Pre0_14_0ProviderAs;


//------------ Pre0_10_0AspaDefinition ---------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0AspaDefinition {
    pub customer: Pre0_14_0ProviderAs, // string notation was used <0.10
    pub providers: Vec<Pre0_14_0ProviderAs>,
}

impl From<Pre0_10_0AspaDefinition> for AspaDefinition {
    fn from(old: Pre0_10_0AspaDefinition) -> Self {
        AspaDefinition {
            customer: old.customer.provider,
            providers: old.providers.into_iter().map(|o| o.provider).collect(),
        }
    }
}


//------------ Pre_0_10_0AspaObjectsUpdates ----------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0AspaObjectsUpdates {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub updated: Vec<Pre0_10_0AspaInfo>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<Pre0_10_0CustomerAsn>,
}


//------------ Pre_0_10_0AspaInfo --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0AspaInfo {
    pub definition: Pre0_10_0AspaDefinition,
    pub aspa: Base64, // Can't be parsed anymore
    pub since: Time,  // Creation time
}


//------------ Pre_0_10_0CustomerAsn -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10_0CustomerAsn(Pre0_14_0ProviderAs); // re-use ProviderAs for string parsing

impl From<Pre0_10_0CustomerAsn> for rpki::resources::Asn {
    fn from(pre: Pre0_10_0CustomerAsn) -> Self {
        pre.0.provider
    }
}
