use std::collections::HashMap;

use crate::daemon::auth::common::config::Role;

pub type ConfigAuthUsers = HashMap<String, ConfigUserDetails>;

pub struct ConfigDefaults {}

impl ConfigDefaults {
    fn auth_user_role() -> Role {
        Role::Admin
    }

    fn auth_user_cas() -> Vec<String> {
        vec![]
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigUserDetails {
    #[serde(default = "ConfigDefaults::auth_user_role")]
    pub role: Role,

    #[serde(default = "ConfigDefaults::auth_user_cas")]
    pub cas: Vec<String>,

    pub password_hash: String,
}