use std::collections::HashMap;

use serde::{de, Deserialize, Deserializer};

use crate::daemon::auth::common::config::Role;

pub struct ConfigDefaults {}

impl ConfigDefaults {
    fn roles_source() -> ConfigAuthOpenIDConnectRoleSource {
        ConfigAuthOpenIDConnectRoleSource::IdTokenAdditionalClaim
    }

    fn roles_jmespath() -> String {
        "role".to_string()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnect {
    pub issuer_url: String,

    pub client_id: String,

    pub client_secret: String,

    #[serde(default)]
    pub roles: ConfigAuthOpenIDConnectRoles,

    #[serde(default)]
    pub http_debug_log_enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnectRoles {
    #[serde(default = "ConfigDefaults::roles_source")]
    pub source: ConfigAuthOpenIDConnectRoleSource,

    #[serde(default = "ConfigDefaults::roles_jmespath")]
    pub jmespath: String,

    pub mapping: Option<ConfigAuthOpenIDConnectRoleMap>,
}

impl Default for ConfigAuthOpenIDConnectRoles {
    fn default() -> Self {
        ConfigAuthOpenIDConnectRoles {
            source: ConfigDefaults::roles_source(),
            jmespath: ConfigDefaults::roles_jmespath(),
            mapping: None,
        }
    }
}

#[derive(Clone, Debug, Display)]
pub enum ConfigAuthOpenIDConnectRoleSource {
    IdTokenAdditionalClaim,
    UserInfoAdditionalClaim,
}

impl<'de> Deserialize<'de> for ConfigAuthOpenIDConnectRoleSource {
    fn deserialize<D>(d: D) -> Result<ConfigAuthOpenIDConnectRoleSource, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "id_token_additional_claim" => Ok(ConfigAuthOpenIDConnectRoleSource::IdTokenAdditionalClaim),
            "user_info_additional_claim" => Ok(ConfigAuthOpenIDConnectRoleSource::UserInfoAdditionalClaim),
            _ => Err(de::Error::custom(format!(
                "expected \"id_token_additional_claim\" or \"user_info_additional_claim\", found : \"{}\"",
                string
            ))),
        }
    }
}

pub type ConfigAuthOpenIDConnectRoleMap = HashMap<Role, String>;