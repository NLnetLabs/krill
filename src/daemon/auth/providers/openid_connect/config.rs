use std::collections::HashMap;

use serde::{de, Deserialize, Deserializer};

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

// Implement Serialize as well for this type as we serialize it when sending it
// as part of the login session state to the client. Make sure that it
// serializes to snake_case as that is what is expeced by the custom deserialize
// implementation below.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigAuthOpenIDConnectRole {
    Admin,
    GuiReadOnly,
    GuiReadWrite,
}

impl<'de> Deserialize<'de> for ConfigAuthOpenIDConnectRole {
    fn deserialize<D>(d: D) -> Result<ConfigAuthOpenIDConnectRole, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "admin" => Ok(ConfigAuthOpenIDConnectRole::Admin),
            "gui_read_only" => Ok(ConfigAuthOpenIDConnectRole::GuiReadOnly),
            "gui_read_write" => Ok(ConfigAuthOpenIDConnectRole::GuiReadWrite),
            _ => Err(de::Error::custom(format!(
                "expected \"admin\", \"gui_read_only\" or \"gui_read_write\", found : \"{}\"",
                string
            ))),
        }
    }
}

pub type ConfigAuthOpenIDConnectRoleMap = HashMap<ConfigAuthOpenIDConnectRole, String>;