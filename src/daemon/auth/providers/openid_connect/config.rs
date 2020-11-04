use std::collections::HashMap;

use serde::{de, Deserialize, Deserializer};

use crate::daemon::auth::common::config::Role;

pub struct ConfigDefaults {}

impl ConfigDefaults {
    fn role_claim() -> ConfigAuthOpenIDConnectClaim {
        ConfigAuthOpenIDConnectClaim {
            source: ConfigAuthOpenIDConnectClaimSource::IdTokenAdditionalClaim,
            jmespath: "role".to_string(),
        }
    }

    fn cas_claim() -> ConfigAuthOpenIDConnectClaim {
        ConfigAuthOpenIDConnectClaim {
            source: ConfigAuthOpenIDConnectClaimSource::IdTokenAdditionalClaim,
            jmespath: "cas".to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnect {
    pub issuer_url: String,

    pub client_id: String,

    pub client_secret: String,

    #[serde(default)]
    pub claims: ConfigAuthOpenIDConnectClaims,

    #[serde(default)]
    pub http_debug_log_enabled: bool,

    pub role_map: Option<ConfigAuthOpenIDConnectRoleMap>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnectClaims {
    #[serde(default = "ConfigDefaults::role_claim")]
    pub role: ConfigAuthOpenIDConnectClaim,
    #[serde(default = "ConfigDefaults::cas_claim")]
    pub cas: ConfigAuthOpenIDConnectClaim,
}

impl Default for ConfigAuthOpenIDConnectClaims {
    fn default() -> Self {
        ConfigAuthOpenIDConnectClaims {
            role: ConfigDefaults::role_claim(),
            cas: ConfigDefaults::cas_claim(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnectClaim {
    pub source: ConfigAuthOpenIDConnectClaimSource,
    pub jmespath: String,
}

#[derive(Clone, Debug, Display)]
pub enum ConfigAuthOpenIDConnectClaimSource {
    IdTokenStandardClaim,
    IdTokenAdditionalClaim,
    UserInfoStandardClaim,
    UserInfoAdditionalClaim,
}

impl<'de> Deserialize<'de> for ConfigAuthOpenIDConnectClaimSource {
    fn deserialize<D>(d: D) -> Result<ConfigAuthOpenIDConnectClaimSource, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "id_token_standard_claim" => Ok(ConfigAuthOpenIDConnectClaimSource::IdTokenAdditionalClaim),
            "id_token_additional_claim" => Ok(ConfigAuthOpenIDConnectClaimSource::IdTokenStandardClaim),
            "user_info_standard_claim" => Ok(ConfigAuthOpenIDConnectClaimSource::UserInfoAdditionalClaim),
            "user_info_additional_claim" => Ok(ConfigAuthOpenIDConnectClaimSource::UserInfoStandardClaim),
            _ => Err(de::Error::custom(format!(
                "expected \"id_token_additional_claim\", \"id_token_standard_claim\", \"user_info_standard_claim\", or \"user_info_additional_claim\", found : \"{}\"",
                string
            ))),
        }
    }
}

pub type ConfigAuthOpenIDConnectRoleMap = HashMap<Role, String>;