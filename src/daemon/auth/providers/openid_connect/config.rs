use std::collections::HashMap;

use serde::{de, Deserialize, Deserializer};

use crate::daemon::auth::common::config::Role;

pub struct ConfigDefaults {}

impl ConfigDefaults {
    fn id_claim() -> ConfigAuthOpenIDConnectClaim {
        ConfigAuthOpenIDConnectClaim {
            source: ConfigAuthOpenIDConnectClaimSource::IdTokenStandardClaim,
            jmespath: "email".to_string(),
        }
    }

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

    pub role_map: Option<ConfigAuthOpenIDConnectRoleMap>,

    #[serde(default)]
    pub extra_login_scopes: Vec<String>,

    #[serde(default)]
    pub extra_login_params: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnectClaims {
    #[serde(default = "ConfigDefaults::id_claim")]
    pub id: ConfigAuthOpenIDConnectClaim,
    #[serde(default = "ConfigDefaults::role_claim")]
    pub role: ConfigAuthOpenIDConnectClaim,
    #[serde(default = "ConfigDefaults::cas_claim")]
    pub cas: ConfigAuthOpenIDConnectClaim,
}

impl Default for ConfigAuthOpenIDConnectClaims {
    fn default() -> Self {
        ConfigAuthOpenIDConnectClaims {
            id: ConfigDefaults::id_claim(),
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

#[derive(Clone, Debug)]
pub enum ConfigAuthOpenIDConnectClaimSource {
    ConfigFile,
    IdTokenStandardClaim,
    IdTokenAdditionalClaim,
    UserInfoStandardClaim,
    UserInfoAdditionalClaim,
}

impl std::fmt::Display for ConfigAuthOpenIDConnectClaimSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigAuthOpenIDConnectClaimSource::ConfigFile              => write!(f, "config-file"),
            ConfigAuthOpenIDConnectClaimSource::IdTokenStandardClaim    => write!(f, "id-token-standard-claim"),
            ConfigAuthOpenIDConnectClaimSource::IdTokenAdditionalClaim  => write!(f, "id-token-additional-claim"),
            ConfigAuthOpenIDConnectClaimSource::UserInfoStandardClaim   => write!(f, "user-info-standard-claim"),
            ConfigAuthOpenIDConnectClaimSource::UserInfoAdditionalClaim => write!(f, "user-info-additional-claim"),
        }
    }
}

impl<'de> Deserialize<'de> for ConfigAuthOpenIDConnectClaimSource {
    fn deserialize<D>(d: D) -> Result<ConfigAuthOpenIDConnectClaimSource, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        match string.as_str() {
            "config-file"                => Ok(ConfigAuthOpenIDConnectClaimSource::ConfigFile),
            "id-token-standard-claim"    => Ok(ConfigAuthOpenIDConnectClaimSource::IdTokenStandardClaim),
            "id-token-additional-claim"  => Ok(ConfigAuthOpenIDConnectClaimSource::IdTokenAdditionalClaim),
            "user-info-standard-claim"   => Ok(ConfigAuthOpenIDConnectClaimSource::UserInfoStandardClaim),
            "user-info-additional-claim" => Ok(ConfigAuthOpenIDConnectClaimSource::UserInfoAdditionalClaim),
            _ => Err(de::Error::custom(format!(
                "expected \"config-file\", \"id-token-additional-claim\", \"id-token-standard-claim\", \"user-info-standard-claim\", or \"user-info-additional-claim\", found : \"{}\"",
                string
            ))),
        }
    }
}

pub type ConfigAuthOpenIDConnectRoleMap = HashMap<Role, String>;