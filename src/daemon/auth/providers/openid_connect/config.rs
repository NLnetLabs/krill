use std::collections::HashMap;

use serde::Deserialize;

pub struct ConfigDefaults {}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnect {
    pub issuer_url: String,

    pub client_id: String,

    pub client_secret: String,

    pub id_claim: String,

    #[serde(default)]
    pub extra_login_scopes: Vec<String>,

    #[serde(default)]
    pub extra_login_params: HashMap<String, String>,

    #[serde(default = "default_prompt_for_login")]
    pub prompt_for_login: bool,

    #[serde(default)]
    pub logout_url: Option<String>,

    #[serde(default)]
    pub insecure: bool,
}

fn default_prompt_for_login() -> bool {
    // On by default for backward compatability. See: https://github.com/NLnetLabs/krill/issues/614
    true
}

