use std::collections::HashMap;
use serde::Deserialize;
use super::claims::{ClaimSource, MatchExpression, SubstExpression};

pub struct ConfigDefaults {}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnect {
    pub issuer_url: String,

    pub client_id: String,

    pub client_secret: String,

    #[serde(default = "default_claims")]
    pub claims: Vec<ConfigAuthOpenIDConnectClaim>,

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
    // On by default for backward compatability.
    // See: https://github.com/NLnetLabs/krill/issues/614
    true
}


#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnectClaim {
    pub dest: String,
    pub source: Option<ClaimSource>,
    pub claim: String,
    #[serde(rename = "match")]
    pub match_expr: Option<MatchExpression>,
    pub subst: Option<SubstExpression>,
}

fn default_claims() -> Vec<ConfigAuthOpenIDConnectClaim> {
    vec![
        ConfigAuthOpenIDConnectClaim {
            dest: "id".into(),
            source: None,
            claim: "email".into(),
            match_expr: None,
            subst: None,
        },
        ConfigAuthOpenIDConnectClaim {
            dest: "id".into(),
            source: None,
            claim: "role".into(),
            match_expr: None,
            subst: None,
        },
    ]
}

