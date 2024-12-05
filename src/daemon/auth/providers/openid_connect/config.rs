use std::collections::HashMap;
use serde::Deserialize;
use super::claims::{MatchRule, TransformationRule};

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigAuthOpenIDConnect {
    pub issuer_url: String,

    pub client_id: String,

    pub client_secret: String,

    #[serde(default = "default_id_claims")]
    pub id_claims: Vec<TransformationRule>,

    #[serde(default = "default_role_claims")]
    pub role_claims: Vec<TransformationRule>,

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

fn default_id_claims() -> Vec<TransformationRule> {
    vec![
        TransformationRule::Match(MatchRule {
            source: None,
            claim: "email".into(),
            match_expr: None,
            subst: None,
        }),
    ]
}

fn default_role_claims() -> Vec<TransformationRule> {
    vec![
        TransformationRule::Match(MatchRule {
            source: None,
            claim: "role".into(),
            match_expr: None,
            subst: None,
        }),
    ]
}

