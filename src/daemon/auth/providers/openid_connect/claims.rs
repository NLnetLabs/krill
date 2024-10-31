//! Processing OpenID Connect claims.

use std::sync::Arc;
use regex::{Regex, Replacer};
use serde::de::{Deserialize, Deserializer, Error as _};
use serde_json::{Number as JsonNumber, Value as JsonValue};
use crate::commons::KrillResult;
use crate::commons::error::Error;
use super::util::{FlexibleIdTokenClaims, FlexibleUserInfoClaims};
use super::config::ConfigAuthOpenIDConnectClaim;


//------------ Claims --------------------------------------------------------

pub struct Claims<'a> {
    claims_conf: &'a [ConfigAuthOpenIDConnectClaim],
    id_token_claims: &'a FlexibleIdTokenClaims,
    user_info_claims: Option<FlexibleUserInfoClaims>,

    id_standard: Option<JsonValue>,
    id_additional: Option<JsonValue>,
    user_standard: Option<JsonValue>,
    user_additional: Option<JsonValue>,
}

impl<'a> Claims<'a> {
    pub fn new(
        claims_conf: &'a [ConfigAuthOpenIDConnectClaim],
        id_token_claims: &'a FlexibleIdTokenClaims,
        user_info_claims: Option<FlexibleUserInfoClaims>,
    ) -> Self {
        Self {
            claims_conf,
            id_token_claims, user_info_claims,
            id_standard: None, id_additional: None,
            user_standard: None, user_additional: None,
        }
    }

    pub fn extract_id(&mut self) -> KrillResult<String> {
        self.extract_claim("id")
    }

    pub fn extract_role(&mut self) -> KrillResult<Arc<str>> {
        self.extract_claim("role").map(Into::into)
    }

    fn extract_claim(&mut self, dest: &str) -> KrillResult<String> {
        for conf in self.claims_conf.iter().filter(|conf| conf.dest == dest) {
            if let Some(res) = self.process_claim_conf(conf)? {
                return Ok(res)
            }
        }

        Err(Self::internal_error(
            format!("OpenID Connect: no value found for '{}' claim.", dest),
            None
        ))
    }

    fn process_claim_conf(
        &mut self, conf: &ConfigAuthOpenIDConnectClaim
    ) -> KrillResult<Option<String>> {
        use self::ClaimSource::*;

        match conf.source {
            Some(IdTokenStandardClaim) => {
                Self::process_claim_json(conf, self.id_standard()?)
            }
            Some(IdTokenAdditionalClaim) => {
                Self::process_claim_json(conf, self.id_additional()?)
            }
            Some(UserInfoStandardClaim) => {
                self.user_standard()?.and_then(|json| {
                    Self::process_claim_json(conf, json).transpose()
                }).transpose()
            }
            Some(UserInfoAdditionalClaim) => {
                self.user_additional()?.and_then(|json| {
                    Self::process_claim_json(conf, json).transpose()
                }).transpose()
            }
            None => {
                if let Some(res) = Self::process_claim_json(
                    conf, self.id_standard()?
                )? {
                    return Ok(Some(res))
                }
                if let Some(res) = Self::process_claim_json(
                    conf, self.id_additional()?
                )? {
                    return Ok(Some(res))
                }
                if let Some(res) = self.user_standard()?.and_then(|json| {
                    Self::process_claim_json(conf, json).transpose()
                }).transpose()? {
                    return Ok(Some(res))
                }
                self.user_additional()?.and_then(|json| {
                    Self::process_claim_json(conf, json).transpose()
                }).transpose()
            }
        }
    }

    fn id_standard(&mut self) -> KrillResult<&JsonValue> {
        if self.id_standard.is_none() {
            self.id_standard = Some(
                serde_json::to_value(self.id_token_claims).map_err(|_| {
                    Self::internal_error(
                        "OpenID Connect: \
                         failed to generate standard ID token claims",
                         None
                    )
                })?
            )
        }
        Ok(self.id_standard.as_ref().unwrap())
    }

    fn id_additional(&mut self) -> KrillResult<&JsonValue> {
        if self.id_additional.is_none() {
            self.id_additional = Some(
                serde_json::to_value(
                    self.id_token_claims.additional_claims()
                ).map_err(|_| {
                    Self::internal_error(
                        "OpenID Connect: \
                         failed to generate additional ID token claims",
                         None
                    )
                })?
            )
        }
        Ok(self.id_additional.as_ref().unwrap())
    }

    fn user_standard(&mut self) -> KrillResult<Option<&JsonValue>> {
        let claims = match self.user_info_claims.as_ref() {
            Some(claims) => claims,
            None => return Ok(None)
        };
        if self.user_standard.is_none() {
            self.user_standard = Some(
                serde_json::to_value(claims).map_err(|_| {
                    Self::internal_error(
                        "OpenID Connect: \
                         failed to generate standard user info claims",
                         None
                    )
                })?
            )
        }
        Ok(self.user_standard.as_ref())
    }

    fn user_additional(&mut self) -> KrillResult<Option<&JsonValue>> {
        let claims = match self.user_info_claims.as_ref() {
            Some(claims) => claims,
            None => return Ok(None)
        };
        if self.user_additional.is_none() {
            self.user_additional = Some(
                serde_json::to_value(claims.additional_claims()).map_err(|_| {
                    Self::internal_error(
                        "OpenID Connect: \
                         failed to generate standard user info claims",
                         None
                    )
                })?
            )
        }
        Ok(self.user_additional.as_ref())
    }

    fn process_claim_json(
        conf: &ConfigAuthOpenIDConnectClaim,
        json: &JsonValue,
    ) -> KrillResult<Option<String>> {
        let object = match json {
            JsonValue::Object(object) => object,
            _ => return Ok(None)
        };
        let value = match object.get(&conf.claim) {
            Some(value) => value,
            None => return Ok(None)
        };
        match value {
            JsonValue::Array(array) => Self::process_claim_array(conf, array),
            JsonValue::Bool(true) => Self::process_claim_str(conf, "true"),
            JsonValue::Bool(false) => Self::process_claim_str(conf, "false"),
            JsonValue::String(s) => Self::process_claim_str(conf, s),
            JsonValue::Number(num) => Self::process_claim_number(conf, num),
            _ => Ok(None)
        }
    }

    fn process_claim_array(
        conf: &ConfigAuthOpenIDConnectClaim,
        array: &[JsonValue],
    ) -> KrillResult<Option<String>> {
        for item in array {
            let res = match item {
                JsonValue::Bool(true) => {
                    Self::process_claim_str(conf, "true")?
                }
                JsonValue::Bool(false) => {
                    Self::process_claim_str(conf, "false")?
                }
                JsonValue::String(s) => {
                    Self::process_claim_str(conf, s)?
                }
                JsonValue::Number(num) => {
                    Self::process_claim_number(conf, num)?
                }
                _ => None
            };
            if let Some(res) = res {
                return Ok(Some(res))
            }
        }
        Ok(None)
    }

    fn process_claim_number(
        conf: &ConfigAuthOpenIDConnectClaim,
        num: &JsonNumber
    ) -> KrillResult<Option<String>> {
        Self::process_claim_str(conf, &num.to_string())
    }

    fn process_claim_str(
        conf: &ConfigAuthOpenIDConnectClaim,
        s: &str,
    ) -> KrillResult<Option<String>> {
        if let Some(expr) = conf.match_expr.as_ref() {
            match conf.subst.as_ref() {
                Some(subst) => {
                    if subst.no_expansion {
                        match expr.0.find(s) {
                            Some(m) => {
                                let mut res = String::with_capacity(s.len());
                                res.push_str(&s[..m.start()]);
                                res.push_str(&subst.expr);
                                res.push_str(&s[m.end()..]);
                                Ok(Some(res))
                            }
                            None => Ok(None)
                        }
                    }
                    else {
                        match expr.0.captures(s) {
                            Some(c) => {
                                let mut res = String::with_capacity(
                                    subst.expr.len()
                                );
                                c.expand(&subst.expr, &mut res);
                                Ok(Some(res))
                            }
                            None => Ok(None)
                        }
                    }
                }
                None => {
                    if expr.0.is_match(s) {
                        Ok(Some(s.into()))
                    }
                    else {
                        Ok(None)
                    }
                }
            }
        }
        else {
            // If there is no match expression, the value always matches and
            // we return it (even if there is a subst expression -- we just
            // ignore it).
            Ok(Some(s.into()))
        }
    }


    /// Log and convert the given error such that the detailed, possibly
    /// sensitive details are logged and only the high level statement
    /// about the error is passed back to the caller.
    fn internal_error<S>(msg: S, additional_info: Option<S>) -> Error
    where
        S: Into<String>,
    {
        let msg: String = msg.into();
        match additional_info {
            Some(additional_info) => {
                warn!("{} [additional info: {}]", msg, additional_info.into())
            }
            None => warn!("{}", msg),
        };
        Error::ApiLoginError(msg)
    }
}


//------------ MatchExpression -----------------------------------------------

#[derive(Clone, Debug)]
pub struct MatchExpression(Regex);

impl<'de> Deserialize<'de> for MatchExpression {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        String::deserialize(deserializer).and_then(|s| {
            Regex::try_from(s).map_err(D::Error::custom)
        }).map(Self)
    }
}


//------------ SubstExpression -----------------------------------------------

#[derive(Clone, Debug)]
pub struct SubstExpression {
    expr: String,
    no_expansion: bool,
}

impl<'de> Deserialize<'de> for SubstExpression {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D
    ) -> Result<Self, D::Error> {
        let mut expr = String::deserialize(deserializer)?;
        let no_expansion = expr.no_expansion().is_some();
        Ok(Self { expr, no_expansion })
    }
}


//------------ ClaimSource ---------------------------------------------------

#[derive(Clone, Copy, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ClaimSource {
    IdTokenStandardClaim,
    IdTokenAdditionalClaim,
    UserInfoStandardClaim,
    UserInfoAdditionalClaim,
}

impl std::fmt::Display for ClaimSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::ClaimSource::*;

        f.write_str(
            match self {
                IdTokenStandardClaim => "id-token-standard-claim",
                IdTokenAdditionalClaim => "id-token-additional-claim",
                UserInfoStandardClaim => "user-info-standard-claim",
                UserInfoAdditionalClaim => "user-info-additional-claim",
            }
        )
    }
}

impl<'de> Deserialize<'de> for ClaimSource {
    fn deserialize<D>(
        d: D,
    ) -> Result<ClaimSource, D::Error>
    where
        D: Deserializer<'de>,
    {
        use self::ClaimSource::*;

        match <&'de str>::deserialize(d)? {
            "id-token-standard-claim" => Ok(IdTokenStandardClaim),
            "id-token-additional-claim" => Ok(IdTokenAdditionalClaim),
            "user-info-standard-claim" => Ok(UserInfoStandardClaim),
            "user-info-additional-claim" => Ok(UserInfoAdditionalClaim),
            s => {
                Err(serde::de::Error::custom(
                    format!(
                        "expected \"id-token-additional-claim\", \
                        \"id-token-standard-claim\", \
                        \"user-info-standard-claim\", or \
                        \"user-info-additional-claim\", found : \"{}\"",
                    s
                )))
            }
        }
    }
}

