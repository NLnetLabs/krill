//! Stateless implementation of an OAuth 2.0 "confidential" client and OpenID Connect 1.0 "relying party".
//!
//! Acts as an OAuth 2.0 "confidential" client on behalf of the Krill Lagosta web UI (as opposed to the UI itself acting
//! as an OAuth 2.0 "public" client). Intended to be compliant with the following OAuth 2.0 and OpenID Connect 1.0
//! specifications:
//!
//!   - [The OAuth 2.0 Authorization Framework RFC 6749][rfc6749]
//!   - [OAuth 2.0 Token Revocation][rfc7009]
//!   - [OpenID Connect Core 1.0 incorporating errata set 1][openid-connect-core-1_0]
//!   - [OpenID Connect Discovery 1.0 incorporating errata set 1][openid-connect-discovery-1_0] (excluding WebFinger)
//!   - [OpenID Connect RP-Initiated Logout 1.0 - draft 01][openid-connect-rpinitiated-1_0]
//!
//! Compliant OpenID Connect 1.0 providers (OPs) MUST support:
//!   - [OpenID Connect Discovery 1.0][openid-connect-discovery-1_0]
//!   - Either [OpenID Connect RP-Initiated Logout 1.0][openid-connect-rpinitiated-1_0] or [OAuth 2.0 Token Revocation][rfc7009]
//!
//! [rfc6749]: https://tools.ietf.org/html/rfc6749
//! [rfc7009]: https://tools.ietf.org/html/rfc7009
//! [openid-connect-core-1_0]: https://openid.net/specs/openid-connect-core-1_0.html
//! [openid-connect-discovery-1_0]: https://openid.net/specs/openid-connect-discovery-1_0.html
//! [openid-connect-rpinitiated-1_0]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

use std::ops::Deref;
use std::{path::PathBuf, sync::RwLockReadGuard};
use std::sync::Arc;
use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    sync::RwLock,
};

use basic_cookies::Cookie;
use hyper::header::{HeaderValue, SET_COOKIE};
use jmespatch as jmespath;
use jmespath::ToJmespath;

use openidconnect::{core::CoreRevocableToken, AccessToken, RequestTokenError, RevocationErrorResponseType};
use openidconnect::{
    core::{
        CoreAuthPrompt, CoreErrorResponseType, CoreIdTokenVerifier, CoreJwsSigningAlgorithm, CoreResponseMode,
        CoreResponseType,
    },
    RevocationUrl,
};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    RedirectUrl, RefreshToken, Scope,
};
use openidconnect::UserInfoError;

use urlparse::{urlparse, GetQuery};

use crate::commons::error::Error;
use crate::commons::util::sha256;
use crate::commons::KrillResult;
use crate::commons::{actor::ActorDef, api::Token};
use crate::daemon::auth::common::crypt;
use crate::daemon::auth::common::session::*;
use crate::daemon::auth::providers::config_file::config::ConfigUserDetails;
use crate::daemon::auth::providers::openid_connect::config::ConfigAuthOpenIDConnectClaims;
use crate::daemon::auth::providers::openid_connect::httpclient::logging_http_client;
use crate::daemon::auth::providers::openid_connect::jmespathext;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser};
use crate::daemon::config::Config;
use crate::daemon::http::auth::url_encode;
use crate::daemon::http::auth::AUTH_CALLBACK_ENDPOINT;
use crate::daemon::http::HttpResponse;

use super::config::{
    ConfigAuthOpenIDConnect, ConfigAuthOpenIDConnectClaim, ConfigAuthOpenIDConnectClaimSource as ClaimSource,
};
use super::util::{
    FlexibleClient, FlexibleIdTokenClaims, FlexibleTokenResponse, FlexibleUserInfoClaims, LogOrFail, WantedMeta,
};

// On modern browsers (Chrome >= 51, Edge >= 16, Firefox >= 60 & Safari >= 12) the "__Host" prefix is a defence-in-depth
// measure that causes the browser to further restrict access to the cookie, permitting access only if the cookie was
// set with the "secure" attribute from a secure (HTTPS) origin with path "/" and WITHOUT a "domain" attribute.
// See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes
const NONCE_COOKIE_NAME: &str = "__Host-krill_login_nonce";
const CSRF_COOKIE_NAME: &str = "__Host-krill_login_csrf_hash";
const LOGIN_SESSION_STATE_KEY_PATH: &str = "login_session_state.key"; // TODO: decide on proper location

#[allow(clippy::enum_variant_names)]
enum TokenKind {
    AccessToken,
    RefreshToken,
    IdToken,
}

impl From<TokenKind> for String {
    fn from(token_kind: TokenKind) -> Self {
        match token_kind {
            TokenKind::AccessToken => String::from("access_token"),
            TokenKind::RefreshToken => String::from("refresh_token"),
            TokenKind::IdToken => String::from("id_token"),
        }
    }
}

impl From<TokenKind> for &'static str {
    fn from(token_kind: TokenKind) -> Self {
        match token_kind {
            TokenKind::AccessToken => "access_token",
            TokenKind::RefreshToken => "refresh_token",
            TokenKind::IdToken => "id_token",
        }
    }
}

enum LogoutMode {
    OAuth2TokenRevocation {
        revocation_url: String,
        post_revocation_redirect_url: String,
    },
    OperatorProvidedLogout {
        operator_provided_logout_url: String,
    },
    ReturnToUI {
        url: String,
    },
    RPInitiatedLogout {
        provider_url: String,
        post_logout_redirect_url: String,
    },
}

pub struct ProviderConnectionProperties {
    client: FlexibleClient,
    email_scope_supported: bool,
    userinfo_endpoint_supported: bool,
    logout_mode: LogoutMode,
}

pub struct OpenIDConnectAuthProvider {
    config: Arc<Config>,
    session_cache: Arc<LoginSessionCache>,
    session_key: Vec<u8>,
    conn: Arc<RwLock<Option<ProviderConnectionProperties>>>,
}

impl OpenIDConnectAuthProvider {
    pub fn new(config: Arc<Config>, session_cache: Arc<LoginSessionCache>) -> KrillResult<Self> {
        let session_key = Self::init_session_key(&config.data_dir)?;

        Ok(OpenIDConnectAuthProvider {
            config,
            session_cache,
            session_key,
            conn: Arc::new(RwLock::new(None)),
        })
    }

    fn initialize_connection_if_needed(&self) -> KrillResult<()> {
        let mut conn_guard = self.conn
            .write()
            .map_err(|err| OpenIDConnectAuthProvider::internal_error(
                "Unable to initialize provider connection: Unable to acquire internal lock",
                Some(&err.to_string()),
            ))?;

        if conn_guard.is_none() {
            *conn_guard = Some(self.initialize_connection()?);
        }

        Ok(())
    }

    fn initialize_connection(&self) -> KrillResult<ProviderConnectionProperties> {
        trace!("OpenID Connect: Initializing provider connection...");
        let meta = self.discover()?;
        let (email_scope_supported, userinfo_endpoint_supported, logout_mode) =
            self.check_provider_capabilities(&meta)?;
        let client = self.build_client(meta, &logout_mode)?;
        let conn = ProviderConnectionProperties {
            client,
            email_scope_supported,
            userinfo_endpoint_supported,
            logout_mode,
        };
        trace!("OpenID Connect: Provider connection initialized");
        Ok(conn)
    }

    /// Discover the OpenID Connect: identity provider details via the
    /// https://openid.net/specs/openid-connect-discovery-1_0.html spec defined
    /// discovery endpoint of the provider, e.g.
    ///   https://<provider.domain>/<something/.well-known/openid-configuration
    /// Via which we can discover both endpoint URIs and capability flags.
    fn discover(&self) -> KrillResult<WantedMeta> {
        // Read from config the OpenID Connect identity provider discovery URL.
        // Strip off /.well-known/openid-configuration because the openid-connect
        // crate wants to add this itself and will fail if it is already present
        // in the URL.
        let issuer = self.oidc_conf()?.issuer_url.clone();
        let issuer = issuer.trim_end_matches("/.well-known/openid-configuration");
        let issuer = IssuerUrl::new(issuer.to_string())?;

        info!(
            "OpenID Connect: Discovering provider details using issuer {}",
            &issuer.as_str()
        );

        // Contact the OpenID Connect: identity provider discovery endpoint to
        // learn about and configure ourselves to talk to it.
        let meta = WantedMeta::discover(&issuer, logging_http_client).map_err(|e| {
            Error::Custom(format!(
                "OpenID Connect: Discovery failed with issuer {}: {}",
                issuer.to_string(),
                e.to_string()
            ))
        })?;

        Ok(meta)
    }

    /// Verify that the OpenID Connect: discovery metadata indicates that the
    /// provider has support for the features that we require.
    fn check_provider_capabilities(&self, meta: &WantedMeta) -> KrillResult<(bool, bool, LogoutMode)> {
        // TODO: verify token_endpoint_auth_methods_supported?
        // TODO: verify response_types_supported?
        let mut ok = true;
        let mut email_scope_supported = false;

        info!("Verifying OpenID Connect: Provider capabilities..");

        // From: https://openid.net/specs/openid-connect-discovery-1_0.html
        // response_modes_supported
        //     OPTIONAL. JSON array containing a list of the OAuth 2.0
        //     response_mode values that this OP supports, as specified in OAuth
        //     2.0 Multiple Response Type Encoding Practices [OAuth.Responses].
        //     If omitted, the default for Dynamic OpenID Providers is
        //     ["query", "fragment"].
        if meta.response_modes_supported().is_some() {
            // Some modes are specified, do they include "query"?
            if is_supported_opt!(meta.response_modes_supported(), CoreResponseMode::Query)
                .log_or_fail("response_modes_supported", Some("query"))
                .is_err()
            {
                ok = false;
            }
        }

        // From: https://openid.net/specs/openid-connect-discovery-1_0.html
        // id_token_signing_alg_values_supported
        //     REQUIRED. JSON array containing a list of the JWS signing
        //     algorithms (alg values) supported by the OP for the ID Token to
        //     encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be
        //     included. The value none MAY be supported, but MUST NOT be used
        //     unless the Response Type used returns no ID Token from the
        //     Authorization Endpoint (such as when using the Authorization
        //     Code Flow).
        if is_supported!(
            meta.id_token_signing_alg_values_supported(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256
        )
        .log_or_fail("id_token_signing_alg_values_supported", Some("RS256"))
        .is_err()
        {
            // According to the spec quoted above RS256 MUST be supported so
            // this OpenID Connect provider is not spec compliant.
            ok = false;
        }

        // From: https://openid.net/specs/openid-connect-discovery-1_0.html
        // scopes_supported
        //     RECOMMENDED. JSON array containing a list of the OAuth 2.0
        //     [RFC6749] scope values that this server supports. The server MUST
        //     support the openid scope value. Servers MAY choose not to
        //     advertise some supported scope values even when this parameter is
        //     used, although those defined in [OpenID.Core] SHOULD be listed,
        //     if supported.
        if is_supported_val_opt!(meta.scopes_supported(), Scope::new("openid".to_string()))
            .log_or_fail("scopes_supported", Some("openid"))
            .is_err()
        {
            ok = false;
        }

        if is_supported_val_opt!(meta.scopes_supported(), Scope::new("email".to_string())).is_some() {
            email_scope_supported = true;
        }

        // From: https://openid.net/specs/openid-connect-discovery-1_0.html
        // userinfo_endpoint
        //     RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core].
        //     This URL MUST use the https scheme and MAY contain port, path,
        //     and query parameter components.
        let userinfo_endpoint_supported = meta.userinfo_endpoint().is_some();

        // end_session_endpoint is not required to exist by the OpenID Connect discovery spec, nor is the operator
        // required to configure a custom logout URL, but we want some way to log the user out so if one of these is not
        // set, fallback to a local Krill only logout with post-logout-redirect to the Krill UI index page.
        //
        // The following logic should be used:
        //
        //   -------------------|-------------------|------------------|---------------------------------------------
        //   Config File logout | RP-Initiated      | Token Revocation | Action taken
        //   URL specified?	    | Logout supported?	| supported?       | by Krill
        //   -------------------|-------------------|------------------|---------------------------------------------
        //   no	                | no                | no               | Direct the user to the Krill login page
        //   no	                | no                | yes              | Revoke the token then direct the user to the
        //                      |                   |                  | Krill login page.
        //   no	                | yes               | no               | Direct the user to the customer logout portal
        //                      |                   |                  | If redirected back to Krill, direct the user
        //                      |                   |                  | to the login page.
        //   no	                | yes               | yes              | Behave as if only RP-Initiated Logout is
        //                      |                   |                  | supported
        //   yes                | no                | no               | Direct the user to the configured logout URL
        //   yes                | no                | yes              | Revoke the token then direct the user to the
        //                      |                   |                  | configured logout URL
        //   yes                | yes               | no               | Behave as if only RP-Initiated Logout is NOT
        //                      |                   |                  | supported
        //   yes                | yes               | yes              | Behave as if only RP-Initiated Logout is NOT
        //                      |                   |                  | supported
        //   -------------------|-------------------|------------------|---------------------------------------------

        let config_file_url = self.oidc_conf()?.logout_url.as_ref();
        let mut rp_initiated_logout_url = meta.additional_metadata().end_session_endpoint.as_ref();
        let mut revocation_url = meta.additional_metadata().revocation_endpoint.as_ref();
        let service_uri = self.config.service_uri().as_str().to_string();

        if let Some(rev_url) = revocation_url {
            // From: https://tools.ietf.org/html/rfc7009#section-2
            //   2. Token Revocation
            //     The client requests the revocation of a particular token by making an
            //     HTTP POST request to the token revocation endpoint URL.  This URL
            //     MUST conform to the rules given in [RFC6749], Section 3.1.  Clients
            //     MUST verify that the URL is an HTTPS URL.
            if urlparse(rev_url).scheme != "https" {
                warn!("OpenID Connect: Ignoring insecure revocation_endpoint '{}'", rev_url);
                revocation_url = None;
            }
        }

        if let Some(rpinit_url) = &meta.additional_metadata().end_session_endpoint {
            // From: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
            //   end_session_endpoint
            //     REQUIRED. URL at the OP to which an RP can perform a redirect to request that the End-User be
            //     logged out at the OP. This URL MUST use the https scheme and MAY contain port, path, and query
            //     parameter components.
            if urlparse(rpinit_url).scheme != "https" {
                warn!(
                    "OpenID Connect: Ignoring insecure end_session_endpoint '{}'",
                    rpinit_url
                );
                rp_initiated_logout_url = None;
            }
        }

        let logout_mode = match (config_file_url, rp_initiated_logout_url, revocation_url) {
            (None, None, None) => LogoutMode::ReturnToUI { url: service_uri },
            (None, None, Some(rev_url)) => LogoutMode::OAuth2TokenRevocation {
                revocation_url: rev_url.clone(),
                post_revocation_redirect_url: service_uri,
            },
            (None, Some(rpinit_url), _) => LogoutMode::RPInitiatedLogout {
                provider_url: rpinit_url.clone(),
                post_logout_redirect_url: service_uri,
            },
            (Some(config_url), _, None) => LogoutMode::OperatorProvidedLogout {
                operator_provided_logout_url: config_url.clone(),
            },
            (Some(config_url), _, Some(rev_url)) => LogoutMode::OAuth2TokenRevocation {
                revocation_url: rev_url.clone(),
                post_revocation_redirect_url: config_url.clone(),
            },
        };

        match ok {
            true => Ok((email_scope_supported, userinfo_endpoint_supported, logout_mode)),
            false => Err(Error::Custom(
                "OpenID Connect: The provider lacks support for one or more required capabilities.".to_string(),
            )),
        }
    }

    fn build_client(&self, meta: WantedMeta, logout_mode: &LogoutMode) -> KrillResult<FlexibleClient> {
        // Read from config the credentials we should use to authenticate
        // ourselves with the identity provider. These details should have been
        // obtained by the Krill operator when they created a registration for
        // their Krill instance with their identity provider.
        let oidc_conf = self.oidc_conf()?;
        let client_id = ClientId::new(oidc_conf.client_id.clone());
        let client_secret = ClientSecret::new(oidc_conf.client_secret.clone());

        // Create a client we can use to communicate with the provider based on
        // what we just learned and using the credentials we read from config
        // above.
        let client = FlexibleClient::from_provider_metadata(meta, client_id, Some(client_secret));

        // Note: we still haven't actually verified that the client id and
        // secret are correct, that will only happen when we try to exchange a
        // temporary code for access and id tokens.

        // Configure the client to instruct the 3rd party login form that after
        // successful login it should redirect, via the client browser, to the
        // Krill authentication callback endpoint. When the callback is invoked
        // it will come through to us so that we can exchange the temporary code
        // for access and id tokens.
        let redirect_uri = RedirectUrl::new(
            self.config
                .service_uri()
                .join(AUTH_CALLBACK_ENDPOINT.trim_start_matches('/').as_bytes())
                .to_string(),
        )?;

        // Log the redirect URI to help the operator in the event that the
        // OpenID Connect: provider complains that the redirect URI doesn't match
        // that configured at the provider.
        debug!("OpenID Connect: Redirect URI set to {}", redirect_uri.to_string());

        let mut client = client.set_redirect_uri(redirect_uri);

        if let LogoutMode::OAuth2TokenRevocation { revocation_url, .. } = logout_mode {
            client = client.set_revocation_uri(RevocationUrl::new(revocation_url.to_owned())?);
        }

        Ok(client)
    }

    fn build_rpinitiated_logout_url(
        &self,
        provider_url: &str,
        post_logout_redirect_url: &str,
        id_token: Option<&String>,
    ) -> KrillResult<String> {
        // Ask Lagosta to direct the user first the to OpenID Connect provider logout page, and ask it
        // to then redirect post-logout back to the Krill UI landing page.
        // TODO: Should we also use any of other parameters defined in the RP Initiated Logout 1.0 spec?
        // See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
        //      https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
        // E.g. state or ui_locales?

        // From https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout:
        //   "An id_token_hint carring an ID Token for the RP is also REQUIRED when requesting
        //    post-logout redirection"
        let id_token = id_token.ok_or_else(|| Error::custom("Missing id token"))?;
        Ok(format!(
            "{}?post_logout_redirect_uri={}&id_token_hint={}",
            provider_url,
            url_encode(post_logout_redirect_url)?,
            url_encode(id_token)?
        ))
    }

    fn try_revoke_token(&self, session: &ClientSession) -> Result<(), RevocationErrorResponseType> {
        // Connect to the OpenID Connect provider OAuth 2.0 token revocation endpoint to terminate the
        // provider session
        // From: https://tools.ietf.org/html/rfc7009#section-2
        //   "Implementations MUST support the revocation of refresh tokens and SHOULD support the
        //    revocation of access tokens (see Implementation Note)."
        let token_to_revoke = if let Some(token) = session.get_secret(TokenKind::RefreshToken.into()) {
            CoreRevocableToken::from(RefreshToken::new(token.clone()))
        } else if let Some(token) = session.get_secret(TokenKind::AccessToken.into()) {
            CoreRevocableToken::from(AccessToken::new(token.clone()))
        } else {
            return Err(RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(
                "Internal error: Token revocation attempted without a token".to_string(),
            )));
        };

        trace!("OpenID Connect: Revoking token for user: \"{}\"", &session.id);
        trace!("OpenID Connect: Submitting RFC-7009 section 2 Token Revocation request");
        let lock_guard = self.get_connection()
            .map_err(|err| RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(err.to_string())))?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()

        match conn
            .client
            .revoke_token(token_to_revoke)
            .map_err(|err| {
                RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(format!(
                    "Unexpected error while preparing to revoke token: {}",
                    err.to_string()
                )))
            })?
            .request(logging_http_client)
        {
            Ok(_) => Ok(()),
            Err(err) => match &err {
                // this is where the RFC-7009 2.2.1 Error Response is received and return to the caller.
                // It's the responsibility of the caller to decide whether to retry or report back to
                // the user.
                //
                // Note that [Errata for RFC 6749](https://www.rfc-editor.org/errata/eid4745)
                // defines two additional error responses, `server_error` and
                // `temporarily_unavailable`, that don't have variant counterparts
                // in the openid-connect crate. These two error messages will
                // therefore **not** end up in the `ServerReponse` variant.
                openidconnect::RequestTokenError::ServerResponse(r) => Err(r.error().clone()),
                openidconnect::RequestTokenError::Request(r) => {
                    self.forget_connection(lock_guard);
                    Err(RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(
                        format!("Network failure while revoking token: {}", r.to_string()),
                    )))
                }
                openidconnect::RequestTokenError::Parse(r, _) => {
                    Err(RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(
                        format!("Error while parsing token revocation response: {}", r.to_string()),
                    )))
                }
                openidconnect::RequestTokenError::Other(err_string) => match err_string.as_str() {
                    "temporarily_unavailable" | "server_error" => {
                        self.forget_connection(lock_guard);
                        Err(RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(
                            err_string.to_string(),
                        )))
                    }
                    _ => Err(RevocationErrorResponseType::Basic(CoreErrorResponseType::Extension(
                        format!("Unknown error while revoking token: {}", err_string),
                    ))),
                },
            },
        }
    }

    /// Try refreshing the token once with the OIDC Provider and return either the new token, or the Error received from
    /// the OpenID Connect Provider. This Error is FOR INTERNAL CONSUMPTION only. The caller of this function is
    /// responsible for creating end-user error messages, logging and (optionally) retrying.
    fn try_refresh_token(&self, session: &ClientSession) -> Result<Auth, CoreErrorResponseType> {
        let refresh_token =
            &session
                .secrets
                .get(TokenKind::RefreshToken.into())
                .ok_or_else(|| CoreErrorResponseType::Extension(
                    "Internal error: Token refresh attempted without a refresh token".to_string(),
                ))?;

        debug!("OpenID Connect: Refreshing token for user: \"{}\"", &session.id);
        trace!("OpenID Connect: Submitting RFC-6749 section 6 Access Token Refresh request");

        let lock_guard = self.get_connection()
            .map_err(|err| CoreErrorResponseType::Extension(err.to_string()))?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()
        
        let token_response = conn
            .client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request(logging_http_client);

        match token_response {
            Ok(token_response) => {
                let new_token_res = self.session_cache.encode(
                    &session.id,
                    &session.attributes,
                    secrets_from_token_response(&token_response),
                    &self.session_key,
                    token_response.expires_in(),
                );

                match new_token_res {
                    Ok(new_token) => {
                        // The new token was successfully acquired from the OpenID Connect Provider,
                        // and early returned.
                        Ok(Auth::Bearer(new_token))
                    }
                    Err(err) => Err(CoreErrorResponseType::Extension(format!(
                        "Internal error: Error while encoding the refreshed token {}",
                        err
                    ))),
                }
            }
            Err(err) => {
                match &err {
                    // this is where the RFC-6749 5.2 Error Response is received and
                    // return to the caller. It's the responsibility of the caller
                    // to decide whether to retry or report back to the user.
                    //
                    // Note that [Errata for RFC 6749](https://www.rfc-editor.org/errata/eid4745)
                    // defines two additional error responses, `server_error` and
                    // `temporarily_unavailable`, that don't have variant counterparts
                    // in the openid-connect crate. These two error messages will
                    // therefore **not** end up in the `ServerReponse` variant.
                    openidconnect::RequestTokenError::ServerResponse(r) => Err(r.error().clone()),
                    openidconnect::RequestTokenError::Request(r) => {
                        self.forget_connection(lock_guard);
                        Err(CoreErrorResponseType::Extension(format!(
                            "Network failure while refreshing token: {}",
                            r.to_string()
                        )))
                    }
                    openidconnect::RequestTokenError::Parse(r, _) => {
                        Err(CoreErrorResponseType::Extension(format!(
                            "Error while parsing refreshed token: {}",
                            r.to_string()
                        )))
                    }
                    openidconnect::RequestTokenError::Other(err_string) => match err_string.as_str() {
                        "temporarily_unavailable" | "server_error" => {
                            self.forget_connection(lock_guard);
                            Err(CoreErrorResponseType::Extension(err_string.to_string()))
                        }
                        _ => Err(CoreErrorResponseType::Extension(format!(
                            "Unknown error while refreshing token: {}",
                            err_string
                        ))),
                    },
                }
            }
        }
    }

    fn extract_claim(
        &self,
        claim_conf: &ConfigAuthOpenIDConnectClaim,
        id_token_claims: &FlexibleIdTokenClaims,
        user_info_claims: Option<&FlexibleUserInfoClaims>,
    ) -> KrillResult<Option<String>> {
        let searchable_claims = match &claim_conf.source {
            Some(ClaimSource::ConfigFile) => return Ok(None),
            Some(ClaimSource::IdTokenStandardClaim) => Some(id_token_claims.to_jmespath()),
            Some(ClaimSource::IdTokenAdditionalClaim) => Some(id_token_claims.additional_claims().to_jmespath()),
            Some(ClaimSource::UserInfoStandardClaim) if user_info_claims.is_some() => {
                Some(user_info_claims.unwrap().to_jmespath())
            }
            Some(ClaimSource::UserInfoAdditionalClaim) if user_info_claims.is_some() => {
                Some(user_info_claims.unwrap().additional_claims().to_jmespath())
            }
            _ => None,
        };

        // optional because it's not needed when looking up a value in the config file instead
        let jmespath_string = claim_conf
            .jmespath
            .as_ref()
            .ok_or_else(|| {
                OpenIDConnectAuthProvider::internal_error("Missing JMESPath configuration value for claim", None)
            })?
            .to_string();

        // Create a new JMESPath Runtime. TODO: Somehow make this a single
        // persistent runtime to which API request handling threads (such as
        // ours) dispatch search commands to be compiled and executed and which
        // can receive results back. Perhaps with a pair of channels, one to
        // to send search requests and the other to receive search results?
        let runtime = jmespathext::init_runtime();

        // We don't precompile the JMESPath expression because the jmespath
        // crate requires it to have a lifetime and storing that in our state
        // struct would infect the entire struct with lifetimes, plus logins
        // don't happen very often and are slow anyway (as the user has to visit
        // the OpenID Connect providers own login form then be redirected back
        // to us) so this doesn't have to be fast. Note to self: perhaps the
        // lifetime issue could be worked around using a Box?
        let expr = &runtime.compile(&jmespath_string).map_err(|e| {
            OpenIDConnectAuthProvider::internal_error(
                format!(
                    "OpenID Connect: Unable to compile JMESPath expression '{}'",
                    &jmespath_string
                ),
                Some(e.to_string()),
            )
        })?;

        let claims_to_search = match searchable_claims {
            Some(claim) => vec![(claim_conf.source.as_ref().unwrap(), claim)],
            None => {
                let mut claims = vec![
                    (&ClaimSource::IdTokenStandardClaim, id_token_claims.to_jmespath()),
                    (
                        &ClaimSource::IdTokenAdditionalClaim,
                        id_token_claims.additional_claims().to_jmespath(),
                    ),
                ];

                if let Some(user_info_claims) = user_info_claims {
                    claims.extend(vec![
                        (&ClaimSource::UserInfoStandardClaim, user_info_claims.to_jmespath()),
                        (
                            &ClaimSource::UserInfoAdditionalClaim,
                            user_info_claims.additional_claims().to_jmespath(),
                        ),
                    ]);
                }

                claims
            }
        };

        for (source, claims) in claims_to_search.clone() {
            let claims = claims.map_err(|e| {
                OpenIDConnectAuthProvider::internal_error(
                    "OpenID Connect: Unable to prepare claims for parsing",
                    Some(&e.to_string()),
                )
            })?;

            debug!("Searching {:?} for \"{}\"..", source, &jmespath_string);

            let result = expr.search(&claims).map_err(|e| {
                OpenIDConnectAuthProvider::internal_error(
                    "OpenID Connect: Error while searching claims",
                    Some(&e.to_string()),
                )
            })?;
            debug!("Search result in {:?}: '{:?}'", source, &result);

            // Did the JMESPath search find a match?
            if !matches!(*result, jmespath::Variable::Null) {
                // Yes. Is it a JMESPath String type?
                if let Some(result_str) = result.as_string() {
                    // Yes. Is it non-empty after trimming leading and trailing whitespace?
                    if !result_str.trim().is_empty() {
                        // Yes
                        return Ok(Some(result_str.clone()));
                    }
                }
            }
        }

        let err_msg_parts = &claims_to_search
            .iter()
            .map(|(source, claims)| format!("{} {:?}", source, claims))
            .collect::<Vec<String>>()
            .join(", ");

        debug!("Claim \"{}\" not found in {}", &jmespath_string, err_msg_parts);

        Ok(None)
    }

    fn init_session_key(data_dir: &PathBuf) -> KrillResult<Vec<u8>> {
        let key_path = data_dir.join(LOGIN_SESSION_STATE_KEY_PATH);
        info!("Initializing session encryption key {}", &key_path.display());
        crypt::load_or_create_key(key_path.as_path())
    }

    fn oidc_conf(&self) -> KrillResult<&ConfigAuthOpenIDConnect> {
        match &self.config.auth_openidconnect {
            Some(oidc_conf) => Ok(oidc_conf),
            None => Err(Error::ConfigError(
                "Missing [auth_openidconnect] config section!".into(),
            )),
        }
    }

    fn extract_cookie(&self, request: &hyper::Request<hyper::Body>, cookie_name: &str) -> Option<String> {
        for cookie_hdr_val in request.headers().get_all(hyper::http::header::COOKIE) {
            if let Ok(cookie_hdr_val_str) = cookie_hdr_val.to_str() {
                // Use a helper crate to parse the cookie string as it's
                // actually a bit of a pain as the string is semi-colon-with-
                // optional-trailing-space separated, cookie names must be
                // parsed according to token rules defined in RFC-2616 and
                // cookie values must be parsed according to grammar defined in
                // RFC-6265 (e.g. cookie values may be double quoted and can
                // only contain a specified subset of US-ASCII characters).
                // See:
                //   https://tools.ietf.org/html/rfc6265#section-4.2.1
                //   https://tools.ietf.org/html/rfc6265#section-4.1.1
                //   https://tools.ietf.org/html/rfc2616#section-2.2 (for the
                //   definition of 'token' used for cookie names)
                match Cookie::parse(cookie_hdr_val_str) {
                    Ok(parsed_cookies) => {
                        trace!("OpenID Connect: parsed cookies={:?}", &parsed_cookies);
                        // Even with the helper crate we have to do some work...
                        // Why doesn't it return a map???
                        if let Some(found_cookie) =
                            parsed_cookies.iter().find(|cookie| cookie.get_name() == cookie_name)
                        {
                            return Some(found_cookie.get_value().to_string());
                        }
                    }
                    Err(err) => {
                        error!(
                            "Unable to parse HTTP cookie header value '{}': {}",
                            cookie_hdr_val_str, err
                        );
                    }
                }
            }
        }
        None
    }

    fn internal_error<S>(msg: S, additional_info: Option<S>) -> Error
    where
        S: Into<String>,
    {
        let msg: String = msg.into();
        match additional_info {
            Some(additional_info) => warn!("{} [additional info: {}]", msg, additional_info.into()),
            None => warn!("{}", msg),
        };
        Error::ApiLoginError(msg)
    }

    fn get_auth(&self, request: &hyper::Request<hyper::Body>) -> Option<Auth> {
        if let Some(query) = urlparse(request.uri().to_string()).get_parsed_query() {
            if let Some(code) = query.get_first_from_str("code") {
                trace!("OpenID Connect: Processing potential RFC-6749 section 4.1.2 redirected Authorization Response");
                if let Some(state) = query.get_first_from_str("state") {
                    if let Some(nonce) = self.extract_cookie(request, NONCE_COOKIE_NAME) {
                        if let Some(csrf_token_hash) = self.extract_cookie(request, CSRF_COOKIE_NAME) {
                            trace!("OpenID Connect: Detected RFC-6749 section 4.1.2 redirected Authorization Response");
                            return Some(Auth::authorization_code(
                                Token::from(code),
                                state,
                                nonce,
                                csrf_token_hash,
                            ));
                        } else {
                            debug!("OpenID Connect: Ignoring potential RFC-6749 section 4.1.2 redirected Authorization Response due to missing CSRF token hash cookie.");
                        }
                    } else {
                        debug!("OpenID Connect: Ignoring potential RFC-6749 section 4.1.2 redirected Authorization Response due to missing nonce cookie.");
                    }
                } else {
                    debug!("OpenID Connect: Ignoring potential RFC-6749 section 4.1.2 redirected Authorization Response due to missing 'state' query parameter.");
                }
            }
        }

        None
    }

    fn get_connection(&self) -> KrillResult<RwLockReadGuard<Option<ProviderConnectionProperties>>> {
        let conn_guard = self.conn
            .read()
            .map_err(|err| OpenIDConnectAuthProvider::internal_error(
                "Unable to login: Unable to acquire internal lock",
                Some(&err.to_string()),
            ))?;

        conn_guard.as_ref().ok_or_else(|| OpenIDConnectAuthProvider::internal_error(
                "Connection to provider not yet established",
                None,
            ))?;

        Ok(conn_guard)
    }

    fn forget_connection(&self, read_locked_conn: RwLockReadGuard<Option<ProviderConnectionProperties>>) {
        std::mem::drop(read_locked_conn);
        if let Ok(mut conn_guard) = self.conn.write() {
            debug!("Discarding current OpenID Connect provider connection details due to connection issue");
            *conn_guard = None;
        }
    }

    fn verify_csrf_token(&self, state: String, csrf_token_hash: String) -> KrillResult<()> {
        let request_csrf_hash = sha256(state.as_bytes());
        match base64::decode_config(csrf_token_hash, base64::URL_SAFE_NO_PAD) {
            Ok(cookie_csrf_hash) if request_csrf_hash == cookie_csrf_hash => {
                Ok(())
            }
            Ok(cookie_csrf_hash) => {
                Err(Self::internal_error("OpenID Connect: CSRF token mismatch",
                    Some(&format!("cookie CSRF hash={:?}, request CSRF hash={:?}",
                    &cookie_csrf_hash, request_csrf_hash.to_vec()))))
            }
            Err(err) => {
                Err(Self::internal_error("OpenID Connect: Invalid CSRF token",
                    Some(&err.to_string())))
            }
        }
    }
    
    fn get_token_response(&self, code: Token) -> KrillResult<FlexibleTokenResponse> {
        let lock_guard = self.get_connection()?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()

        let token_response: FlexibleTokenResponse = conn
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request(logging_http_client)
            .map_err(|e| {
                let (msg, additional_info) = match e {
                    RequestTokenError::ServerResponse(provider_err) => {
                        (format!("Server returned error response: {:?}", provider_err), None)
                    }
                    RequestTokenError::Request(req) => {
                        self.forget_connection(lock_guard);
                        (format!("Request failed: {:?}", req), None)
                    },
                    RequestTokenError::Parse(parse_err, res) => {
                        let body = match std::str::from_utf8(&res) {
                            Ok(text) => text.to_string(),
                            Err(_) => format!("{:?}", &res),
                        };
                        (format!("Failed to parse server response: {}", parse_err), Some(body))
                    }
                    RequestTokenError::Other(err_string) => match err_string.as_str() {
                        "temporarily_unavailable" | "server_error" => {
                            self.forget_connection(lock_guard);
                            (err_string.to_string(), None)
                        }
                        _ => (err_string, None),
                    }
                };
                OpenIDConnectAuthProvider::internal_error(
                    format!("OpenID Connect: Code exchange failed: {}", msg),
                    additional_info,
                )
            })?;

        Ok(token_response)
    }

    fn get_token_id_claims<'a>(&self, token_response: &'a FlexibleTokenResponse, nonce_hash: Nonce) -> KrillResult<&'a FlexibleIdTokenClaims> {
        let lock_guard = self.get_connection()?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()
        let mut id_token_verifier: CoreIdTokenVerifier = conn.client.id_token_verifier();

        if self.oidc_conf()?.insecure {
            // This is NOT a good idea. It was needed when testing with
            // one provider and so may be of use to others in future
            // too.
            id_token_verifier = id_token_verifier.insecure_disable_signature_check();
        }

        trace!("OpenID Connect: Processing OpenID Connect Core 1.0 section 3.1.3.3 Token Response");
        let id_token_claims: &FlexibleIdTokenClaims = token_response
            .extra_fields()
            .id_token()
            .ok_or_else(|| {
                OpenIDConnectAuthProvider::internal_error(
                    "OpenID Connect: ID token is missing, does the provider support OpenID Connect?",
                    None,
                )
            })? // happens if the server only supports OAuth2
            .claims(&id_token_verifier, &nonce_hash)
            .map_err(|e| {
                OpenIDConnectAuthProvider::internal_error(
                    format!("OpenID Connect: ID token verification failed: {}", e.to_string()),
                    None,
                )
            })?;

        trace!(
            "OpenID Connect: Identity provider returned ID token: {:?}",
            id_token_claims
        );

        Ok(id_token_claims)
    }

    fn get_user_info_claims(&self, token_response: &FlexibleTokenResponse) -> KrillResult<Option<FlexibleUserInfoClaims>> {
        let lock_guard = self.get_connection()?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()

        let user_info_claims: Option<FlexibleUserInfoClaims> = if conn.userinfo_endpoint_supported {
            // Fetch claims from the userinfo endpoint. Why? Do we need to
            // do this if we already got the users identity and role from
            // the previous step, and thus only in the case where they are
            // not available without contacting the userinfo endpoint?
            Some(
                conn.client
                    .user_info(token_response.access_token().clone(), None)
                    .map_err(|e| {
                        OpenIDConnectAuthProvider::internal_error(
                            "OpenID Connect: Provider has no user info endpoint",
                            Some(&e.to_string()),
                        )
                    })?
                    // don't require the response to be signed as the spec says
                    // signing it is optional: See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
                    .require_signed_response(false)
                    .request(logging_http_client)
                    .map_err(|e| {
                        let (msg, additional_info) = match e {
                            UserInfoError::ClaimsVerification(provider_err) => {
                                (format!("Failed to verify claims: {:?}", provider_err), None)
                            }
                            UserInfoError::Response(_, _, provider_err) => {
                                (format!("Server returned error response: {:?}", provider_err), None)
                            }
                            UserInfoError::Request(req) => {
                                self.forget_connection(lock_guard);
                                (format!("Request failed: {:?}", req), None)
                            }
                            UserInfoError::Parse(parse_err) => {
                                (format!("Failed to parse server response: {}", parse_err), None)
                            }
                            UserInfoError::Other(err_string) => match err_string.as_str() {
                                "temporarily_unavailable" | "server_error" => {
                                    self.forget_connection(lock_guard);
                                    (err_string.to_string(), None)
                                }
                                _ => (err_string, None),
                            }
                            _ => {
                                ("Unknown error".to_string(), None)
                            }
                        };
                        OpenIDConnectAuthProvider::internal_error(
                            format!("OpenID Connect: UserInfo request failed: {}", msg),
                            additional_info,
                        )
                    })?
            )
        } else {
            None
        };

        Ok(user_info_claims)
    }

    fn resolve_claims(
        &self,
        claims_conf: HashMap<String, ConfigAuthOpenIDConnectClaim>,
        user: Option<&ConfigUserDetails>,
        id_token_claims: &FlexibleIdTokenClaims,
        user_info_claims: Option<FlexibleUserInfoClaims>,
        id: &str)
     -> KrillResult<HashMap<String, String>> {
        let mut attributes: HashMap<String, String> = HashMap::new();
        for (attr_name, claim_conf) in claims_conf {
            if attr_name == "id" {
                continue;
            }
            let attr_value = match &claim_conf.source {
                Some(ClaimSource::ConfigFile) if user.is_some() => {
                    // Lookup the claim value in the auth_users config file section
                    user.unwrap().attributes.get(&attr_name.to_string()).cloned()
                }
                _ => self.extract_claim(&claim_conf, &id_token_claims, user_info_claims.as_ref())?,
            };

            if let Some(attr_value) = attr_value {
                // Apply any defined destination mapping for this claim.
                // A destination causes the created attribute to have a
                // different name than the claim key in the
                // configuration. With this we can handle situations
                // such as the extracted role value not matching a valid
                // role according to policy (by specifying the same
                // source claim field multiple times but each time
                // using a different JMESPath expression to extract (and
                // optionally transform) a different value each time,
                // but mapping all of them to the same final attribute,
                // e.g. 'role'. A similar case this addresses is where
                // different values for an attribute (e.g. 'role') are
                // not present in a single claim field but instead may
                // be present in one of several claims (e.g. use (part
                // of) claim A to check for admins but use (part of)
                // claim B to check for readonly users).
                let final_attr_name = match claim_conf.dest {
                    None => attr_name.to_string(),
                    Some(alt_attr_name) => alt_attr_name.to_string(),
                };
                // Only use the first found value
                match attributes.entry(final_attr_name.clone()) {
                    Occupied(found) => {
                        info!("Skipping found value '{}' for claim '{}' as attribute '{}': attribute already has a value: '{}'",
                            attr_value, attr_name, final_attr_name, found.get());
                    }
                    Vacant(vacant) => {
                        debug!(
                            "Storing found value '{}' for claim '{}' as attribute '{}'",
                            attr_value, attr_name, final_attr_name
                        );
                        vacant.insert(attr_value);
                    }
                }
            } else {
                // With Oso policy based configuration the absence of
                // claim values isn't necessarily a problem, it's very
                // client configuration dependent, but let's mention
                // that we didn't find anything just to make it easier
                // to spot configuration mistakes via the logs.
                info!("No '{}' claim found for user: {}", &attr_name, &id);
            }
        }
        Ok(attributes)
    }
}

impl AuthProvider for OpenIDConnectAuthProvider {
    // Connect Core 1.0 section 3.1.26 Authentication Error Response
    // OAuth 2.0 RFC-674 4.1.2.1 (Authorization Request Errors) & 5.2 (Access Token Request Errors)

    /// Validate the current login session, extending it with the OIDC provider if needed.
    /// Returns either the session attributes and (if available) the refreshed token, or
    /// an error to report back to the user (one of the ApiAuth* Error types).
    /// Make sure to not leak any OIDC implementation details into the Error result!
    /// This function is also responsible for all logging around refreshing the token / extending the session.
    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>> {
        trace!("Attempting to authenticate the request..");

        self.initialize_connection_if_needed().map_err(|err| {
            OpenIDConnectAuthProvider::internal_error(
                "OpenID Connect: Cannot authenticate request: Failed to connect to provider",
                Some(&err.to_string()),
            )
        })?;

        let res = match self.get_bearer_token(request) {
            Some(token) => {
                // see if we can decode, decrypt and deserialize the users token
                // into a login session structure
                let session = self.session_cache.decode(token, &self.session_key, true)?;
                let status = session.status();

                // Token found in cache and active; all good, do an early return
                match status {
                    SessionStatus::Active => {
                        return Ok(Some(ActorDef::user(session.id, session.attributes, None)));
                    }
                    SessionStatus::NeedsRefresh => {
                        // If we have a refresh token try and extend the session. Otherwise return the cached token
                        // and continue the login session until it expires.
                        if !session.secrets.contains_key(TokenKind::RefreshToken.into()) {
                            return Ok(Some(ActorDef::user(session.id, session.attributes, None)));
                        }
                    }
                    SessionStatus::Expired => {
                        // We can only try to extend the session if we have a refresh token. Otherwise, return early
                        // with an error that indicates the user needs to login again.
                        if !session.secrets.contains_key(TokenKind::RefreshToken.into()) {
                            return Err(Error::ApiAuthSessionExpired("No token to be refreshed".to_string()));
                        }
                    }
                }

                // Token needs refresh and we have a refresh token, try to refresh
                let new_auth = match self.try_refresh_token(&session) {
                    Ok(auth) => {
                        trace!(
                            "OpenID Connect: Succesfully refreshed token for user \"{}\"",
                            &session.id
                        );
                        auth
                    }
                    Err(err) => {
                        trace!("OpenID Connect: RFC 6749 5.2 Error response returned...");
                        debug!(
                            "OpenID Connect: Refreshing the token for user '{}' failed: {}",
                            &session.id, &err
                        );
                        match err {
                            // This is the Error returned by the OpenID Connect Provider if the session was terminated
                            // by them. The user should be able to create a new session by logging in again.
                            CoreErrorResponseType::InvalidGrant => {
                                warn!("OpenID Connect: invalid_grant {:?}", err);
                                return Err(Error::ApiInvalidCredentials(
                                    "Unable to extend login session: your session has been terminated.".to_string(),
                                ));
                            }
                            CoreErrorResponseType::InvalidRequest | CoreErrorResponseType::InvalidClient => {
                                warn!("OpenID Connect: RFC 6749 5.2 {:?}", err);
                                return Err(Error::ApiAuthPermanentError(
                                    "Unable to extend login session: the provider rejected the request.".to_string(),
                                ));
                            }
                            // If changes are made to the roles of the user, the client or
                            // the scope on the side of the OpenID Connect Provider,
                            // the token refresh may get one of these errors.
                            CoreErrorResponseType::UnauthorizedClient
                            | CoreErrorResponseType::UnsupportedGrantType
                            | CoreErrorResponseType::InvalidScope => {
                                warn!("OpenID Connect: RFC 6749 5.2 {:?}", err);
                                return Err(Error::ApiInsufficientRights(
                                    "Unable to extend login session: the authorization was revoked for this user, client or action.".to_string(),
                                ));
                            }
                            // The Extension Type Errors are used by the try_refresh_token
                            // method to signal generic problems with either the current
                            // token, or the freshly received one. Additionally the two
                            // error responses from [Errata for RFC 6749]
                            // (https://www.rfc-editor.org/errata/eid4745),
                            // "temporarily_unavailable" and "server_error", end up here.
                            CoreErrorResponseType::Extension(err) => match err.as_str() {
                                "temporarily_unavailable" | "server_error" => {
                                    warn!("OpenID Connect: RFC 6749 5.2 {:?}", err);
                                    return Err(Error::ApiAuthTransientError(
                                        "Unable to extend login session: could not contact the provider".to_string(),
                                    ));
                                }
                                _ => {
                                    warn!("OpenID Connect: RFC 6749 5.2 unknown error {:?}", err);
                                    return Err(Error::ApiAuthTransientError(
                                        "Unable to extend login session: unknown error".to_string(),
                                    ));
                                }
                            },
                        }
                    }
                };

                Ok(Some(ActorDef::user(session.id, session.attributes, Some(new_auth))))
            }
            _ => Ok(None),
        };

        if log_enabled!(log::Level::Trace) {
            trace!("Authentication result: {:?}", res);
        }

        res
    }

    /// Generate the login URL that the client should direct the end-user to so
    /// they can login with the operators chosen OpenID Connect: provider. The
    /// URL should be requested by the client on every login as the intention is
    /// that it contains randomly generated CSFF token and nonce values which
    /// can be used to protect against certain cross-site and replay attacks.
    fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // TODO: we probably should do some more work here to ensure we get the
        // proper security benefits of the CSRF token, currently we are
        // discarding the CSRF token instead of checking it.
        //
        // Per https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest:
        //   "Opaque value used to maintain state between the request and the
        //    callback. Typically, Cross-Site Request Forgery (CSRF, XSRF)
        //    mitigation is done by cryptographically binding the value of this
        //    parameter with a browser cookie."
        //
        // Per https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes:
        //   "One method to achieve this for Web Server Clients is to store a
        //    cryptographically random value as an HttpOnly session cookie and
        //    use a cryptographic hash of the value as the nonce parameter. In
        //    that case, the nonce in the returned ID Token is compared to the
        //    hash of the session cookie to detect ID Token replay by third
        //    parties"

        self.initialize_connection_if_needed().map_err(|err| {
            OpenIDConnectAuthProvider::internal_error(
                "OpenID Connect: Cannot get login URL: Failed to connect to provider",
                Some(&err.to_string()),
            )
        })?;

        // Generate a random nonce and hash it, and use the hash as the actual
        // nonce value and store the unhashed nonce in a client-side HTTP only
        // secure cookie, as per the OpenID spec advice quoted above.
        let random_value = Nonce::new_random();
        let nonce_b64_str = random_value.secret();
        let nonce_hash = sha256(nonce_b64_str.as_bytes());

        let lock_guard = self.get_connection()?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()
        
        // At the time of writing the underlying oauth2 crate CsrfToken::new_random() function is used to
        // generate a "base64-encoded 128-bit" URL safe value that we use as the "state" parameter in the login
        // URL that the client is redirected to. Each attempt by the client to login should re-request the
        // login URL and thereby use a CSRF value unique to that login attempt.
        //
        // When the end user submits the 3rd party login form the state value should be included in the redirect
        // response that directs the user agent back to Krill. In order to verify the CSRF token we need to
        // either store it somewhere so that the separate request into the Krill HTTP server to complete the
        // login process can retrieve it (and we should be able to be sure we are retrieving the CSRF token that
        // was issued here by us to the user logging in) and compare it to the state value contained in the HTTP
        // HTTP back to Krill.
        //
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest says the state parameter should be
        // an "opaque value" - it is.
        //
        // https://tools.ietf.org/html/rfc6819#section-4.4.1.12 says a ""state" parameter created with secure
        // random codes should be deployed on the client side" - assuming that the random generator is secure
        // then yes we are using a secure random code.
        //
        // https://tools.ietf.org/html/rfc6749#section-4.2.2.1 says the state parameter "SHOULD NOT include
        // sensitive client or resource owner information in plain text" - it does not.
        //
        // https://tools.ietf.org/html/rfc6749#section-10.12 says the state parameter "MUST contain a
        // non-guessable value" - it does.
        //
        // https://tools.ietf.org/html/rfc6749#section-10.14 says that the "client MUST sanitize (and validate
        // when possible) any value received -- in particular, the value of the "state" and "redirect_uri"
        // parameters" - we can check that it is correctly base64 encoded and is of the expected length, but the
        // random value has no meaning or inherent structure that we can verify.
        //
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest,
        // https://tools.ietf.org/html/rfc6749#section-10.12, https://tools.ietf.org/html/rfc6819#section-3.6
        // and https://tools.ietf.org/html/rfc6819#section-5.3.5 all refer to using a value that "binds" the
        // request to the user agent's state and refer to cryptographic binding and use of hashing and cookies
        // to achieve such binding.
        //
        // We need a way to verify that the state value that we have received back is the one that we issued to
        // the client to use in the login process. Hashing it and issuing the hash to the client browser as a
        // cookie could be used to verifiably relate the state value to a value that we can issue at the start
        // of the login process and get back on redirect from the 3rd party back to Krill, and that won't be
        // sent to the 3rd party (i.e. the cookie, which will be restricted to our domain and thus shouldn't be
        // sent by the browser to the 3rd party domain). By using a cookie we automatically incorporate a
        // mechanism for delivering the hash back to us (as the user agent will follow the 3rd party redirect
        // back to us without giving client-side javascript a chance to inspect or modify it).
        //
        // This is actually exactly the same mechanism used to pass a nonce value to the 3rd party authorization
        // server and check it afterwards, the only difference being that the state parameter is passed back to
        // us as a request parameter on the authorisation code redirect response from the 3rd party, and the
        // nonce is a value embedded in the ID token that is issued at the very end of the login process (after
        // the authorisation code is exchanged for access and id tokens), except the hash and hashed value are
        // in reversed positions.
        let csrf_token = CsrfToken::new_random();
        let csrf_token_hash = sha256(csrf_token.secret().as_bytes());
        let csrf_token_hash_b64_str = base64::encode_config(csrf_token_hash, base64::URL_SAFE_NO_PAD);

        let mut request = conn.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || csrf_token,
            || Nonce::new(base64::encode_config(nonce_hash, base64::URL_SAFE_NO_PAD)),
        );

        // From https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest:
        //   "prompt: login - The Authorization Server SHOULD prompt the
        //    End-User for reauthentication. If it cannot reauthenticate the
        //    End-User, it MUST return an error, typically login_required."
        // We set this because the only time a user of Lagosta should be sent
        // to the OpenID Connect: provider login form is when they actually want
        // to specify who to login as, we don't want the provider somehow
        // automatically completing the login process because it has some notion
        // of an existing loging session.
        request = request.add_prompt(CoreAuthPrompt::Login);

        // The "openid" scope that OpenID Connect: providers are required to
        // check for is sent automatically by the openidconnect crate. We can
        // add more scopes here if needed by the customers provider setup. For
        // now the only additional scope that we add is "email" so that we can
        // identify in Lagosta and in logs the user using the API. This isn't
        // guaranteed to be unique, the "sub" identifier returned in the OpenID
        // Connect ID Token is intended for that but doesn't exhibit the same
        // obvious relationship to a real end-user as an email address does.
        // See:
        //   https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
        //   https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        //   https://openid.net/specs/openid-connect-core-1_0.html#IDToken
        if conn.email_scope_supported {
            request = request.add_scope(Scope::new("email".to_string()));
        }

        // TODO: use request.set_pkce_challenge() ?

        // This unwrap is safe as we check in new() that the OpenID Connect
        // config exists.
        let oidc_conf = self.oidc_conf()?;

        for scope in &oidc_conf.extra_login_scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }

        for (k, v) in oidc_conf.extra_login_params.iter() {
            request = request.add_extra_param(k, v);
        }

        let (authorize_url, _csrf_state, _nonce) = request.url();

        debug!("OpenID Connect: Login URL will be {:?}", &authorize_url);

        let res_body = authorize_url.as_str().as_bytes().to_vec();
        let mut res = HttpResponse::text_no_cache(res_body).response();

        // Create a cookie with the following attributes to attempt to protect them as much as possible:
        //   Secure       - Cookie is only sent to the server when a request is made with the https: scheme
        //                  (except on localhost), and therefore is more resistent to man-in-the-middle attacks.
        //   HttpOnly     - Forbids JavaScript from accessing the cookie, for example, through the
        //                  Document.cookie property. Note that a cookie that has been created with HttpOnly
        //                  will still be sent with JavaScript-initiated requests, e.g. when calling
        //                  XMLHttpRequest.send() or fetch(). This mitigates attacks against cross-site
        //                  scripting (XSS).
        //   SameSite=Lax - Note: This is now the default on modern browsers. Controls whether a cookie is sent
        //                  with cross-origin requests, providing some protection against cross-site request
        //                  forgery attacks (CSRF). Lax: The cookie is not sent on cross-site requests, such as
        //                  calls to load images or frames, but is sent when a user is navigating to the origin
        //                  site from an external site (e.g. if following a link). Lax mode is needed to ensure
        //                  that we receive the cookie when the OpenID Connect provider redirects the user agent
        //                  after login to our /auth/callback endpoint.
        //   Max-Age=300  - The user agent will delete the cookie after 5 minutes. As these cookies are only
        //                  used while logging in this should be sufficient while ensuring that these cookies
        //                  are kept no longer than necessary.
        //   Path=/       - Required for cookie names that are prefixed with __Host.
        // From: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#attributes
        fn make_secure_cookie_value(cookie_name: &str, cookie_value: &str) -> KrillResult<HeaderValue> {
            let cookie_str = format!("{}={}; Secure; HttpOnly; SameSite=Lax; Max-Age=300; Path=/", cookie_name, cookie_value);
            HeaderValue::from_str(&cookie_str).map_err(|err| {
                OpenIDConnectAuthProvider::internal_error(
                    format!(
                        "Unable to construct HTTP cookie '{}' with value '{}'",
                        cookie_name, cookie_value
                    ),
                    Some(err.to_string()),
                )
            })
        }

        res.headers_mut()
            .insert(SET_COOKIE, make_secure_cookie_value(NONCE_COOKIE_NAME, nonce_b64_str)?);
        res.headers_mut().append(
            SET_COOKIE,
            make_secure_cookie_value(CSRF_COOKIE_NAME, &csrf_token_hash_b64_str)?,
        );

        Ok(HttpResponse::new(res))
    }

    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        self.initialize_connection_if_needed().map_err(|err| {
            OpenIDConnectAuthProvider::internal_error(
                "OpenID Connect: Cannot login user: Failed to connect to provider",
                Some(&err.to_string()),
            )
        })?;

        match self.get_auth(request) {
            // OpenID Connect Authorization Code Flow
            // See: https://tools.ietf.org/html/rfc6749#section-4.1
            //      https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
            Some(Auth::AuthorizationCode { code, state, nonce, csrf_token_hash }) => {
                // verify the CSRF "state" value by hashing it and comparing it to the value in the CSRF cookie
                // TODO: use constant time comparison, e.g. as provided by the ring crate?
                self.verify_csrf_token(state, csrf_token_hash)?;

                // ==========================================================================================
                // Step 1: exchange the temporary (e.g. valid for 10 minutes or
                // something like that) OAuth2 authorization code for an OAuth2
                // access token, OAuth2 refresh token and OpenID Connect ID
                // token.
                // See: https://tools.ietf.org/html/rfc6749#section-4.1.2
                //      https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
                // ==========================================================================================
                trace!("OpenID Connect: Submitting RFC-6749 section 4.1.3 Access Token Request");

                let token_response = self.get_token_response(code)?;

                // TODO: extract and keep the access token and refresh token so
                // that we can extend the login session later. These are
                // sensitive tokens which are passed to us and MUST not be
                // shared with the client. If we want to be stateless we need to
                // give it to the client without enabling the client (or an
                // attacker that steals it from the clients browser session or
                // browser storage for example) to use it with the identity
                // provider themselves. Thus we will need to encrypt it. Note
                // that the access token has an expires_in time in seconds and
                // that the refresh token is optional, the provider may not give
                // us a refresh token. We may also receive a scope value but
                // only if different to the scope that we requested. Ensure,
                // where not already done by the openidconnect crate, that the
                // OAuth2 security consideratons are taken into account.
                // See: https://tools.ietf.org/html/rfc6749#section-5.1
                //      https://tools.ietf.org/html/rfc6749#section-10

                // ==========================================================================================
                // Step 2: Verify the ID token (including checking if it is
                // signed correctly, if the ID provider supports ID token
                // signing).
                // ==========================================================================================
                // The openidconnect crate does a lot of the required
                // steps for us, though does NOT support steps 1 (decrypting
                // encrypted ID token responses), steps 4-5 (azp claim
                // validation, as it claims these are "specific to the ID token"
                // which I think means it depends on our logic) and steps 9-13
                // are also not checked as they are "specific to the ID token".
                // See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
                //      https://github.com/ramosbugs/openidconnect-rs/blob/1.0.1/src/verification.rs#L204

                // TODO: implement missing security steps 4-5 and 9-13 if
                // appropriate. This mainly seems to be about checking that the
                // exp and lat claim values make sense compared to our current
                // time, and checking the nonce value. Other checks appear to
                // concern the optional "acr" and "auth_time" claims which we
                // are not using. TODO: Should we use them?

                // In this next step the openidconnect crate will verify the
                // signature of the ID token. Depending on the customer provider
                // configuration we might get user identity and possibly also
                // the users Krill access role from this next step, or
                // alternatively we might have to get them in the step after
                // that by contacting the OpenID Connect provider userinfo
                // endpoint.

                // Hash the nonce we obtained from the request as the nonce
                // claim is actually the hash of the original nonce, as per
                // the advice in the OpenID Core 1.0 spec. See:
                // https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
                let nonce_hash =
                    Nonce::new(base64::encode_config(sha256(nonce.as_bytes()), base64::URL_SAFE_NO_PAD));

                let id_token_claims = self.get_token_id_claims(&token_response, nonce_hash)?;

                // TODO: There's also a suggestion to verify the access token
                // received above using the at_hash claim in the ID token, if
                // we received that claim.
                // See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation

                // ==========================================================================================
                // Step 3: Contact the userinfo endpoint.
                // See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                // ==========================================================================================

                let user_info_claims = self.get_user_info_claims(&token_response)?;

                // ==========================================================================================
                // Step 4: Extract and validate the "claims" that tells us which
                // attributes this user should have. The Oso Polar policy will
                // use these to determine whether or not users are authorized to
                // perform a given action on a given resource.
                //
                // For each claim configuration, either it tells us how to grab
                // a value from a claim included in either the ID Token or User
                // Info response from the provider, or it tells us which
                // attribute value to use from the config file authentication
                // provider configuration (for operators who want to use OpenID
                // connect for authentication but not for authorization).
                //
                // We can only get the "id" of the user from the OpenID Connect
                // response claims, as we cannot lookup a value for an "id"
                // attribute in the config file authentication provider
                // configuration without the "id" key :-)
                // ==========================================================================================

                let claims_conf = with_default_claims(&self.oidc_conf()?.claims);

                let id_claim_conf = claims_conf.get("id").ok_or_else(|| {
                    OpenIDConnectAuthProvider::internal_error("Missing 'id' claim configuration", None)
                })?;

                let id = self
                    .extract_claim(&id_claim_conf, &id_token_claims, user_info_claims.as_ref())?
                    .ok_or_else(|| {
                        OpenIDConnectAuthProvider::internal_error("No value found for 'id' claim", None)
                    })?;

                // Lookup the a user in the config file authentication provider
                // configuration by the id value that we just obtained, if
                // present. Any claim configurations that refer to attributes of
                // users configured in the config file will be looked up on this
                // user.
                let user = self.config.auth_users.as_ref().and_then(|users| users.get(&id));

                let attributes = self.resolve_claims(claims_conf, user, id_token_claims, user_info_claims, &id)?;

                // ==========================================================================================
                // Step 5: Respond to the user: access granted, or access denied
                // TODO: Choose which data to store at the client, and then
                // encrypt it here and decrypt it in get_actor(). How can we do
                // that? If we don't do encryption at this point, and thus don't
                // store the access token and refresh token on the client, where
                // does that leave us? Storing the signed id token at the client
                // gives us a login session token which can be verified due to
                // it being signed, and MAY contain the users role in Krill
                // thereby preventing that from being altered. Even if not
                // signed this would be no worse than the existing Krill token
                // security. If we were to refuse a signed token older than 30
                // minutes we would have the same login session time as Lagosta
                // has now and can prevent re-use of old tokens thereby
                // requiring users to prove themselves again to the identity
                // provider, except that Lagosta has a 30 minute *idle* time,
                // not a 30 minute session time. So ideally we would re-issue
                // the token and increase the expiration time and re-sign it.
                // The Lagosta idle timeout matches the RedHat KeyCloud expires
                // time of 1800 seconds or 30 minutes, so attempting to refresh
                // an access token after that much time would also fail.
                // ==========================================================================================
                let api_token = self.session_cache.encode(
                    &id,
                    &attributes,
                    secrets_from_token_response(&token_response),
                    &self.session_key,
                    token_response.expires_in(),
                )?;

                Ok(LoggedInUser {
                    token: api_token,
                    id,
                    attributes,
                })
            }

            _ => Err(Error::ApiInvalidCredentials("Missing credentials".to_string())),
        }
    }

    /// Log the user out of the OpenID Connect provider.
    ///
    /// Note: As the session state is stored in an encrypted bearer token held by the client we cannot force the user to
    /// be logged out. Instead we rely on the Lagosta web UI to forget the bearer token and on informing the OpenID
    /// Connect provider that it should discard any session state that it holds so that any attempt in the near future
    /// by Krill to refresh the access token at the provider will fail.
    ///
    /// Returns a HTTP 200 response with a body consisting of the URL which the Lagosta web UI should direct the user to
    /// in order to complete the logout process. We cannot respond with a HTTP redirect because we are contacted by
    /// JavaScript, not by the user agent. TODO: should we use a redirect based approach instead?
    ///
    /// When the provider supports OpenID Connect RP-Initiated Logout 1.0 the URL returned is that of the OpenID Connect
    /// provider logout endpoint, including a post_logout_redirect_url which instructs the provider to redirect the user
    /// agent back to the Krill Lagosta web UI after logout is complete.
    ///
    /// If instead the provider supports OAuth 2.0 Token Revocation then the trip via the user agent to the provider
    /// logout page is not possible, instead from the end-user's perspective they are returned to the Lagosta web UI
    /// index page (which currently immediately redirects the user to the 3rd party OpenID Connect provider login page)
    /// but before that Krill contacts the provider on the logged-in users behalf to revoke their token at the provider.
    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        // verify the bearer token indeed represents a logged-in Krill OpenID Connect provider session
        let token = self.get_bearer_token(request).ok_or_else(|| {
            warn!("Unexpectedly received a logout request without a session token.");
            Error::ApiInvalidCredentials("Invalid session token".to_string())
        })?;

        // fetch the decoded session from the cache or decode it otherwise if we cannot decode it that's an unexpected
        // problem so bail out
        let session = self.session_cache.decode(token.clone(), &self.session_key, false)?;

        // announce that the user requested to be logged out
        info!("User logged out: {}", session.id);

        // perform the logout:

        // 1. remove any cached copy of the decoded session
        trace!("Removing any cached decoded login session details");
        self.session_cache.remove(&token);

        // 2. verify that the provider is at least to some extent available, there's no point trying to log the token
        //    out of the provider if we know there's a problem with the provider
        self.initialize_connection_if_needed().map_err(|err| {
            OpenIDConnectAuthProvider::internal_error(
                "OpenID Connect: Cannot logout with provider: Failed to connect to provider",
                Some(&err.to_string()),
            )
        })?;

        // 3. use the provider connection details to contact the provider to terminate the client session
        let lock_guard = self.get_connection()?;
        let conn = lock_guard.deref().as_ref().unwrap(); // safe to unwrap as was tested in get_connection()

        let go_to_url = match &conn.logout_mode {
            LogoutMode::OAuth2TokenRevocation {
                post_revocation_redirect_url,
                ..
            } => {
                if let Err(err) = self.try_revoke_token(&session) {
                    OpenIDConnectAuthProvider::internal_error(
                        format!("Error while revoking token for user '{}'", session.id),
                        Some(err.to_string()),
                    );
                }
                post_revocation_redirect_url.clone()
            }
            LogoutMode::OperatorProvidedLogout {
                operator_provided_logout_url,
            } => {
                trace!("OpenID Connect: Directing user to Krill config file defined logout URL");
                operator_provided_logout_url.clone()
            }
            LogoutMode::ReturnToUI { url } => {
                trace!("OpenID Connect: Directing user to Krill UI URL");
                url.clone()
            }
            LogoutMode::RPInitiatedLogout {
                provider_url,
                post_logout_redirect_url,
            } => {
                trace!("OpenID Connect: Directing user to RP-Initiated Logout 1.0 compliant logout endpoint");

                let id_token = session.secrets.get(TokenKind::IdToken.into());

                self.build_rpinitiated_logout_url(provider_url, post_logout_redirect_url, id_token)
                    .unwrap_or_else(|err| {
                        OpenIDConnectAuthProvider::internal_error(
                            format!(
                                "Error while building OpenID Connect RP-Initiated Logout URL for user '{}'",
                                session.id
                            ),
                            Some(err.to_string()),
                        );
                        post_logout_redirect_url.clone()
                    })
            }
        };

        trace!("Telling Lagosta to direct the user to logout at: {}", &go_to_url);
        Ok(HttpResponse::text_no_cache(go_to_url.into()))
    }
}

fn secrets_from_token_response(token_response: &FlexibleTokenResponse) -> HashMap<String, String> {
    let mut secrets: HashMap<String, String> = HashMap::new();

    secrets.insert(
        TokenKind::AccessToken.into(),
        token_response.access_token().secret().clone(),
    );

    if let Some(refresh_token) = token_response.refresh_token() {
        secrets.insert(TokenKind::RefreshToken.into(), refresh_token.secret().clone());
    };

    if let Some(id_token) = token_response.extra_fields().id_token() {
        secrets.insert(TokenKind::IdToken.into(), id_token.to_string());
    }

    secrets
}

fn with_default_claims(claims: &Option<ConfigAuthOpenIDConnectClaims>) -> ConfigAuthOpenIDConnectClaims {
    let mut claims = match claims {
        Some(claims) => claims.clone(),
        None => ConfigAuthOpenIDConnectClaims::new(),
    };

    claims.entry("id".into()).or_insert(ConfigAuthOpenIDConnectClaim {
        source: None,
        jmespath: Some("email".to_string()),
        dest: None,
    });

    claims.entry("role".into()).or_insert(ConfigAuthOpenIDConnectClaim {
        source: None,
        jmespath: Some("role".to_string()),
        dest: None,
    });

    claims
}