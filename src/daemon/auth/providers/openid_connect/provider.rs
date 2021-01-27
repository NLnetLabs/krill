//! Stateless implementation of an OAuth 2.0 "confidential" client and OpenID Connect 1.0 "relying party".
//!
//! Acts as an OAuth 2.0 "confidential" client on behalf of the Krill Lagosta web UI (as opposed to the UI itself acting
//! as an OAuth 2.0 "public" client). Intended to be compliant with the following OAuth 2.0 and OpenID Connect 1.0
//! specifications:
//!
//!   - [The OAuth 2.0 Authorization Framework RFC 6749][rfc6749]
//!   - [OAuth 2.0 Token Revocation][rfc7009]
//!   - [OpenID Connect Core 1.0 incorporating errata set 1][openid-connect-core-1_0]
//!   - [OpenID Connect Discovery 1.0 incorporating errata set 1][openid-connect-discovery-1_0]
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

use std::path::PathBuf;
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

use openidconnect::core::{
    CoreAuthPrompt, CoreIdTokenVerifier, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
};
use openidconnect::reqwest::http_client as oidc_http_client;
use openidconnect::RequestTokenError;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    RedirectUrl, RefreshToken, Scope,
};

use reqwest::Url;
use urlparse::{urlparse, GetQuery};

use crate::commons::util::sha256;
use crate::commons::KrillResult;
use crate::commons::{actor::ActorDef, api::Token};
use crate::daemon::auth::common::crypt;
use crate::daemon::auth::common::session::*;
use crate::daemon::auth::providers::openid_connect::config::ConfigAuthOpenIDConnectClaims;
use crate::daemon::auth::providers::openid_connect::jmespathext;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser};
use crate::daemon::config::Config;
use crate::daemon::http::auth::AUTH_CALLBACK_ENDPOINT;
use crate::daemon::http::HttpResponse;
use crate::{commons::error::Error, daemon::auth::providers::openid_connect::token_revocation::TokenRevocationRequest};

use super::config::{
    ConfigAuthOpenIDConnect, ConfigAuthOpenIDConnectClaim, ConfigAuthOpenIDConnectClaimSource as ClaimSource,
};
use super::util::{
    FlexibleClient, FlexibleIdTokenClaims, FlexibleTokenResponse, FlexibleUserInfoClaims, LogOrFail, WantedMeta,
};

const NONCE_COOKIE_NAME: &str = "nonce_hash";
const LOGIN_SESSION_STATE_KEY_PATH: &str = "login_session_state.key"; // TODO: decide on proper location

enum ProviderLogoutURL {
    RPInitiatedLogoutURL(String),
    OAuth2TokenRevocationURL(String),
}

pub struct ProviderConnectionProperties {
    client: FlexibleClient,
    email_scope_supported: bool,
    userinfo_endpoint_supported: bool,
    logout_url: ProviderLogoutURL,
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
        // TODO: hang on, why are we taking a write lock just to check if the
        // Option is set??
        match self.conn.write() {
            Ok(mut conn_guard) => {
                if conn_guard.is_none() {
                    trace!("OpenID Connect: Initializing provider connection...");
                    let meta = self.discover()?;
                    let (email_scope_supported, userinfo_endpoint_supported, logout_url) =
                        self.check_provider_capabilities(&meta)?;
                    let client = self.build_client(meta)?;

                    *conn_guard = Some(ProviderConnectionProperties {
                        client,
                        email_scope_supported,
                        userinfo_endpoint_supported,
                        logout_url,
                    });
                }
            }
            Err(err) => {
                return Err(self.internal_error(
                    "Unable to initialize provider connection: Unable to acquire internal lock",
                    Some(&err.to_string()),
                ));
            }
        }

        Ok(())
    }

    /// Discover the OpenID Connect: identity provider details via the
    /// https://openid.net/specs/openid-connect-discovery-1_0.html spec defined
    /// discovery endpoint of the provider, e.g.
    ///   https://<provider.domain>/<something/.well-known/openid-configuration
    /// Via which we can discover both endpoint URIs and capability flags.
    fn discover(&self) -> KrillResult<WantedMeta> {
        // Read from config the OpenID Connect identity provider discovery URL.
        // Strip off /.well-known/openid_configuration because the openid-connect
        // crate wants to add this itself and will fail if it is already present
        // in the URL.
        let issuer = self.oidc_conf()?.issuer_url.clone();
        let issuer = issuer.trim_end_matches("/.well-known/openid_configuration");
        let issuer = IssuerUrl::new(issuer.to_string())?;

        info!(
            "OpenID Connect: Discovering provider details using issuer {}",
            &issuer.as_str()
        );

        // Contact the OpenID Connect: identity provider discovery endpoint to
        // learn about and configure ourselves to talk to it.
        let meta = WantedMeta::discover(&issuer, logging_http_client!()).map_err(|e| {
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
    fn check_provider_capabilities(&self, meta: &WantedMeta) -> KrillResult<(bool, bool, ProviderLogoutURL)> {
        // TODO: verify token_endpoint_auth_methods_supported?
        // TODO: verify response_types_supported?
        let mut ok = true;
        let mut email_scope_supported = false;
        let mut logout_url = None;

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

        // Neither end_session_endpoint nor revocation_endpoint are required to exist by the OpenID Connect discovery
        // spec, but we want some way to log the user out so if one of these is not set, fallback to a specified
        // end_session_endpoint.
        if let Some(url) = &meta.additional_metadata().end_session_endpoint {
            logout_url = Some(ProviderLogoutURL::RPInitiatedLogoutURL(url.clone()))
        } else if let Some(url) = &meta.additional_metadata().revocation_endpoint {
            logout_url = Some(ProviderLogoutURL::OAuth2TokenRevocationURL(url.clone()))
        } else if let Some(url) = &self.oidc_conf()?.logout_url {
            logout_url = Some(ProviderLogoutURL::RPInitiatedLogoutURL(url.clone()))
        } else {
            None::<String>.log_or_fail(
                "end_session_endpoint, revocation_endpoint or config file logout_url",
                None,
            )?;
            ok = false;
        }

        match ok {
            true => Ok((email_scope_supported, userinfo_endpoint_supported, logout_url.unwrap())),
            false => Err(Error::Custom(
                "OpenID Connect: The provider lacks support for one or more required capabilities.".to_string(),
            )),
        }
    }

    fn build_client(&self, meta: WantedMeta) -> KrillResult<FlexibleClient> {
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

        let client = client.set_redirect_uri(redirect_uri);

        Ok(client)
    }

    fn try_refresh_token(&self, session: &ClientSession) -> Option<Auth> {
        match &session.secrets.get(0) {
            Some(refresh_token) => {
                debug!("OpenID Connect: Refreshing token for user: \"{}\"", &session.id);
                trace!("OpenID Connect: Submitting RFC-6749 section 6 Access Token Refresh request");
                match self.conn.read() {
                    Ok(conn_guard) => {
                        match &*conn_guard {
                            Some(conn) => {
                                let token_response = conn
                                    .client
                                    .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
                                    .request(logging_http_client!());
                                match token_response {
                                    Ok(token_response) => {
                                        let secrets = if let Some(new_refresh_token) = token_response.refresh_token() {
                                            vec![new_refresh_token.secret().clone()]
                                        } else {
                                            vec![]
                                        };

                                        let new_token_res = self.session_cache.encode(
                                            &session.id,
                                            &session.attributes,
                                            &secrets,
                                            &self.session_key,
                                            token_response.expires_in(),
                                        );

                                        match new_token_res {
                                            Ok(new_token) => {
                                                return Some(Auth::Bearer(new_token));
                                            }
                                            Err(err) => {
                                                warn!(
                                                    "OpenID Connect: Could not extend login session for user '{}': {}",
                                                    &session.id, err
                                                );
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        warn!(
                                            "OpenID Connect: Could not extend login session for user '{}': {}",
                                            &session.id, err
                                        );
                                    }
                                }
                            }
                            None => {
                                // should be unreachable
                                warn!(
                                    "OpenID Connect: Could not extend login session for user '{}': {}",
                                    &session.id, "Connection to OpenID Connect provider not yet established"
                                );
                            }
                        }
                    }
                    Err(err) => {
                        warn!(
                            "OpenID Connect: Could not extend login session for user '{}': {}",
                            &session.id, err
                        );
                    }
                }
            }
            None => {
                debug!(
                    "OpenID Connect: Could not extend login session for user '{}': no refresh token available",
                    &session.id
                );
            }
        }
        None
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
            .ok_or_else(|| self.internal_error("Missing JMESPath configuration value for claim", None))?
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
            self.internal_error(
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
                self.internal_error(
                    "OpenID Connect: Unable to prepare claims for parsing",
                    Some(&e.to_string()),
                )
            })?;

            debug!("Searching {:?} for \"{}\"..", source, &jmespath_string);

            if let Ok(result) = expr.search(&claims) {
                if matches!(*result, jmespath::Variable::Null) {
                    continue;
                }
                debug!("Search result in {:?}: {:?}", source, &result);

                // return Some(String) if there is match, None otherwise (e.g. an array
                // instead of a string)
                return Ok(result.as_string().cloned());
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

    fn extract_nonce(&self, request: &hyper::Request<hyper::Body>) -> Option<String> {
        if let Some(cookie_hdr_val) = request.headers().get(hyper::http::header::COOKIE) {
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
                        // Even with the helper crate we have to do some work...
                        // Why doesn't it return a map???
                        if let Some(nonce_cookie) = parsed_cookies
                            .iter()
                            .find(|cookie| cookie.get_name() == NONCE_COOKIE_NAME)
                        {
                            return Some(nonce_cookie.get_value().to_string());
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

    fn internal_error<S>(&self, msg: S, additional_info: Option<S>) -> Error
    where
        S: Into<String>,
    {
        let msg: String = msg.into();
        match additional_info {
            Some(additional_info) => warn!("{} [additional info: {}]", msg, additional_info.into()),
            None => warn!("{}", msg),
        };
        Error::ApiAuthError(msg)
    }

    fn get_auth(&self, request: &hyper::Request<hyper::Body>) -> Option<Auth> {
        if let Some(query) = urlparse(request.uri().to_string()).get_parsed_query() {
            if let Some(code) = query.get_first_from_str("code") {
                trace!("OpenID Connect: Processing potential RFC-6749 section 4.1.2 redirected Authorization Response");
                if let Some(state) = query.get_first_from_str("state") {
                    if let Some(nonce) = self.extract_nonce(request) {
                        trace!("OpenID Connect: Detected RFC-6749 section 4.1.2 redirected Authorization Response");
                        return Some(Auth::authorization_code(Token::from(code), state, nonce));
                    } else {
                        debug!("OpenID Connect: Ignoring potential RFC-6749 section 4.1.2 redirected Authorization Response due to missing nonce hash cookie.");
                    }
                } else {
                    debug!("OpenID Connect: Ignoring potential RFC-6749 section 4.1.2 redirected Authorization Response due to missing 'state' query parameter.");
                }
            }
        }

        None
    }
}

impl AuthProvider for OpenIDConnectAuthProvider {
    // TODO: handle error responses from the provider as per RFC 6749 and OpenID
    // Connect Core 1.0 section 3.1.26 Authentication Error Response

    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>> {
        if log_enabled!(log::Level::Trace) {
            trace!("Attempting to authenticate the request..");
        }

        self.initialize_connection_if_needed().map_err(|err| {
            self.internal_error(
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

                let mut new_auth = None;
                if status != SessionStatus::Active {
                    new_auth = self.try_refresh_token(&session);
                    if new_auth.is_none() && status == SessionStatus::Expired {
                        return Err(Error::ApiInvalidCredentials(
                            "Session expired, please login again".to_string(),
                        ));
                    }
                }

                Ok(Some(ActorDef::user(session.id, session.attributes, new_auth)))
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
            self.internal_error(
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

        match &*self.conn.read().map_err(|err| {
            self.internal_error(
                "Unable to login: Unable to acquire internal lock",
                Some(&err.to_string()),
            )
        })? {
            Some(conn) => {
                let mut request = conn.client.authorize_url(
                    AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                    CsrfToken::new_random,
                    || Nonce::new(base64::encode(nonce_hash)),
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

                // Note: Cookies without an Expires attribute expire when the user agent
                // "session" ends, i.e. when the browser is closed. Note that the nonce
                // value is already base64 encoded.
                let cookie_str = format!("{}={}; Secure; HttpOnly", NONCE_COOKIE_NAME, nonce_b64_str);
                let cookie_hdr_val = HeaderValue::from_str(&cookie_str).map_err(|err| {
                    self.internal_error(
                        format!("Unable to construct HTTP cookie from nonce value '{}'", nonce_b64_str),
                        Some(err.to_string()),
                    )
                })?;

                let res_body = authorize_url.as_str().as_bytes().to_vec();
                let mut res = HttpResponse::text_no_cache(res_body).response();
                res.headers_mut().insert(SET_COOKIE, cookie_hdr_val);
                Ok(HttpResponse::new(res))
            }
            None => {
                // should be unreachable
                Err(self.internal_error("Cannot get login URL: Connection to provider not yet established", None))
            }
        }
    }

    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        self.initialize_connection_if_needed().map_err(|err| {
            self.internal_error(
                "OpenID Connect: Cannot login user: Failed to connect to provider",
                Some(&err.to_string()),
            )
        })?;

        match self.get_auth(request) {
            // OpenID Connect Authorization Code Flow
            // See: https://tools.ietf.org/html/rfc6749#section-4.1
            //      https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
            // TODO: use _state.
            Some(Auth::AuthorizationCode(code, _state, nonce)) => {
                // ==========================================================================================
                // Step 1: exchange the temporary (e.g. valid for 10 minutes or
                // something like that) OAuth2 authorization code for an OAuth2
                // access token, OAuth2 refresh token and OpenID Connect ID
                // token.
                // See: https://tools.ietf.org/html/rfc6749#section-4.1.2
                //      https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
                // ==========================================================================================
                trace!("OpenID Connect: Submitting RFC-6749 section 4.1.3 Access Token Request");
                match &*self.conn.read().map_err(|err| {
                    self.internal_error(
                        "Unable to login: Unable to acquire internal lock",
                        Some(&err.to_string()),
                    )
                })? {
                    Some(conn) => {
                        let token_response: FlexibleTokenResponse = conn
                            .client
                            .exchange_code(AuthorizationCode::new(code.to_string()))
                            .request(logging_http_client!())
                            .map_err(|e| {
                                let (msg, additional_info) = match e {
                                    RequestTokenError::ServerResponse(provider_err) => {
                                        (format!("Server returned error response: {:?}", provider_err), None)
                                    }
                                    RequestTokenError::Request(req) => (format!("Request failed: {:?}", req), None),
                                    RequestTokenError::Parse(parse_err, res) => {
                                        let body = match std::str::from_utf8(&res) {
                                            Ok(text) => text.to_string(),
                                            Err(_) => format!("{:?}", &res),
                                        };
                                        (format!("Failed to parse server response: {}", parse_err), Some(body))
                                    }
                                    RequestTokenError::Other(msg) => (msg, None),
                                };
                                self.internal_error(
                                    format!("OpenID Connect: Code exchange failed: {}", msg),
                                    additional_info,
                                )
                            })?;

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
                        let nonce_hash = Nonce::new(base64::encode(sha256(nonce.as_bytes())));

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
                                self.internal_error(
                                    "OpenID Connect: ID token is missing, does the provider support OpenID Connect?",
                                    None,
                                )
                            })? // happens if the server only supports OAuth2
                            .claims(&id_token_verifier, &nonce_hash)
                            .map_err(|e| {
                                self.internal_error(
                                    format!("OpenID Connect: ID token verification failed: {}", e.to_string()),
                                    None,
                                )
                            })?;

                        trace!(
                            "OpenID Connect: Identity provider returned ID token: {:?}",
                            id_token_claims
                        );

                        // TODO: There's also a suggestion to verify the access token
                        // received above using the at_hash claim in the ID token, if
                        // we revceived that claim.
                        // See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation

                        // ==========================================================================================
                        // Step 3: Contact the userinfo endpoint.
                        // See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                        // ==========================================================================================

                        let user_info_claims: Option<FlexibleUserInfoClaims> = if conn.userinfo_endpoint_supported {
                            // Fetch claims from the userinfo endpoint. Why? Do we need to
                            // do this if we already got the users identity and role from
                            // the previous step, and thus only in the case where they are
                            // not available without contacting the userinfo endpoint?
                            Some(
                                conn.client
                                    .user_info(token_response.access_token().clone(), None)
                                    .map_err(|e| {
                                        self.internal_error(
                                            "OpenID Connect: Provider has no user info endpoint",
                                            Some(&e.to_string()),
                                        )
                                    })?
                                    // don't require the response to be signed as the spec says
                                    // signing it is optional: See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
                                    .require_signed_response(false)
                                    .request(logging_http_client!())
                                    .map_err(|e| {
                                        self.internal_error(
                                            "OpenID Connect: User info request failed",
                                            Some(&e.to_string()),
                                        )
                                    })?,
                            )
                        } else {
                            None
                        };

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

                        let id_claim_conf = claims_conf
                            .get("id")
                            .ok_or_else(|| self.internal_error("Missing 'id' claim configuration", None))?;

                        let id = self
                            .extract_claim(&id_claim_conf, &id_token_claims, user_info_claims.as_ref())?
                            .ok_or_else(|| self.internal_error("No value found for 'id' claim", None))?;

                        // Lookup the a user in the config file authentication provider
                        // configuration by the id value that we just obtained, if
                        // present. Any claim configurations that refer to attributes of
                        // users configured in the config file will be looked up on this
                        // user.
                        let user = self.config.auth_users.as_ref().and_then(|users| users.get(&id));

                        // Iterate over the configured claims and try to lookup their
                        // values so that we can store these as attributes on the user
                        // session object.
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
                        let secrets = if let Some(new_refresh_token) = token_response.refresh_token() {
                            vec![new_refresh_token.secret().clone()]
                        } else {
                            vec![]
                        };

                        let api_token = self.session_cache.encode(
                            &id,
                            &attributes,
                            &secrets,
                            &self.session_key,
                            token_response.expires_in(),
                        )?;

                        Ok(LoggedInUser {
                            token: api_token,
                            id,
                            attributes,
                        })
                    }
                    None => {
                        // should be unreachable
                        Err(self.internal_error("Cannot login user: Connection to provider not yet established", None))
                    }
                }
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

        // fetch the decoded session from the cache or decode it otherwise
        // if we cannot decode it that's an unexpected problem so bail out
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
            self.internal_error(
                "OpenID Connect: Cannot logout with provider: Failed to connect to provider",
                Some(&err.to_string()),
            )
        })?;

        // 3. use the provider connection details to contact the provider to terminate the client session
        match &*self.conn.read().map_err(|err| {
            self.internal_error(
                "Unable to logout: Unable to acquire internal lock",
                Some(&err.to_string()),
            )
        })? {
            Some(conn) => {
                let service_uri = self.config.service_uri();
                let go_to_url = match conn.logout_url {
                    ProviderLogoutURL::RPInitiatedLogoutURL(ref url) => {
                        trace!("OpenID Connect provider offers an RP-Initiated Logout 1.0 compliant logout endpoint");
                        // Ask Lagosta to direct the user first the to OpenID Connect provider logout page, and ask it
                        // to then redirect post-logout back to the Krill UI landing page.
                        // TODO: Should we also use any of other parameters defined in the RP Initiated Logout 1.0 spec?
                        // See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
                        //      https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
                        // E.g. id_token_hint, state or ui_locales? Apparently we MSUT use id_token_hint because the
                        // spec states:
                        //   "An id_token_hint carring an ID Token for the RP is also REQUIRED when requesting
                        //    post-logout redirection"
                        // TODO: Require HTTPS as per the spec: "This URL MUST use the https scheme"
                        // See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#OPMetadata
                        format!("{}?post_logout_redirect_uri={}", url, service_uri.as_str())
                    }
                    ProviderLogoutURL::OAuth2TokenRevocationURL(ref url) => {
                        trace!(
                            "OpenID Connect provider offers an OAuth 2.0 Token Revocation compliant logout endpoint"
                        );
                        // Connect to the OpenID Connect provider OAuth 2.0 token revocation endpoint to terminate the
                        // provider session
                        // From: https://tools.ietf.org/html/rfc7009#section-2
                        //   "Implementations MUST support the revocation of refresh tokens and SHOULD support the
                        //    revocation of access tokens (see Implementation Note)."
                        if !session.secrets.is_empty() {
                            let refresh_token = RefreshToken::new(session.secrets[0].clone());

                            TokenRevocationRequest {
                                url: Url::parse(&url)?,
                                refresh_token
                            }
                            .request(logging_http_client!())
                            .map_err(|err| {
                                Error::custom(format!("Unable to revoke OAuth 2.0 refresh token: {}", err))
                            })?;
                        }

                        // Then ask Lagosta to direct the user to the Krill UI landing page.
                        service_uri.as_str().to_string()
                    }
                };

                trace!("Telling Lagosta to direct the user to logout at: {}", &go_to_url);
                Ok(HttpResponse::text_no_cache(go_to_url.into()))
            }
            None => {
                // should be unreachable
                Err(self.internal_error(
                    "Cannot get logout URL: Connection to provider not yet established",
                    None,
                ))
            }
        }
    }
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
