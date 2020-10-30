use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cached::{proc_macro::cached, Cached};

use jmespatch as jmespath;

use openidconnect::{
    AccessToken, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, RedirectUrl, 
    RefreshToken, Scope,
};
use openidconnect::core::{
    CoreAuthPrompt, CoreClaimName, CoreIdTokenVerifier, CoreJwsSigningAlgorithm,
    CoreResponseMode, CoreResponseType,
};
use openidconnect::reqwest::http_client as oidc_http_client;

use crate::commons::{actor::Actor, api::Token, error::Error as KrillError};
use crate::commons::KrillResult;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser, Permissions};
use crate::daemon::config::CONFIG;
use crate::daemon::http::auth::AUTH_CALLBACK_ENDPOINT;

use super::config::{
    ConfigAuthOpenIDConnect, ConfigAuthOpenIDConnectRole as Role,
    ConfigAuthOpenIDConnectRoleSource as RoleSource
};
use super::util::{
    self, LogOrFail, FlexibleClient, FlexibleIdTokenClaims,
    FlexibleTokenResponse, FlexibleUserInfoClaims, WantedMeta,
};
use super::crypt;

const NONCE_TODO_MAKE_RANDOM: &str = "DUMMY_FIXED_VALUE_FOR_NOW";
const TAG_SIZE: usize = 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientSession {
    pub start_time: u64,
    pub expires_in: Option<Duration>,
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub id: String,
    pub role_name: String,
}

// TODO: is this stuff thread safe?
pub struct OpenIDConnectAuthProvider {
    client: FlexibleClient,
    logout_url: String,
}

impl OpenIDConnectAuthProvider {
    pub fn new() -> KrillResult<Self> {
        match &CONFIG.auth_openidconnect {
            Some(oidc_conf) => {
                    let meta = Self::discover(oidc_conf)?;
                    Self::check_provider_capabilities(&meta)?;
                    let logout_url = Self::build_logout_url(&meta);
                    let client = Self::build_client(oidc_conf, meta)?;

                    Ok(OpenIDConnectAuthProvider {
                        client,
                        logout_url,
                    })
                },
            None => Err(KrillError::Custom(
                "Missing [auth_openidconnect] config section!".into()))
        }
    }

    /// Discover the OpenID Connect: identity provider details via the
    /// https://openid.net/specs/openid-connect-discovery-1_0.html spec defined
    /// discovery endpoint of the provider, e.g.
    ///   https://<provider.domain>/<something/.well-known/openid-configuration
    /// Via which we can discover both endpoint URIs and capability flags.
    fn discover(oidc_conf: &ConfigAuthOpenIDConnect)
        -> KrillResult<WantedMeta>
    {
        // Read from config the OpenID Connect: identity provider discovery URL
        let issuer = IssuerUrl::new(oidc_conf.issuer_url.clone())?;

        info!("Discovering OpenID Connect: provider details using issuer {}",
            &issuer.as_str());

        // Contact the OpenID Connect: identity provider discovery endpoint to
        // learn about and configure ourselves to talk to it.
        let meta = WantedMeta::discover(&issuer, logging_http_client!()).map_err(|e| KrillError::Custom(format!(
            "OpenID Connect: discovery failed with issuer {}: {}",
            issuer.to_string(),
            e.to_string())))?;

        Ok(meta)
    }

    /// Verify that the OpenID Connect: discovery metadata indicates that the
    /// provider has support for the features that we require.
    fn check_provider_capabilities(meta: &WantedMeta) -> KrillResult<()> {
        // TODO: verify token_endpoint_auth_methods_supported?
        // TODO: verify response_types_supported?
        let mut ok = true;

        info!("Verifying OpenID Connect: provider capabilities..");

        if is_supported_opt!(meta.response_modes_supported(), CoreResponseMode::Query)
               .log_or_fail("response_modes_supported", Some("query"))
               .is_err() {
            ok = false;
        }

        if is_supported!(meta.id_token_signing_alg_values_supported(), CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256)
               .log_or_fail("id_token_signing_alg_values_supported", Some("RS256"))
               .is_err() {
            ok = false;
        }
    
        for scope_name in &["openid", "email"] {
            if is_supported_val_opt!(meta.scopes_supported(), Scope::new(scope_name.to_string()))
                .log_or_fail("scopes_supported", Some(scope_name))
                .is_err() {
                ok = false;
            }
        }
        
        for claim_name in &["email"] {
            if is_supported_val_opt!(meta.claims_supported(), CoreClaimName::new(claim_name.to_string()))
                .log_or_fail("claims_supported", Some(claim_name))
                .is_err() {
                ok = false;
            }
        }

        if meta.additional_metadata().end_session_endpoint.as_ref()
            .log_or_fail("end_session_endpoint", None)
            .is_err() {
            ok = false;
        }

        match ok {
            true => Ok(()),
            false => Err(KrillError::Custom(
                "OpenID Connect: The provider lacks support for one or more required capabilities.".to_string()))
        }
    }

    fn build_client(
        oidc_conf: &ConfigAuthOpenIDConnect,
        meta: WantedMeta
    ) -> KrillResult<FlexibleClient> {
        // Read from config the credentials we should use to authenticate
        // ourselves with the identity provider. These details should have been
        // obtained by the Krill operator when they created a registration for
        // their Krill instance with their identity provider.
        let client_id = ClientId::new(oidc_conf.client_id.clone());
        let client_secret = ClientSecret::new(oidc_conf.client_secret.clone());

        // Create a client we can use to communicate with the provider based on
        // what we just learned and using the credentials we read from config
        // above.
        let client = FlexibleClient::from_provider_metadata(
            meta, client_id, Some(client_secret));

        // Note: we still haven't actually verified that the client id and
        // secret are correct, that will only happen when we try to exchange a
        // temporary code for access and id tokens.

        // Configure the client to instruct the 3rd party login form that after
        // successful login it should redirect, via the client browser, to the
        // Krill authentication callback endpoint. When the callback is invoked
        // it will come through to us so that we can exchange the temporary code
        // for access and id tokens.
        let redirect_uri = RedirectUrl::new(
            CONFIG.service_uri()
                .join(AUTH_CALLBACK_ENDPOINT.trim_start_matches("/").as_bytes())
                .to_string())?;

        // Log the redirect URI to help the operator in the event that the
        // OpenID Connect: provider complains that the redirect URI doesn't match
        // that configured at the provider.
        debug!("OpenID Connect: redirect URI set to {}", redirect_uri.to_string());

        let client = client.set_redirect_uri(redirect_uri);

        Ok(client)
    }

    /// Build a logout URL to which the client should be directed to so that
    /// they can logout with the OpenID Connect: provider. The URL includes an
    /// OpenID Connect: RP Initiatiated Logout spec compliant query parameter
    /// telling the provider to redirect back to Krill once logout is complete.
    /// 
    /// See: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    fn build_logout_url(meta: &WantedMeta) -> String {
        let logout_url = meta.additional_metadata().end_session_endpoint.as_ref().unwrap();

        format!("{}?post_logout_redirect_uri={}",
            logout_url, CONFIG.service_uri().as_str())
    }

    fn refresh_token(&self, session: ClientSession) -> Option<Auth> {
        if let Some(refresh_token) = session.refresh_token {
            if let Some(expires_in) = session.expires_in {
                match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(now) => {
                        let session_age = now.as_secs() - session.start_time;
                        debug!("OpenID Connect: session age: {}, expires in: {} (for ID \"{}\")",
                                &session_age, expires_in.as_secs(), &session.id);
                        if session_age > expires_in.as_secs() {
                            debug!("OpenID Connect: refreshing token for ID \"{}\"", &session.id);
                            let token_response = self.client
                                .exchange_refresh_token(&refresh_token)
                                .request(logging_http_client!());
                            match token_response {
                                Ok(token_response) => {
                                    if let Ok(new_token) = create_session_token(token_response, session.id, session.role_name) {
                                        return Some(Auth::Bearer(Token::from(new_token)));
                                    }
                                },
                                Err(err) => {
                                    warn!("OpenID Connect: unable to determine the session age: {}", err);
                                }
                            }
                        }
                    },
                    Err(err) => {
                        warn!("OpenID Connect: unable to determine the session age: {}", err);
                    }
                }
            }
        }
        None
    }
}

impl AuthProvider for OpenIDConnectAuthProvider {
    fn get_actor(&self, auth: &Auth) -> KrillResult<Option<Actor>> {
        match auth {
            Auth::Bearer(token) => {
                // see if we can decode, decrypt and deserialize the users token
                // into a login session structure
                let session = extract_session_from_token(token.clone())?;

                Ok(Some(Actor::from_string(session.id)))
            },
            _ => Err(KrillError::ApiInvalidCredentials)
        }
    }

    fn is_api_allowed(&self, auth: &Auth, wanted_access: Permissions) -> KrillResult<Option<Auth>> {
        match auth {
            Auth::Bearer(token) => {
                // see if we can decode, decrypt and deserialize the users token
                // into a login session structure
                let session = extract_session_from_token(token.clone())?;

                // so far so good, now find out which permissions the users
                // role entitles them to (and don't lose the session)
                let (role, entitled_perms) = lookup_role(session.role_name.clone())?;

                // do the users entitled permissions grant the wanted access?
                let allowed = entitled_perms.contains(wanted_access);

                debug!("ID: {:?}, Role: {:?}, Access Granted? {}, Requested: {:?}, Entitled: {:?}",
                    &session.id, &role, &allowed, &wanted_access, &entitled_perms);

                // if yes, also refresh the access token if needed and pass it
                // back as part of a new encrypted session token to the caller
                // for eventual storage at the client
                match allowed {
                    true => Ok(self.refresh_token(session)),
                    false => Err(KrillError::ApiInsufficientRights)
                }
            },
            _ => Err(KrillError::ApiInvalidCredentials)
        }
    }

    /// Generate the login URL that the client should direct the end-user to so
    /// they can login with the operators chosen OpenID Connect: provider. The
    /// URL should be requested by the client on every login as the intention is
    /// that it contains randomly generated CSFF token and nonce values which
    /// can be used to protect against certain cross-site and replay attacks.
    fn get_login_url(&self) -> String {
        // TODO: we probably should do some more work here to ensure we get the
        // proper security benefits of the CSRF token and nonce features.
        // Currently we are discarding the CSRF token instead of checking it
        // later, and for the Nonce we're using a simple hard-coded value that
        // we can easily check on processing of the redirect.
        //
        // Per https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest:
        //   "Opaque value used to maintain state between the request and the
        //    callback. Typically, Cross-Site Request Forgery (CSRF, XSRF)
        //    mitigation is done by cryptographically binding the value of this
        //    parameter with a browser cookie."
        //
        // Per https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes:
        //   "we can persist the nonce in the client e.g. by storing "the
        //    cryptographically random value in HTML5 local storage and use a
        //    cryptographic hash of this value."
        let request = self.client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                || Nonce::new(NONCE_TODO_MAKE_RANDOM.to_string()) // Nonce::new_random
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
        let request = request.add_prompt(CoreAuthPrompt::Login);

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
        let request = request.add_scope(Scope::new("email".to_string()));

        // TODO: let the operator specify additional scopes to send in the Krill
        // config file.

        let (authorize_url, _csrf_state, _nonce) = request.url();

        debug!("OpenID Connect: login URL will be {:?}", &authorize_url);

        return authorize_url.to_string()
    }

    fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser> {
        match auth {
            // OpenID Connect Authorization Code Flow
            // See: https://tools.ietf.org/html/rfc6749#section-4.1
            //      https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
            Auth::AuthorizationCode(code, _state) => {
// ==========================================================================================
                // Step 1: exchange the temporary (e.g. valid for 10 minutes or
                // something like that) OAuth2 authorization code for an OAuth2
                // access token, OAuth2 refresh token and OpenID Connect ID
                // token.
                // See: https://tools.ietf.org/html/rfc6749#section-4.1.2
                //      https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse
// ==========================================================================================
                let token_response: FlexibleTokenResponse = self.client
                    .exchange_code(AuthorizationCode::new(code.to_string()))
                    .request(logging_http_client!())
                    .map_err(|e| KrillError::Custom(format!(
                        "OpenID Connect: code exchange failed: {}",
                        e.to_string())))?;

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

                let nonce = Nonce::new(NONCE_TODO_MAKE_RANDOM.to_string());
                let id_token_verifier: CoreIdTokenVerifier = self.client.id_token_verifier();
                let id_token_claims: &FlexibleIdTokenClaims = token_response
                    .extra_fields()
                    .id_token()
                    .ok_or_else(|| KrillError::Custom(format!(
                        "OpenID Connect: ID token is missing, does the
                            provider support OpenID Connect?")))? // happens if the server only supports OAuth2
                    .claims(&id_token_verifier, &nonce)
                    .map_err(|e| KrillError::Custom(format!(
                        "OpenID Connect: ID token verification failed: {}",
                        e.to_string())))?;

                if util::http_debug_log_enabled() {
                    debug!("OpenID Connect: Identity provider returned ID token: {:?}", id_token_claims);
                }

                // TODO: There's also a suggestion to verify the access token
                // received above using the at_hash claim in the ID token, if
                // we revceived that claim.
                // See: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation

                // TODO: allow the customer to configure which claim is used for
                // identity, don't just assume it is "email". This might also
                // require allowing the customer to control the scope values 
                // that are sent to the server (which we configured above in
                // fn build_client()).
                let email = id_token_claims.email().map_or("Unknown".to_string(), |v| v.to_string());

                // TODO: Why am I saving this??? Left over from early testing?
                // Was I thinking of passing it to the client and then getting
                // it back and re-verifying it? Why not do that with the ID
                // token above instead as that is always signed while the
                // userinfo response is optionally signed...?
                // let mut saved_ui_res: Option<openidconnect::HttpResponse> = None;

// ==========================================================================================
                // Step 3: Contact the userinfo endpoint.
                // See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
// ==========================================================================================

                // Fetch claims from the userinfo endpoint. Why? Do we need to
                // do this if we already got the users identity and role from
                // the previous step, and thus only in the case where they are
                // not available without contacting the userinfo endpoint?
                let user_info_claims: FlexibleUserInfoClaims = self.client
                    .user_info(token_response.access_token().clone(), None)
                    .map_err(|e| KrillError::Custom(format!(
                        "OpenID Connect: ID provider has no user info endpoint: {}",
                        e.to_string())))?
                    // don't require the response to be signed as the spec says
                    // signing it is optional: See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
                    .require_signed_response(false)
                    .request(logging_http_client!())
                    .map_err(|e| KrillError::Custom(format!(
                        "OpenID Connect: ID user info request failed: {}",
                        e.to_string())))?;

// ==========================================================================================
                // Step 4: Extract and validate the "claim" that tells us which
                // Krill role this user should have.
// ==========================================================================================

                // This unwrap() is safe as we must have an OpenID Connect
                // config block in order to reach this point and the roles field
                // has a default value so always exists.
                let roles_conf = &CONFIG.auth_openidconnect.as_ref().unwrap().roles;

                let extra_claims = match &roles_conf.source {
                    RoleSource::IdTokenAdditionalClaim => {
                        Some(id_token_claims.additional_claims())
                    },
                    RoleSource::UserInfoAdditionalClaim => {
                        Some(user_info_claims.additional_claims())
                    },
                };

                let role_name = match &roles_conf.source {
                    RoleSource::IdTokenAdditionalClaim|RoleSource::UserInfoAdditionalClaim => {
                        // We don't precompile the JMESPath expression because
                        // the jmespath crate requires it to have a lifetime and
                        // storing that in our state struct would infect the
                        // entire struct with lifetimes, plus logins don't
                        // happen very often and are slow anyway (as the user
                        // has to visit the OpenID Connect providers own login
                        // form then be redirected back to us).
                        let jmespath_string = roles_conf.jmespath.to_string();
                        let expr = &jmespath::compile(&jmespath_string)
                            .map_err(|e| KrillError::Custom(format!(
                                "OpenID Connect: unable to compile roles JMESPath {}: {:?}",
                                &jmespath_string,
                                e)))?;
                        let found = expr.search(&extra_claims.unwrap())
                            .map_err(|e| KrillError::Custom(format!(
                                "OpenID Connect: unable to find match for JMESPath {} in additional claims: {:?}",
                                &jmespath_string,
                                e)))?;

                        // return Some if there is match, None otherwise (e.g.
                        // an array instead of a string)
                        found.as_string().cloned()
                    },
                    // StandardClaim
                    // ConfigFile
                };

// ==========================================================================================
                // Step 5: Respond to the user: access granted, or access denied
                // TODO: Choose which data to store at the client, and then
                // encrypt it here and decrypt it in is_api_allowed(). How can
                // we do that? If we don't do encryption at this point, and thus
                // don't store the access token and refresh token on the client,
                // where does that leave us? Storing the signed id token at the
                // client gives us a login session token which can be verified
                // due to it being signed, and MAY contain the users role in
                // Krill thereby preventing that from being altered. Even if not
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
                match role_name {
                    Some(role_name) => {
                        let (role, entitled_perms) = lookup_role(role_name.clone())?;

                        let api_token = create_session_token(token_response, email.clone(), role_name)?;

                        debug!("ID: {:?}, Role: {:?}, Permissions: {:?}", &email, &role, &entitled_perms);

                        Ok(LoggedInUser { token: api_token, id: base64::encode(&email) })
                    },
                    _ => Err(KrillError::ApiInvalidCredentials), // TODO: change me to user has no role
                }
            },
            _ => Err(KrillError::ApiInvalidCredentials),
        }
    }

    fn logout(&self, auth: Option<Auth>) -> String {
        match auth {
            Some(Auth::Bearer(token)) => {
                forget_cached_session_token(&token);
            },
            Some(Auth::AuthorizationCode(_, _)) => {
                warn!("OpenID Connect: unexpectedly received a temporary authorization token at the logout endpoint.");        
            },
            None => {
                warn!("OpenID Connect: unexpectedly received a logout request without a session token.");        
            }
        }
        self.logout_url.clone()
    }
}

#[cached(
    name = "ROLE_CACHE",
    result = true
)]
fn lookup_role(role_name: String) -> KrillResult<(Role, Permissions)> {
    let roles_conf = &CONFIG.auth_openidconnect.as_ref().unwrap().roles;

    // use the role map, if defined, to lookup the actual role e.g. from an
    // Azure ActiveDirectory group ID GUID.
    let role = match &roles_conf.mapping {
        None => {
            // No customer defined mapping of customer role names to Krill
            // role names, map the name to the role object directly
            match role_name.as_ref() {
                "admin"          => Role::Admin,
                "gui_read_only"  => Role::GuiReadOnly,
                "gui_read_write" => Role::GuiReadWrite,
                _ => return Err(KrillError::ApiInvalidRole),
            }
       },
        Some(mapping) => {
            // The customer defined a mapping from their role names to Krill
            // role names, lookup the role object by the Krill role name.
            // As the mapping in the Krill config file is from Krill role to
            // name customer role name we have to find the key whose _value_
            // is the customer role name.
            match mapping.iter().find(|(_, v)| v == &&role_name) {
                Some((found_role, _)) => found_role.clone(),
                _ => return Err(KrillError::ApiInvalidRole),
            }
        }
    };

    let entitled_perms = match role {
        Role::Admin        => Permissions::ALL_ADMIN,
        Role::GuiReadOnly  => Permissions::GUI_READ,
        Role::GuiReadWrite => Permissions::GUI_WRITE,
    };

    Ok((role, entitled_perms))
}

#[cached(
    name = "SESSION_CACHE",
    result = true,
    time = 1800
)]
fn extract_session_from_token(token: Token) -> KrillResult<ClientSession> {
    info!("Decrypting...");
    let bytes = base64::decode(token.as_ref().as_bytes())
        .map_err(|err| KrillError::Custom(
            format!("OpenID Connect: invalid bearer token: {}", err)))?;

    if bytes.len() <= TAG_SIZE {
        return Err(KrillError::Custom(format!("OpenID Connect: bearer token is too short")));
    }

    let encrypted_len = bytes.len() - TAG_SIZE;
    let (encrypted_bytes, tag_bytes) = bytes.split_at(encrypted_len);
    let mut unencrypted_bytes = Vec::with_capacity(encrypted_len);
    crypt::decrypt(encrypted_bytes, tag_bytes, &mut unencrypted_bytes)?;

    serde_json::from_slice::<ClientSession>(&unencrypted_bytes)
        .map_err(|err| KrillError::Custom(
            format!("OpenID Connect: error while deserializing: {}", err)))
}

fn create_session_token(token_response: FlexibleTokenResponse, id: String, role_name: String) -> KrillResult<String> {
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| KrillError::Custom(
            format!("OpenID Connect: unable to determine the current time: {}", err)))?
        .as_secs();

    let session = ClientSession {
        access_token: token_response.access_token().clone(),
        refresh_token: token_response.refresh_token().cloned(),
        start_time: start_time,
        expires_in: token_response.expires_in(),
        id: id.clone(),
        role_name: role_name.clone(),
    };

    let session_json_str = serde_json::to_string(&session)
        .map_err(|err| KrillError::Custom(format!(
            "OpenID Connect: Error while serializing session data: {}",
            err)))?;
    let unencrypted_bytes = session_json_str.as_bytes();

    let mut encrypted_bytes = Vec::with_capacity(unencrypted_bytes.len());
    let tag: [u8; 16] = crypt::encrypt(unencrypted_bytes, &mut encrypted_bytes)?;

    encrypted_bytes.extend(tag.iter());
    let api_token = base64::encode(&encrypted_bytes);

    Ok(api_token)
}

fn forget_cached_session_token(token: &Token) {
    match SESSION_CACHE.lock() {
        Ok(mut cache) => { cache.cache_remove(token); },
        Err(err) => warn!("OpenID Connect: session cache evict error: {}", err)
    }
}

pub fn get_session_cache_size() -> usize {
    match SESSION_CACHE.lock() {
        Ok(cache) => {
            cache.cache_size()
        },
        Err(err) => {
            warn!("OpenID Connect: session cache size error: {}", err);
            0
        }
    }
}