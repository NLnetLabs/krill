//! A mock implementation of an OpenID Connect 1.0 provider (OP) with support for the following specifications:
//!
//!   - [The OAuth 2.0 Authorization Framework RFC 6749][rfc6749]
//!   - [OAuth 2.0 Token Revocation RFC 7009][rfc7009]
//!   - [OpenID Connect Core 1.0 incorporating errata set 1][openid-connect-core-1_0]
//!   - [OpenID Connect Discovery 1.0 incorporating errata set 1][openid-connect-discovery-1_0]
//!   - [OpenID Connect RP-Initiated Logout 1.0 - draft 01][openid-connect-rpinitiated-1_0]
//!
//! [rfc6749]: https://tools.ietf.org/html/rfc6749
//! [rfc7009]: https://tools.ietf.org/html/rfc7009
//! [openid-connect-core-1_0]: https://openid.net/specs/openid-connect-core-1_0.html
//! [openid-connect-discovery-1_0]: https://openid.net/specs/openid-connect-discovery-1_0.html
//! [openid-connect-rpinitiated-1_0]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
use log::{error, info, trace, warn};
use openidconnect::core::*;
use openidconnect::PrivateSigningKey;
use openidconnect::*;
use openssl::rsa::Rsa;
use serde::ser::{Serialize as SerdeSerialize, SerializeStruct, Serializer as SerdeSerializer};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use urlparse::{parse_qs, urlparse, GetQuery, Query, Url};

use tokio::task;
use tokio::time::sleep;

use krill::commons::error::Error;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::ui::{
    OpenIDConnectMockConfig,
    OpenIDConnectMockMode::{self, *},
};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CustomAdditionalMetadata {
    end_session_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
}
impl AdditionalProviderMetadata for CustomAdditionalMetadata {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CustomAdditionalClaims {
    role: Option<String>,
    inc_cas: Option<String>,
    exc_cas: Option<String>,
}
impl AdditionalClaims for CustomAdditionalClaims {}

// use the CustomAdditionalMetadata type
type CustomProviderMetadata = ProviderMetadata<
    CustomAdditionalMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

// use the CustomAdditionalClaims type, has to be cascaded down a few nesting
// levels of OIDC crate types...
type CustomIdTokenClaims = IdTokenClaims<CustomAdditionalClaims, CoreGenderClaim>;

type CustomIdToken = IdToken<
    CustomAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

type CustomIdTokenFields = IdTokenFields<
    CustomAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;

type CustomTokenResponse = StandardTokenResponse<CustomIdTokenFields, CoreTokenType>;
// end cascade

#[derive(Clone, Debug)]
enum FailureMode {
    // These are various generic failure modes,
    // without Oauth/OpenID Connect specific errors
    SlowResponse {
        rel_path_prefix: String,
        duration: Duration,
    },
    Error500Response {
        rel_path_prefix: String,
    },
    Error503Response {
        rel_path_prefix: String,
    },
    WrongCSRFState,
    MalformedIDToken,
    // These are the RFC 6749 5.2 Errors
    InvalidRequestErrorResponse,
    InvalidClientErrorResponse,
    InvalidGrantErrorResponse,
    InvalidScopeErrorResponse,
    UnauthorizedClientErrorResponse,
    UnsupportedGrantTypeErrorResponse,
}

impl SerdeSerialize for FailureMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: SerdeSerializer,
    {
        let mut state = serializer.serialize_struct("Error", 0)?;
        match self {
            FailureMode::InvalidRequestErrorResponse => state.serialize_field("error", "invalid_request")?,
            FailureMode::InvalidClientErrorResponse => state.serialize_field("error", "invalid_client")?,
            FailureMode::InvalidGrantErrorResponse => state.serialize_field("error", "invalid_grant")?,
            FailureMode::UnauthorizedClientErrorResponse => state.serialize_field("error", "unauthorized_client")?,
            FailureMode::InvalidScopeErrorResponse => state.serialize_field("error", "invalid_scope")?,
            FailureMode::UnsupportedGrantTypeErrorResponse => {
                state.serialize_field("error", "unsupported_grant_type")?
            }
            _ => unreachable!(),
        }
        state.end()
    }
}

#[derive(Clone, Debug, Default)]
struct KnownUser {
    attributes: HashMap<String, String>,
    token_secs: Option<u32>,
    refresh: bool,
    failure_mode: Option<FailureMode>,
}

struct TempAuthzCodeDetails {
    client_id: String,
    nonce: String,
    username: String,
}

#[derive(Clone, Debug)]
struct LoginSession {
    id: KnownUserId,
    id_token: Option<String>,
}

type TempAuthzCode = String;
type TempAuthzCodes = HashMap<TempAuthzCode, TempAuthzCodeDetails>;

type LoggedInAccessToken = String;
type LoginSessions = HashMap<LoggedInAccessToken, LoginSession>;

type KnownUserId = String;
type KnownUsers = HashMap<KnownUserId, KnownUser>;

const DEFAULT_TOKEN_DURATION_SECS: u32 = 3600;
static MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG: AtomicBool = AtomicBool::new(false);

// This function is not used by the integration tests which are the main users of this code, but sometimes it's helpful
// to be able to spin up the mock outside of an integration test which is why this main() fn exists. If we don't allow
// dead_code then cargo test spams the output with function is never used warnings.
#[allow(dead_code)]
#[tokio::main]
pub async fn main() {
    // Log to stdout.
    let _logger = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Trace)
        .chain(std::io::stdout())
        .apply()
        .map_err(|e| format!("Failed to init stderr logging: {}", e));

    start(OpenIDConnectMockConfig::enabled(WithRPInitiatedLogout), 2500).await;
}

pub async fn start(config: OpenIDConnectMockConfig, delay_secs: u64) -> task::JoinHandle<()> {
    let join_handle = task::spawn_blocking(move || {
        run_mock_openid_connect_server(config);
    });

    // wait for the mock OpenID Connect server to be up before continuing
    // otherwise Krill might fail to query its discovery endpoint
    while !MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.load(Ordering::Relaxed) {
        info!("Waiting for mock OpenID Connect server to start");
        sleep(Duration::from_secs(delay_secs)).await;
    }

    join_handle
}

pub async fn stop(join_handle: task::JoinHandle<()>) {
    info!("Signalling the OpenID Connect server to stop");
    MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.store(false, Ordering::Relaxed);
    join_handle.await.unwrap();
}

fn run_mock_openid_connect_server(config: OpenIDConnectMockConfig) {
    let mut enabled = config.enabled_on_startup();
    let mut authz_codes = TempAuthzCodes::new();
    let mut login_sessions = LoginSessions::new();
    let mut known_users = KnownUsers::new();

    let logout_metadata = match config.mode() {
        WithRPInitiatedLogout => CustomAdditionalMetadata {
            end_session_endpoint: Some(String::from("https://localhost:1818/logout")),
            revocation_endpoint: None,
        },
        WithOAuth2Revocation => CustomAdditionalMetadata {
            end_session_endpoint: None,
            revocation_endpoint: Some(String::from("https://localhost:1818/revoke")),
        },
        WithNoLogoutEndpoints => CustomAdditionalMetadata {
            end_session_endpoint: None,
            revocation_endpoint: None,
        },
        NotStarted => {
            unreachable!()
        }
    };

    let provider_metadata: CustomProviderMetadata = ProviderMetadata::new(
        IssuerUrl::new("https://localhost:1818".to_string()).unwrap(),
        AuthUrl::new("https://localhost:1818/authorize".to_string()).unwrap(),
        JsonWebKeySetUrl::new("https://localhost:1818/jwk".to_string()).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Pairwise],
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        logout_metadata,
    )
    .set_token_endpoint(Some(TokenUrl::new("https://localhost:1818/token".to_string()).unwrap()))
    .set_userinfo_endpoint(Some(
        UserInfoUrl::new("https://localhost:1818/userinfo".to_string()).unwrap(),
    ))
    .set_scopes_supported(Some(vec![
        Scope::new("openid".to_string()),
        Scope::new("email".to_string()),
        Scope::new("profile".to_string()),
    ]))
    .set_response_modes_supported(Some(vec![CoreResponseMode::Query]))
    .set_id_token_signing_alg_values_supported(vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256])
    .set_claims_supported(Some(vec![CoreClaimName::new("email".to_string())]));

    let rsa_key = Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
    let rsa_pem = std::str::from_utf8(&rsa_key).unwrap();
    let signing_key = CoreRsaPrivateSigningKey::from_pem(rsa_pem, Some(JsonWebKeyId::new("key1".to_string())))
        .expect("Invalid RSA private key");

    let jwks = CoreJsonWebKeySet::new(vec![
        // RSA keys may also be constructed directly using CoreJsonWebKey::new_rsa(). Providers
        // aiming to support other key types may provide their own implementation of the
        // JsonWebKey trait or submit a PR to add the desired support to this crate.
        signing_key.as_verification_key(),
    ]);

    let discovery_doc = serde_json::to_string(&provider_metadata)
        .map_err(|err| Error::custom(format!("Error while building discovery JSON response: {}", err)))
        .unwrap();
    let jwks_doc = serde_json::to_string(&jwks)
        .map_err(|err| Error::custom(format!("Error while building jwks JSON response: {}", err)))
        .unwrap();
    let login_doc = std::str::from_utf8(include_bytes!("../../test-resources/ui/oidc_login.html")).unwrap();

    fn make_random_value() -> Result<String, Error> {
        let mut access_token_bytes: [u8; 4] = [0; 4];
        openssl::rand::rand_bytes(&mut access_token_bytes)
            .map_err(|err: openssl::error::ErrorStack| Error::custom(format!("Rand error: {}", err)))?;
        Ok(base64::encode(access_token_bytes))
    }

    fn make_access_token() -> Result<AccessToken, Error> {
        Ok(AccessToken::new(make_random_value()?))
    }

    fn make_refresh_token() -> Result<RefreshToken, Error> {
        Ok(RefreshToken::new(make_random_value()?))
    }

    fn get_user_for_session(session: &LoginSession, known_users: &KnownUsers) -> Result<KnownUser, Error> {
        known_users
            .get(&session.id)
            .cloned()
            .ok_or(Error::custom(format!("Internal error, unknown user: {}", session.id)))
    }

    fn get_token_duration_for_user(user: &KnownUser) -> Result<u32, Error> {
        let token_duration = user.token_secs.unwrap_or(DEFAULT_TOKEN_DURATION_SECS);

        if token_duration != DEFAULT_TOKEN_DURATION_SECS {
            info!(
                "Issuing token with non-default expiration time of {} seconds",
                &token_duration
            );
        }

        Ok(token_duration)
    }

    fn make_id_token_response(
        signing_key: &CoreRsaPrivateSigningKey,
        client_id: String,
        nonce: String,
        session: &LoginSession,
        known_users: &KnownUsers,
    ) -> Result<CustomTokenResponse, Error> {
        let user = get_user_for_session(session, known_users)?;
        let token_duration = get_token_duration_for_user(&user)?;
        let access_token = make_access_token()?;

        let id_token = CustomIdToken::new(
            CustomIdTokenClaims::new(
                // Specify the issuer URL for the OpenID Connect Provider.
                IssuerUrl::new("https://localhost:1818".to_string()).unwrap(),
                // The audience is usually a single entry with the client ID of the client for whom
                // the ID token is intended. This is a required claim.
                vec![Audience::new(client_id)],
                // The ID token expiration is usually much shorter than that of the access or refresh
                // tokens issued to clients. Our client only keeps the access/refresh token and the
                // access token expiration time, so this isn't used.
                chrono::Utc::now() + chrono::Duration::seconds(token_duration.into()),
                // The issue time is usually the current time.
                chrono::Utc::now(),
                // Set the standard claims defined by the OpenID Connect Core spec.
                StandardClaims::new(
                    // Stable subject identifiers are recommended in place of e-mail addresses or other
                    // potentially unstable identifiers. This is the only required claim.
                    SubjectIdentifier::new(session.id.to_string()),
                ),
                CustomAdditionalClaims {
                    role: user.attributes.get("role").map_or(None, |v| Some(v.to_string())),
                    inc_cas: user.attributes.get("inc_cas").map_or(None, |v| Some(v.to_string())),
                    exc_cas: user.attributes.get("exc_cas").map_or(None, |v| Some(v.to_string())),
                },
            )
            // Optional: specify the user's e-mail address. This should only be provided if the
            // client has been granted the 'profile' or 'email' scopes.
            .set_email(Some(EndUserEmail::new(session.id.to_string())))
            // Optional: specify whether the provider has verified the user's e-mail address.
            .set_email_verified(Some(true))
            // OpenID Connect Providers may supply custom claims by providing a struct that
            // implements the AdditionalClaims trait. This requires manually using the
            // generic IdTokenClaims struct rather than the CoreIdTokenClaims type alias,
            // however.
            .set_nonce(Some(Nonce::new(nonce))),
            // The private key used for signing the ID token. For confidential clients (those able
            // to maintain a client secret), a CoreHmacKey can also be used, in conjunction
            // with one of the CoreJwsSigningAlgorithm::HmacSha* signing algorithms. When using an
            // HMAC-based signing algorithm, the UTF-8 representation of the client secret should
            // be used as the HMAC key.
            signing_key,
            // Uses the RS256 signature algorithm. This crate supports any RS*, PS*, or HS*
            // signature algorithm.
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            // When returning the ID token alongside an access token (e.g., in the Authorization Code
            // flow), it is recommended to pass the access token here to set the `at_hash` claim
            // automatically.
            Some(&access_token),
            // When returning the ID token alongside an authorization code (e.g., in the implicit
            // flow), it is recommended to pass the authorization code here to set the `c_hash` claim
            // automatically.
            None,
        )
        .unwrap();

        let mut token_response = CustomTokenResponse::new(
            access_token.clone(),
            CoreTokenType::Bearer,
            CustomIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );

        token_response.set_expires_in(Some(&Duration::from_secs(token_duration.into())));

        if user.refresh {
            let refresh_token = make_refresh_token()?;
            token_response.set_refresh_token(Some(refresh_token));
        }

        Ok(token_response)
    }

    fn base64_decode(encoded: String) -> Result<String, Error> {
        String::from_utf8(
            base64::decode(&encoded)
                .map_err(|err: base64::DecodeError| Error::custom(format!("Base64 decode error: {}", err)))?,
        )
        .map_err(|err: std::string::FromUtf8Error| Error::custom(format!("UTF8 decode error: {}", err)))
    }

    fn url_encode(decoded: String) -> Result<String, Error> {
        urlparse::quote(decoded, b"")
            .map_err(|err: std::string::FromUtf8Error| Error::custom(format!("UTF8 decode error: {}", err)))
    }

    fn require_query_param(query: &Query, param: &str) -> Result<String, Error> {
        // TODO: ensure that such errors actually result in a https://tools.ietf.org/html/rfc6749#section-5.2
        // compliant { "error": "invalid_request" } JSON error response.
        query
            .get_first_from_str(param)
            .ok_or(Error::custom(format!("Missing query parameter '{}'", param)))
    }

    fn handle_discovery_request(request: Request, discovery_doc: &str) -> Result<(), Error> {
        request
            .respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                    .with_data(discovery_doc.clone().as_bytes(), None),
            )
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
    }

    fn handle_jwks_request(request: Request, jwks_doc: &str) -> Result<(), Error> {
        request
            .respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                    .with_data(jwks_doc.clone().as_bytes(), None),
            )
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
    }

    fn handle_authorize_request(request: Request, url: Url, login_doc: &str) -> Result<(), Error> {
        let query = url
            .get_parsed_query()
            .ok_or(Error::custom("Missing query parameters"))?;
        let client_id = require_query_param(&query, "client_id")?;
        let nonce = require_query_param(&query, "nonce")?;
        let state = require_query_param(&query, "state")?;
        let redirect_uri = require_query_param(&query, "redirect_uri")?;

        request
            .respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: text/html").unwrap())
                    .with_data(
                        login_doc
                            .replace("<NONCE>", &base64::encode(&nonce))
                            .replace("<STATE>", &base64::encode(&state))
                            .replace("<REDIRECT_URI>", &base64::encode(&redirect_uri))
                            .replace("<CLIENT_ID>", &base64::encode(&client_id))
                            .as_bytes(),
                        None,
                    ),
            )
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
    }

    fn handle_login_request(
        request: Request,
        url: Url,
        authz_codes: &mut TempAuthzCodes,
        known_users: &mut KnownUsers,
    ) -> Result<(), Error> {
        let query = url
            .get_parsed_query()
            .ok_or(Error::custom("Missing query parameters"))?;
        let redirect_uri = require_query_param(&query, "redirect_uri")?;
        let redirect_uri = base64_decode(redirect_uri)?;

        fn bool_query_param(query: &Query, param: &str) -> bool {
            match query.get_first_from_str(param) {
                Some(value) => bool::from_str(&value).unwrap_or(false),
                None => false,
            }
        }

        fn with_redirect_uri(
            redirect_uri: String,
            query: Query,
            authz_codes: &mut TempAuthzCodes,
            known_users: &mut KnownUsers,
        ) -> Result<(KnownUser, Response<std::io::Empty>), Error> {
            let username = require_query_param(&query, "username")?;
            let failure_mode = query.get_first_from_str("failure_mode");

            let user = match known_users.get(username.as_str()) {
                Some(user) => user,
                None if (username.trim().is_empty() || failure_mode == Some("unknown_user".to_string())) => {
                    return Err(Error::custom(format!("Unknown username '{}'", username)))
                }
                None => {
                    // Create the user on the fly

                    // What attributes should the user have?
                    let mut attributes: HashMap<String, String> = HashMap::new();
                    for i in 1..=5 {
                        if let Some(attr_name) = query.get_first_from_str(&format!("userattr{}", i)) {
                            if let Some(attr_val) = query.get_first_from_str(&format!("userattrval{}", i)) {
                                attributes.insert(attr_name, attr_val);
                            }
                        }
                    }

                    // How long should the issued access token be valid for?
                    let token_secs = Some(u32::from_str(&require_query_param(&query, "token_secs")?).map_err(
                        |err| Error::custom(format!("Failed to parse token_secs query parameter: {}", err)),
                    )?);

                    // Should the user be issued a refresh token?
                    let refresh = bool_query_param(&query, "refresh");

                    fn duration_failure_param(query: &Query) -> Result<Duration, Error> {
                        let secs: String = require_query_param(query, "failure_param")?;
                        let secs: u64 = u64::from_str(&secs).map_err(|err| {
                            Error::custom(format!("Failed to parse failure_param query parameter: {}", err))
                        })?;
                        Ok(Duration::from_secs(secs))
                    }

                    // Should we exhibit some sort of failure for this user?
                    let mut failure_mode = None;
                    if let Some(mode) = query.get_first_from_str("failure_mode") {
                        if let Some(endpoint) = query.get_first_from_str("failure_endpoint") {
                            failure_mode = match (&mode[..], &endpoint[..]) {
                                ("none", "none") => None,
                                ("slow_response", endpoint) => Some(FailureMode::SlowResponse {
                                    rel_path_prefix: format!("/{}", endpoint),
                                    duration: duration_failure_param(&query)?,
                                }),
                                ("http_500", endpoint) => Some(FailureMode::Error500Response {
                                    rel_path_prefix: format!("/{}", endpoint),
                                }),
                                ("http_503", endpoint) => Some(FailureMode::Error503Response {
                                    rel_path_prefix: format!("/{}", endpoint),
                                }),
                                ("invalid_request", _) => Some(FailureMode::InvalidRequestErrorResponse),
                                ("invalid_client", _) => Some(FailureMode::InvalidClientErrorResponse),
                                ("invalid_grant", _) => Some(FailureMode::InvalidGrantErrorResponse),
                                ("unauthorized_client", _) => Some(FailureMode::UnauthorizedClientErrorResponse),
                                ("invalid_scope", _) => Some(FailureMode::InvalidScopeErrorResponse),
                                ("unsupported_grant_type", _) => Some(FailureMode::UnsupportedGrantTypeErrorResponse),
                                ("wrong_csrf_state", _) => Some(FailureMode::WrongCSRFState),
                                ("malformed_id_token", _) => Some(FailureMode::MalformedIDToken),
                                (err_mode, err_endpoint) => {
                                    return Err(Error::custom(format!(
                                        "Unknown failure mode '{}' or endpoint '{:?}'",
                                        err_mode, err_endpoint
                                    )));
                                }
                            };
                        }
                    }

                    let user = KnownUser {
                        attributes,
                        token_secs,
                        refresh,
                        failure_mode,
                    };

                    trace!("Creating mock user '{}': {:?}", &username, &user);

                    known_users.insert(username.clone(), user);

                    known_users.get(username.as_str()).unwrap()
                }
            };

            let client_id = base64_decode(require_query_param(&query, "client_id")?)?;
            let nonce = base64_decode(require_query_param(&query, "nonce")?)?;
            let state = if matches!(user.failure_mode, Some(FailureMode::WrongCSRFState)) {
                info!("Deliberately returning the wrong CSRF state value to the client");
                "some-wrong-csrf-value".to_string()
            } else {
                base64_decode(require_query_param(&query, "state")?)?
            };

            let mut code_bytes: [u8; 4] = [0; 4];
            openssl::rand::rand_bytes(&mut code_bytes)
                .map_err(|err: openssl::error::ErrorStack| Error::custom(format!("Rand error: {}", err)))?;
            let code = base64::encode(code_bytes);

            authz_codes.insert(
                code.clone(),
                TempAuthzCodeDetails {
                    client_id,
                    nonce: nonce.clone(),
                    username,
                },
            );

            let urlsafe_code = url_encode(code)?;
            let urlsafe_state = url_encode(state)?;
            let urlsafe_nonce = url_encode(nonce)?;

            Ok((
                user.clone(),
                Response::empty(StatusCode(302)).with_header(
                    Header::from_str(&format!(
                        "Location: {}?code={}&state={}&nonce={}",
                        redirect_uri, urlsafe_code, urlsafe_state, urlsafe_nonce
                    ))
                    .map_err(|err| {
                        Error::custom(format!("Error while constructing HTTP Location header: {:?}", err))
                    })?,
                ),
            ))
        }

        // per RFC 6749 and OpenID Connect Core 1.0 section 3.1.26
        // Authentication Error Response we should still return a
        // redirect on error but with query params describing the error.
        let (user, response) = match with_redirect_uri(redirect_uri.clone(), query, authz_codes, known_users) {
            Ok((user, response)) => (Some(user), response),
            Err(err) => (
                None,
                Response::empty(StatusCode(302)).with_header(
                    Header::from_str(&format!(
                        "Location: {}?error={}",
                        redirect_uri,
                        url_encode(format!("{}", err))?
                    ))
                    .map_err(|err| {
                        Error::custom(format!("Error while constructing HTTP Location header: {:?}", err))
                    })?,
                ),
            ),
        };

        let request = simulate_server_failure(request, user, &url)?;

        request
            .respond(response)
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
    }

    /// Implement [OpenID Connect RP-Initiated Logout 1.0 - draft 01][openid-connect-rpinitiated-1_0]
    ///
    /// [openid-connect-rpinitiated-1_0]: https://openid.net/specs/openid-connect-rpinitiated-1_0.htmlc
    fn handle_logout_request(
        request: Request,
        known_users: &KnownUsers,
        login_sessions: &mut LoginSessions,
        url: Url,
    ) -> Result<(), Error> {
        let query = url
            .get_parsed_query()
            .ok_or(Error::custom("Missing query parameters"))?;
        let redirect_uri = require_query_param(&query, "post_logout_redirect_uri")?;
        let id_token_hint = require_query_param(&query, "id_token_hint")?;

        let mut found_user_id: Option<String> = None;
        login_sessions.retain(|_k, v| {
            // return false if the id token matches the one we are looking for so that retain() will discard this
            // login session
            if let Some(id_token) = &v.id_token {
                let r = *id_token != id_token_hint;
                if !r {
                    info!(
                        "Logout of id token '{}' terminates session for user '{}' with access/refresh token '{}'",
                        id_token_hint, v.id, _k
                    );
                    if found_user_id.is_none() {
                        found_user_id = Some(v.id.clone());
                    }
                }
                return r;
            }

            warn!("While handling a logout request a login session without an ID token was discovered!");
            true
        });

        match found_user_id {
            Some(user_id) => {
                let request = simulate_server_failure(request, known_users.get(&user_id).cloned(), &url)?;

                remove_related_login_sessions(login_sessions, &user_id);

                let response = Response::empty(StatusCode(302)).with_header(
                    Header::from_str(&format!("Location: {}", redirect_uri)).map_err(|err| {
                        Error::custom(format!("Error while constructing HTTP Location header: {:?}", err))
                    })?,
                );

                return request
                    .respond(response)
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)));
            }
            None => {
                return Err(Error::custom(format!(
                    "Error while logging out: no login session found"
                )))
            }
        };
    }

    fn remove_related_login_sessions(login_sessions: &mut LoginSessions, user_id: &str) {
        // remove all login sessions for the found user id, not just the one with the given token
        // this helps in UI tests where previous tests logged a user in but didn't log them out and their token
        // hasn't expired yet, and then the test calls /test/is_user_logged_in with a user id to see if they are
        // logged in and finds they are, even if they had just been logged out using the id_token_hint...
        login_sessions.retain(|access_or_refresh_token, login_session| {
            // return false if the user id matches the one we are looking for so that retain() will discard this
            // login session
            let r = login_session.id != user_id;
            if !r {
                info!(
                    "Terminating login session for user '{}' with access/refresh token '{}'",
                    login_session.id, access_or_refresh_token
                );
            }
            r
        });
    }

    /// Implement [OAuth 2.0 Token Revocation][rfc7009]
    ///
    /// [rfc7009]: https://tools.ietf.org/html/rfc7009
    fn handle_oauth2_revocation_request(
        mut request: Request,
        login_sessions: &mut LoginSessions,
        known_users: &KnownUsers,
        url: Url,
    ) -> Result<(), Error> {
        // TODO: handle both access and refresh tokens
        let mut body = String::new();
        request
            .as_reader()
            .read_to_string(&mut body)
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))?;

        let query_params = parse_qs(body);
        let token = require_query_param(&query_params, "token")?;
        let token_type_hint = query_params.get_first_from_str("token_type_hint");

        // https://tools.ietf.org/html/rfc7009#section-2.2.1:
        //   unsupported_token_type:  The authorization server does not support
        //   the revocation of the presented token type.  That is, the
        //   client tried to revoke an access token on a server not
        //   supporting this feature.
        if matches!(token_type_hint, Some(hint_str) if hint_str == "access_token") {
            let err_body = json!({
                "error": "unsupported_token_type",
                "error_description": "This mock OpenID Connect server only supports revocation of refresh tokens, not access tokens"
            })
            .to_string();
            request
                .respond(
                    Response::empty(StatusCode(400))
                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                        .with_data(err_body.as_bytes(), None),
                )
                .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
        } else {
            let user = get_requesting_user(&request, known_users, login_sessions).ok();
            let request = simulate_server_failure(request, user, &url)?;

            match login_sessions.remove(&token) {
                None => {
                    warn!("Token '{}' could NOT be revoked: token is NOT known", &token);
                    // From https://tools.ietf.org/html/rfc7009#section-2.2:
                    //   Note: invalid tokens do not cause an error response since the client
                    //   cannot handle such an error in a reasonable way.  Moreover, the
                    //   purpose of the revocation request, invalidating the particular token,
                    //   is already achieved.
                }
                Some(session) => {
                    info!(
                        "Logout of refresh token '{}' terminates session for user '{}'",
                        token, session.id
                    );
                    remove_related_login_sessions(login_sessions, &session.id);
                }
            };

            request
                .respond(Response::empty(StatusCode(200)))
                .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
        }
    }

    fn handle_control_is_user_logged_in_request(
        request: Request,
        url: Url,
        login_sessions: &LoginSessions,
    ) -> Result<(), Error> {
        let query = url
            .get_parsed_query()
            .ok_or(Error::custom("Missing query parameters"))?;
        let username = require_query_param(&query, "username")?;

        match login_sessions.iter().find(|(_, session)| session.id == username) {
            Some((access_token, session)) => {
                info!(
                    "Login session found for user '{}' with access_token={:?} and id_token={:?}",
                    &username, access_token, session.id_token
                );
                request
                    .respond(Response::empty(StatusCode(200)))
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
            }
            None => {
                info!("No login session found for user '{}'", &username);
                request
                    .respond(Response::empty(StatusCode(400)))
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
            }
        }
    }

    fn handle_token_request(
        mut request: Request,
        signing_key: &CoreRsaPrivateSigningKey,
        authz_codes: &mut TempAuthzCodes,
        login_sessions: &mut LoginSessions,
        known_users: &KnownUsers,
        url: Url,
    ) -> Result<(), Error> {
        let mut body = String::new();
        request
            .as_reader()
            .read_to_string(&mut body)
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))?;

        let query_params = parse_qs(body);
        let mut new_keys: Vec<String> = Vec::new();
        let mut new_session: Option<LoginSession> = None;

        // we skip over verifying the Authorization HTTP header but perhaps
        // we should make sure the client is sending that correctly?
        trace!("grant: {:?}", &query_params.get("grant_type"));

        let r = match query_params.get("grant_type") {
            Some(grant_type) if &grant_type[0] == "authorization_code" => {
                if let Some(code) = query_params.get("code") {
                    let code = &code[0];
                    if let Some(authz_code) = authz_codes.remove(code) {
                        trace!("client_id: {:?}", &authz_code.client_id);
                        trace!("username: {:?}", &authz_code.username);

                        // find static user id
                        let mut session = LoginSession {
                            id: known_users
                                .keys()
                                .find(|k| k.to_string() == authz_code.username)
                                .ok_or(Error::custom(format!(
                                    "Internal error, unknown user '{}'",
                                    authz_code.username
                                )))?
                                .clone(),
                            id_token: None, // updated below after the token is generated
                        };

                        let issue_bad_token = if let Some(user) = known_users.get(&session.id) {
                            matches!(user.failure_mode, Some(FailureMode::MalformedIDToken))
                        } else {
                            false
                        };
                        let (token_doc, id_token) = if issue_bad_token {
                            // This represents an ID Token with an illegal "acr" value that is not a string but
                            // rather a nested structure. This will be rejected by the Rust OpenID Connect crate.
                            // We've seen this problem with at least one real OpenID Connect provider deployment.
                            let dummy_access_token = String::from("*****");
                            let id_token_with_invalid_acr = String::from("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL3NvbWUvdXJsIiwic3ViIjoiYmxhaCIsImF1ZCI6ImJsYWgiLCJleHAiOjE2MTcxNDkxMTMsImlhdCI6MTYwNjE2NjA1Mywibm9uY2UiOiJibGFoIiwiYWNyIjp7InZhbHVlcyI6WyJodHRwczovL2V4YW1wbGUuY29tL3NvbWUvdXJsIl19LCJqdGkiOiI5MTgxMGU1Yi01ZDQ2LTRkZGQtYjJiMi01ZjU2MjliMTUyNDAifQ.ZnQvUMKDEcaCI-C9xMdzRB-sEyB9HTZ8sj2nGnMjAQg");
                            let token_doc = format!(
                                r#"{{
                                "access_token":"{}",
                                "token_type":"bearer",
                                "expires_in":299,
                                "id_token":"{}"
                            }}"#,
                                dummy_access_token, id_token_with_invalid_acr
                            );

                            new_keys.push(dummy_access_token);

                            (token_doc, id_token_with_invalid_acr)
                        } else {
                            let token_response = make_id_token_response(
                                signing_key,
                                authz_code.client_id.clone(),
                                authz_code.nonce.clone(),
                                &session,
                                known_users,
                            )?;
                            let token_doc = serde_json::to_string(&token_response).map_err(|err| {
                                Error::custom(format!("Error while building ID Token JSON response: {}", err))
                            })?;
                            if let Some(token) = token_response.refresh_token() {
                                new_keys.push(token.secret().clone());
                            }

                            new_keys.push(token_response.access_token().secret().clone());

                            let id_token = token_response
                                .extra_fields()
                                .id_token()
                                .expect("Missing id_token")
                                .to_string();

                            (token_doc, id_token)
                        };

                        session.id_token = Some(id_token);
                        new_session = Some(session.clone());

                        request
                            .respond(
                                Response::empty(StatusCode(200))
                                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                    .with_data(token_doc.clone().as_bytes(), None),
                            )
                            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
                    } else {
                        Err(Error::custom(format!(
                            "Unknown temporary authorization code '{}'",
                            &code
                        )))
                    }
                } else {
                    Err(Error::custom("Missing query parameter 'code'"))
                }
            }
            Some(grant_type) if &grant_type[0] == "refresh_token" => {
                // we skip over verifying the Authorization HTTP header but perhaps
                // we should make sure the client is sending that correctly?
                info!("client_id refreshing: {:?}", query_params);
                if let Some(refresh_token) = query_params.get("refresh_token") {
                    let refresh_token = &refresh_token[0];
                    if let Some(mut session) = login_sessions.get_mut(refresh_token) {
                        let user = get_user_for_session(&session, known_users)?;
                        trace!("session: {:?}", &session.id);
                        // Check the intentional failure responses we might want to
                        // impose on users and return the apprioriate HTTP response.

                        let request = simulate_server_failure(request, Some(user.clone()), &url)?;

                        let failure_json_str = if let Some(ref failure_mode) = user.failure_mode {
                            match failure_mode {
                                FailureMode::InvalidRequestErrorResponse
                                | FailureMode::InvalidClientErrorResponse
                                | FailureMode::InvalidGrantErrorResponse
                                | FailureMode::InvalidScopeErrorResponse
                                | FailureMode::UnauthorizedClientErrorResponse
                                | FailureMode::UnsupportedGrantTypeErrorResponse => {
                                    Some(json!(failure_mode).to_string())
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };

                        if let Some(json_str) = failure_json_str {
                            warn!(
                                "Simulating refresh failure: Responding with HTTP 400 error '{}' for user '{}'",
                                json_str, &session.id
                            );
                            return request
                                .respond(
                                    Response::empty(StatusCode(400))
                                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                        .with_data(json_str.as_bytes(), None),
                                )
                                .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)));
                        } else if user.refresh {
                            let token_response = make_id_token_response(
                                signing_key,
                                String::from("dummy_client_id"),
                                String::from("dummy_nonce"),
                                &session,
                                known_users,
                            )?;

                            let token_doc = serde_json::to_string(&token_response).map_err(|err| {
                                Error::custom(format!("Error while building ID Token JSON response: {}", err))
                            })?;
                            if let Some(token) = token_response.refresh_token() {
                                new_keys.push(token.secret().clone());
                            }

                            new_keys.push(token_response.access_token().secret().clone());

                            let id_token = token_response
                                .extra_fields()
                                .id_token()
                                .expect("Missing id_token")
                                .to_string();

                            session.id_token = Some(id_token);
                            new_session = Some(session.clone());

                            request
                                .respond(
                                    Response::empty(StatusCode(200))
                                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                        .with_data(token_doc.clone().as_bytes(), None),
                                )
                                .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
                        } else {
                            trace!("Internal error for user session.id={} user={:?}", session.id, &user);
                            Err(Error::custom(format!("Internal error: cowardly refusing to generate a new token for user '{}' that should not get refresh tokens", session.id)))
                        }
                    } else {
                        warn!("Invalid refresh token: Responding with HTTP 400 'invalid_grant'");
                        request
                            .respond(
                                Response::empty(StatusCode(400))
                                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                    .with_data(json!({"error":"invalid_grant"}).to_string().as_bytes(), None),
                            )
                            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
                    }
                } else {
                    warn!("Missing query parameter 'refresh_token': Responding with HTTP 400 'invalid_request'");
                    request
                        .respond(
                            Response::empty(StatusCode(400))
                                .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                .with_data(json!({"error":"invalid_request"}).to_string().as_bytes(), None),
                        )
                        .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
                }
            }
            Some(grant_type) => {
                warn!(
                    "Unsupported grant type: {:?}. Responding with HTTP 400 'unsupported_grant_type'",
                    grant_type
                );
                request
                    .respond(
                        Response::empty(StatusCode(400))
                            .with_header(Header::from_str("Content-Type: application/json").unwrap())
                            .with_data(json!({"error":"unsupported_grant_type"}).to_string().as_bytes(), None),
                    )
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
            }
            None => {
                warn!("Missing query parameter 'grant_type': Responding with HTTP 400 'invalid_request'");
                request
                    .respond(
                        Response::empty(StatusCode(400))
                            .with_header(Header::from_str("Content-Type: application/json").unwrap())
                            .with_data(json!({"error":"invalid_request"}).to_string().as_bytes(), None),
                    )
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
            }
        };

        // do this out here to avoid having both a mutable and immutable reference to login_sessions at the same
        // time, which isn't permitted by the Rust borrow checker. The key could be either an access token or a
        // refresh token, we don't distinguish between the two.
        if let Some(session) = new_session {
            for key in new_keys {
                login_sessions.insert(key, session.clone());
            }
        }

        r
    }

    fn get_requesting_user(
        request: &Request,
        known_users: &KnownUsers,
        login_sessions: &mut LoginSessions,
    ) -> Result<KnownUser, Error> {
        let authz_hdr = request
            .headers()
            .iter()
            .find(|&hdr| hdr.field.equiv("Authorization"))
            .ok_or_else(|| Error::custom("Missing Authorization HTTP request header on call to userinfo endpoint"))?
            .value
            .as_str()
            .to_string();

        if !authz_hdr.to_lowercase().starts_with("bearer ") {
            return Err(Error::custom(format!(
                "Authorization HTTP request header '{}' does not start with 'Bearer ' (case insensitive)",
                authz_hdr
            )));
        }

        let access_token = authz_hdr.splitn(2, ' ').nth(1).ok_or_else(|| {
            Error::custom(format!(
                "Failed to extract access token after the first space in '{}'",
                authz_hdr
            ))
        })?;

        let login_session = login_sessions.get(access_token).ok_or_else(|| {
            Error::custom(format!(
                "Unknown Authorization HTTP request header access token value '{}'",
                access_token
            ))
        })?;

        let user = known_users.get(&login_session.id).ok_or_else(|| {
            Error::custom(format!(
                "No known users found for login session ID '{}'",
                login_session.id
            ))
        })?;

        Ok(user.clone())
    }

    fn handle_user_info_request(
        request: Request,
        known_users: &KnownUsers,
        login_sessions: &mut LoginSessions,
        url: Url,
    ) -> Result<(), Error> {
        let standard_claims: StandardClaims<CoreGenderClaim> =
            StandardClaims::new(SubjectIdentifier::new("sub-123".to_string()));
        let additional_claims = EmptyAdditionalClaims {};
        let claims = UserInfoClaims::new(standard_claims, additional_claims);
        let claims_doc = serde_json::to_string(&claims)
            .map_err(|err| Error::custom(format!("Error while building UserInfo JSON response: {}", err)))?;

        let user = get_requesting_user(&request, known_users, login_sessions)?;
        let request = simulate_server_failure(request, Some(user), &url)?;

        request
            .respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                    .with_data(claims_doc.clone().as_bytes(), None),
            )
            .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
    }

    fn handle_request(
        mode: OpenIDConnectMockMode,
        request: Request,
        discovery_doc: &str,
        jwks_doc: &str,
        login_doc: &str,
        signing_key: &CoreRsaPrivateSigningKey,
        authz_codes: &mut TempAuthzCodes,
        login_sessions: &mut LoginSessions,
        known_users: &mut KnownUsers,
        enabled: &mut bool,
    ) -> Result<(), Error> {
        let url = urlparse(request.url());

        if !*enabled {
            warn!("All OpenID Connect endpoints are disabled! POST /test/enable to re-enable them.")
        }

        match (&enabled, request.method(), url.path.as_str()) {
            // OpenID Connect 1.0. Discovery support
            (true, Method::Get, "/.well-known/openid-configuration") => {
                return handle_discovery_request(request, discovery_doc);
            }
            // OpenID Connect 1.0. Discovery support
            (true, Method::Get, "/jwk") => {
                return handle_jwks_request(request, jwks_doc);
            }
            // OAuth 2.0 Authorization Request support
            (true, Method::Get, "/authorize") => {
                return handle_authorize_request(request, url, login_doc);
            }
            (true, Method::Get, "/login_form_submit") => {
                return handle_login_request(request, url, authz_codes, known_users);
            }
            // OpenID Connect 1.0. Discovery support
            (true, Method::Get, "/userinfo") => {
                return handle_user_info_request(request, known_users, login_sessions, url);
            }
            // OpenID Connect RP-Initiated Logout 1.0 support
            (true, Method::Get, "/logout") => {
                if matches!(mode, WithRPInitiatedLogout) {
                    return handle_logout_request(request, known_users, login_sessions, url);
                }
            }
            (true, Method::Post, "/token") => {
                return handle_token_request(request, signing_key, authz_codes, login_sessions, known_users, url);
            }
            // OAuth 2.0 Token Revocation support
            (true, Method::Post, "/revoke") => {
                if matches!(mode, WithOAuth2Revocation) {
                    return handle_oauth2_revocation_request(request, login_sessions, known_users, url);
                }
            }
            // Test control APIs
            (_, Method::Get, "/test/is_user_logged_in") => {
                return handle_control_is_user_logged_in_request(request, url, login_sessions);
            }
            (_, Method::Post, "/test/enable") => {
                info!("Enabling all OpenID Connect endpoints!");
                *enabled = true;
                return request
                    .respond(Response::empty(StatusCode(200)))
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)));
            }
            (_, Method::Post, "/test/disable") => {
                warn!("Disabling all OpenID Connect endpoints!");
                *enabled = false;
                return request
                    .respond(Response::empty(StatusCode(200)))
                    .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)));
            }
            _ => {}
        };

        return Err(Error::custom(format!("Unknown request: {:?}", request)));
    }

    let address = "127.0.0.1:1818";
    info!("Mock OpenID Connect server: starting on {}", address);

    let server = Server::https(
        address,
        tiny_http::SslConfig {
            certificate: SELF_SIGNED_CERT_PEM.to_vec(),
            private_key: SELF_SIGNED_KEY_PEM.to_vec(),
        },
    )
    .unwrap();

    info!("Mock OpenID Connect server: started");

    if !enabled {
        warn!("All OpenID Connect endpoints are disabled! POST /test/enable to re-enable them.")
    }

    MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.store(true, Ordering::Relaxed);
    while MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.load(Ordering::Relaxed) {
        match server.recv_timeout(Duration::new(1, 0)) {
            Ok(None) => { /* no request received within the timeout */ }
            Ok(Some(request)) => {
                info!("Received {:?}", &request);
                if let Err(err) = handle_request(
                    config.mode(),
                    request,
                    &discovery_doc,
                    &jwks_doc,
                    &login_doc,
                    &signing_key,
                    &mut authz_codes,
                    &mut login_sessions,
                    &mut known_users,
                    &mut enabled,
                ) {
                    error!("{}", err);
                }
            }
            Err(err) => {
                error!("{}", err);
            }
        };
    }

    info!("Mock OpenID Connect: stopped");
}

fn simulate_server_failure(request: Request, user: Option<KnownUser>, url: &Url) -> Result<Request, Error> {
    if let Some(user) = user {
        if let Some(ref failure_mode) = user.failure_mode {
            trace!(
                "Checking if failure {:?} should be simulated for URL {}",
                user.failure_mode,
                url.path
            );
            match failure_mode {
                FailureMode::SlowResponse {
                    rel_path_prefix: prefix,
                    duration: dur,
                } if url.path.starts_with(prefix) => {
                    warn!(
                        "Simulating server failure: Responding slowly after {} seconds",
                        &dur.as_secs()
                    );
                    thread::sleep(*dur);
                }
                FailureMode::Error500Response {
                    rel_path_prefix: prefix,
                } if url.path.starts_with(prefix) => {
                    warn!("Simulating server failure: Responding with HTTP 500");
                    request
                        .respond(Response::empty(StatusCode(500)))
                        .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))?;
                    return Err(Error::custom(
                        "Aborting after deliberately returning a HTTP 500 response",
                    ));
                }
                FailureMode::Error503Response {
                    rel_path_prefix: prefix,
                } if url.path.starts_with(prefix) => {
                    warn!("Simulating server failure: Responding with HTTP 503");
                    request
                        .respond(Response::empty(StatusCode(503)))
                        .map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))?;
                    return Err(Error::custom(
                        "Aborting after deliberately returning a HTTP 503 response",
                    ));
                }
                _ => {
                    trace!("No simulation rules matched");
                }
            }
        }
    }

    Ok(request)
}

static SELF_SIGNED_CERT_PEM: &[u8; 1160] = br#"
-----BEGIN CERTIFICATE-----
MIIDNjCCAh6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEygyMDBBRTIzM0Y4RUE2NkEwMTIyNTJDQThFRTA3OEE5NDM4NEEyQ0JBMCAXDTIxMDIwNTEzMTMxOFoYDzMwMTcwOTEyMTMxMzE4WjAzMTEwLwYDVQQDEygyMDBBRTIzM0Y4RUE2NkEwMTIyNTJDQThFRTA3OEE5NDM4NEEyQ0JBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsb/U46pChhSpznNzX5+XETV+cmSs8AhqVP4Dka7W7RxJnc1H/S5aZRFZsRuQJ7HNW6S9C49WhaY2Pq7s0MQBNjb58WP7XoKjtMrjO6yxOfTv/KwRDbJBahA0H28PpjbKGVHFCN00J8ftV5Cq5K6nLdUslJrNNLx7Rdr3JymHEksJTeK1MQuRtt9EO/1uy1/6a9vIljLUxy2QkbkgVh46GNSu23FAzp21c6c6A99V0FWYhDFSywROpQlhpjuijJKGUR2mulDkp3uaOhcmyUFCOoZ5iZfemI92J8QBLoR2mpQ1d6Kj53P4BgnaiWDSe5JifzDKEFyXhNXkegwI1f+XhwIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQgCuIz+OpmoBIlLKjuB4qUOEosujAfBgNVHSMEGDAWgBQgCuIz+OpmoBIlLKjuB4qUOEosujANBgkqhkiG9w0BAQsFAAOCAQEABAPbMHpra5BFLRtqX/UG/x8yOpjEepIKdSH7sP8QbYcJXa1f7rAe8ZksgmkrLRegwAqo1hcCxJrEaVHTuW+jd4gy9K7HMp+wLaz6W0ToiKZdCVdTH8xIRxH/nVwWFI//Q4F7Qkm+ceHAeHs5qDDMLBuuZz15VcXcw4HaOkDcxeaqdo+8LXx6jvg0Pz5qzjFvdFIxdd8U/q2v2bUSN4g7CZ4Ae6ate0VPCozflIRauNCQ3BBvUMAwxMg9mkNDtpcbJ8rmqMwSjMTP1g9YIDZ2w9BGUagV0xDSHiE56vONQBX209/AWyzQxrvV6jw/222FX2rJL9UNDR+M3jH1QJzS7g==
-----END CERTIFICATE-----
"#;

static SELF_SIGNED_KEY_PEM: &[u8; 1705] = br#"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxv9TjqkKGFKnO
c3Nfn5cRNX5yZKzwCGpU/gORrtbtHEmdzUf9LlplEVmxG5Ansc1bpL0Lj1aFpjY+
ruzQxAE2NvnxY/tegqO0yuM7rLE59O/8rBENskFqEDQfbw+mNsoZUcUI3TQnx+1X
kKrkrqct1SyUms00vHtF2vcnKYcSSwlN4rUxC5G230Q7/W7LX/pr28iWMtTHLZCR
uSBWHjoY1K7bcUDOnbVzpzoD31XQVZiEMVLLBE6lCWGmO6KMkoZRHaa6UOSne5o6
FybJQUI6hnmJl96Yj3YnxAEuhHaalDV3oqPnc/gGCdqJYNJ7kmJ/MMoQXJeE1eR6
DAjV/5eHAgMBAAECggEABADSBp6bCPIGMQQgoRKzEEwoIONrkaxe2LMv2WQaqxRs
BAXPjUAyAPy3DGoWgQ5cFahMKap8xF3N8vN1me4QKOxsDKe3zZUbosK/A2UMSMXf
cc1eRPSyzHS498xEifXJ73AMA/sXZZ33FnXHo4bbdQjMDDzASmPEUvpvfo5M4HiO
hWMd1+vL/zbTvOJblPax7pPG4wL5+U88MezhcYZQ5bCE1Ggixuvnm3UIZaEyBz8+
Jb93RK1f+dXMTnT1PmKaBMWuALzM1wgkES6KLn9ZR6J0x+5r+FVe3lAzUPnsNN0W
fDFVZ+A+padHmrUR+fYIcZRvjJU0wspsOppezM8rwQKBgQDnG80QQ9NwQESL14bS
rXeruqnUngWEOBO8axvF+WR/ImhZAbagDl+F3ERDw+r7b3HkXrmgnVnc9GbuFP27
8jsZsx7aWiejcFkvSW21msDmKEm7ZzBvkcfuWsRUjQk+adLzZcv+0fhJAA/Z3qak
uBctntaiQJI/xAoxI2Mbo1s2SQKBgQDE5MrZ0eC69RLseZtMc4oligw8VNGRB5tN
W9kgXMRpGN2tGsaQQ5fv4B7/gDLZ9HD9g4pAYDMAvjPFYzvfFdvdHbNj5C85nPK0
P/4xLNkzULja28cwzahzCufNuj32fjt5WVPwfqZCd2uP7pl0AIf4lfdx3jp//f0g
xplrmw8fTwKBgBaLTrisdR65FjayApPgmhDld5WnCJC6S6qQpDfuuQ/x0k4EbcU1
Qbo0H3Cg1vZKC8kkOGVjlBWKvdOxtoK0AXHjWDoim0VFO13ygsI5Y2HQQkkGquHn
TaKBti8tRt6QwiQ+JOUppFeyqtks8AKXdqNboEJZnCqePARJGGzkxYwJAoGAEHIT
x3HSVYtW002s/QvBhDUtpHRpNLXv8Nw1HJDjDuw2x9iusSoULMMJk8m/dZkHPwWX
rJzcZbl9VYVeYNnQjX2HmFZc43EKjKezsaPPWIvrhMxKrPbglQtaJULjHg2ZJh+h
9Tp+5JpY76K8SoYo1UihbG9lb39lfzFXazd+Yd0CgYEAuP8OcGYA9Flg4VITsmsR
quZMVrwtPtNEhgfUiJ4v1fCr1OK/QYAufz12GwcK92Q0GMhSkTxjuwvx5EvMIQn2
oGnjilZ7SOyWqZYYqnOSAa1QyS1jKwVeGr0VbZTUsxAa1j6e3IDfjulXVcAsY3Py
oku+A8ZldXbm+E5p9xuOE7w=
-----END PRIVATE KEY-----
"#;
