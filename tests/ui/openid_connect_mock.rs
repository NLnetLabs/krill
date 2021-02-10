//! A mock implementation of an OpenID Connect 1.0 provider (OP) with support for the following specifications:
//!
//!   - [The OAuth 2.0 Authorization Framework RFC 6749][rfc6749]
//!   - [OAuth 2.0 Token Revocation][rfc7009]
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
use tokio::time::delay_for;

use krill::commons::error::Error;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::ui::OpenIDConnectMockMode;

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

// This failure mode can be invoked for a user at user creation time.
// The failure mode will be activated on a 'refresh_token' request
// from Krill to the OIDC Provider
#[derive(Clone, Debug)]
enum RefreshTokenFailureMode {
    // These are the RFC 6749 5.2 Errors
    InvalidRequestErrorResponse,
    InvalidClientErrorResponse,
    InvalidGrantErrorResponse,
    InvalidScopeErrorResponse,
    UnauthorizedClientErrorResponse,
    UnsupportedGrantTypeErrorResponse,
    // These are various generic failure modes,
    // without OAUTH/OpenID Connect specific errors
    NoResponse,
    SlowResponse(Duration),
    Error500Response,
    Error503Response,
}

impl SerdeSerialize for RefreshTokenFailureMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: SerdeSerializer,
    {
        let mut state = serializer.serialize_struct("Error", 0)?;
        match self {
            RefreshTokenFailureMode::InvalidRequestErrorResponse => {
                state.serialize_field("error", "invalid_request")?
            }
            RefreshTokenFailureMode::InvalidClientErrorResponse => state.serialize_field("error", "invalid_client")?,
            RefreshTokenFailureMode::InvalidGrantErrorResponse => state.serialize_field("error", "invalid_grant")?,
            RefreshTokenFailureMode::UnauthorizedClientErrorResponse => {
                state.serialize_field("error", "unauthorized_client")?
            }
            RefreshTokenFailureMode::InvalidScopeErrorResponse => state.serialize_field("error", "invalid_scope")?,
            RefreshTokenFailureMode::UnsupportedGrantTypeErrorResponse => {
                state.serialize_field("error", "unsupported_grant_type")?
            }
            _ => state.serialize_field("error", "unknown_error")?,
        }
        state.end()
    }
}

impl Default for RefreshTokenFailureMode {
    fn default() -> Self {
        RefreshTokenFailureMode::InvalidRequestErrorResponse
    }
}

#[derive(Clone, Default)]
struct KnownUser {
    role: Option<&'static str>,
    inc_cas: Option<&'static str>,
    exc_cas: Option<&'static str>,
    token_secs: Option<u32>,
    refresh: bool,
    on_refresh_token_failure: Option<RefreshTokenFailureMode>,
}

struct TempAuthzCodeDetails {
    client_id: String,
    nonce: String,
    username: String,
}

#[derive(Clone, Debug)]
struct LoginSession {
    id: KnownUserId,
}

type TempAuthzCode = String;
type TempAuthzCodes = HashMap<TempAuthzCode, TempAuthzCodeDetails>;

type LoggedInAccessToken = String;
type LoginSessions = HashMap<LoggedInAccessToken, LoginSession>;

type KnownUserId = &'static str;
type KnownUsers = HashMap<KnownUserId, KnownUser>;

const DEFAULT_TOKEN_DURATION_SECS: u32 = 3600;
static MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG: AtomicBool = AtomicBool::new(false);

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

    start(OpenIDConnectMockMode::OIDCProviderWithRPInitiatedLogout, 2500).await;
}

pub async fn start(config: OpenIDConnectMockMode, delay_secs: u64) -> task::JoinHandle<()> {
    let join_handle = task::spawn_blocking(move || {
        run_mock_openid_connect_server(config);
    });

    // wait for the mock OpenID Connect server to be up before continuing
    // otherwise Krill might fail to query its discovery endpoint
    while !MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.load(Ordering::Relaxed) {
        info!("Waiting for mock OpenID Connect server to start");
        delay_for(Duration::from_secs(delay_secs)).await;
    }

    join_handle
}

pub async fn stop(join_handle: task::JoinHandle<()>) {
    MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.store(false, Ordering::Relaxed);
    join_handle.await.unwrap();
}

fn run_mock_openid_connect_server(config: OpenIDConnectMockMode) {
    thread::spawn(move || {
        let mut authz_codes = TempAuthzCodes::new();
        let mut login_sessions = LoginSessions::new();
        let mut known_users = KnownUsers::new();

        known_users.insert(
            "admin@krill",
            KnownUser {
                role: Some("admin"),
                exc_cas: Some("ta,testbed"),
                ..Default::default()
            },
        );
        known_users.insert(
            "readonly@krill",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                ..Default::default()
            },
        );
        known_users.insert(
            "readwrite@krill",
            KnownUser {
                role: Some("readwrite"),
                exc_cas: Some("ta,testbed"),
                ..Default::default()
            },
        );
        known_users.insert(
            "shorttokenwithoutrefresh@krill",
            KnownUser {
                role: Some("readwrite"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                ..Default::default()
            },
        );
        known_users.insert(
            "shorttokenwithrefresh@krill",
            KnownUser {
                role: Some("readwrite"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                ..Default::default()
            },
        );
        known_users.insert(
            "non-spec-compliant-idtoken-payload",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-unknown-role",
            KnownUser {
                role: None,
                exc_cas: Some("ta,testbed"),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-invalid-request-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::InvalidRequestErrorResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-invalid-client-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::InvalidClientErrorResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-invalid-grant-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::InvalidGrantErrorResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-invalid-scope-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::InvalidScopeErrorResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-unauthorized-client-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::UnauthorizedClientErrorResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-unsupported-grant-type-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::UnsupportedGrantTypeErrorResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-no-response-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::NoResponse),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-slow-response-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::SlowResponse(Duration::from_secs(25))),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-500-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::Error500Response),
                ..Default::default()
            },
        );
        known_users.insert(
            "user-with-503-on-refresh",
            KnownUser {
                role: Some("readonly"),
                exc_cas: Some("ta,testbed"),
                token_secs: Some(5),
                refresh: true,
                on_refresh_token_failure: Some(RefreshTokenFailureMode::Error503Response),
                ..Default::default()
            },
        );

        let logout_metadata = match config {
            OpenIDConnectMockMode::OIDCProviderWithRPInitiatedLogout => CustomAdditionalMetadata {
                end_session_endpoint: Some(String::from("http://localhost:1818/logout")),
                revocation_endpoint: None,
            },
            OpenIDConnectMockMode::OIDCProviderWithOAuth2Revocation => CustomAdditionalMetadata {
                end_session_endpoint: None,
                revocation_endpoint: Some(String::from("http://localhost:1818/revoke")),
            },
            OpenIDConnectMockMode::OIDCProviderWithNoLogoutEndpoints => CustomAdditionalMetadata {
                end_session_endpoint: None,
                revocation_endpoint: None,
            },
            OpenIDConnectMockMode::OIDCProviderWillNotBeStarted => {
                unreachable!()
            }
        };

        let provider_metadata: CustomProviderMetadata = ProviderMetadata::new(
            IssuerUrl::new("http://localhost:1818".to_string()).unwrap(),
            AuthUrl::new("http://localhost:1818/authorize".to_string()).unwrap(),
            JsonWebKeySetUrl::new("http://localhost:1818/jwk".to_string()).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Pairwise],
            vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
            logout_metadata,
        )
        .set_token_endpoint(Some(TokenUrl::new("http://localhost:1818/token".to_string()).unwrap()))
        .set_userinfo_endpoint(Some(
            UserInfoUrl::new("http://localhost:1818/userinfo".to_string()).unwrap(),
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
        let login_doc = std::fs::read_to_string("test-resources/ui/oidc_login.html").unwrap();

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
            authz: &TempAuthzCodeDetails,
            session: &LoginSession,
            known_users: &KnownUsers,
        ) -> Result<CustomTokenResponse, Error> {
            let user = get_user_for_session(session, known_users)?;
            let token_duration = get_token_duration_for_user(&user)?;
            let access_token = make_access_token()?;

            let id_token = CustomIdToken::new(
                CustomIdTokenClaims::new(
                    // Specify the issuer URL for the OpenID Connect Provider.
                    IssuerUrl::new("http://localhost:1818".to_string()).unwrap(),
                    // The audience is usually a single entry with the client ID of the client for whom
                    // the ID token is intended. This is a required claim.
                    vec![Audience::new(authz.client_id.clone())],
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
                        role: user.role.map(|role| role.to_string()),
                        inc_cas: user.inc_cas.map_or(None, |v| Some(v.to_string())),
                        exc_cas: user.exc_cas.map_or(None, |v| Some(v.to_string())),
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
                .set_nonce(Some(Nonce::new(authz.nonce.clone()))),
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
                .map_err(|err| err.into())
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
                .map_err(|err| err.into())
        }

        fn handle_login_request(
            request: Request,
            url: Url,
            authz_codes: &mut TempAuthzCodes,
            known_users: &KnownUsers,
        ) -> Result<(), Error> {
            let query = url
                .get_parsed_query()
                .ok_or(Error::custom("Missing query parameters"))?;
            let redirect_uri = require_query_param(&query, "redirect_uri")?;
            let redirect_uri = base64_decode(redirect_uri)?;

            fn with_redirect_uri(
                redirect_uri: String,
                query: Query,
                authz_codes: &mut TempAuthzCodes,
                known_users: &KnownUsers,
            ) -> Result<Response<std::io::Empty>, Error> {
                let username = require_query_param(&query, "username")?;

                match known_users.get(username.as_str()) {
                    Some(_user) => {
                        let client_id = require_query_param(&query, "client_id")?;
                        let nonce = require_query_param(&query, "nonce")?;
                        let state = require_query_param(&query, "state")?;

                        let client_id = base64_decode(client_id)?;
                        let nonce = base64_decode(nonce)?;
                        let state = base64_decode(state)?;

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

                        Ok(Response::empty(StatusCode(302)).with_header(
                            Header::from_str(&format!(
                                "Location: {}?code={}&state={}&nonce={}",
                                redirect_uri, urlsafe_code, urlsafe_state, urlsafe_nonce
                            ))
                            .map_err(|err| {
                                Error::custom(format!("Error while constructing HTTP Location header: {:?}", err))
                            })?,
                        ))
                    }
                    None => Err(Error::custom("Unknown user name")),
                }
            }

            // per RFC 6749 and OpenID Connect Core 1.0 section 3.1.26
            // Authentication Error Response we should still return a
            // redirect on error but with query params describing the error.
            let response = match with_redirect_uri(redirect_uri.clone(), query, authz_codes, known_users) {
                Ok(response) => response,
                Err(err) => Response::empty(StatusCode(302)).with_header(
                    Header::from_str(&format!(
                        "Location: {}?error={}",
                        redirect_uri,
                        url_encode(format!("{}", err))?
                    ))
                    .map_err(|err| {
                        Error::custom(format!("Error while constructing HTTP Location header: {:?}", err))
                    })?,
                ),
            };

            request.respond(response).map_err(|err| err.into())
        }

        /// Implement [OpenID Connect RP-Initiated Logout 1.0 - draft 01][openid-connect-rpinitiated-1_0]
        ///
        /// [openid-connect-rpinitiated-1_0]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
        fn handle_logout_request(request: Request, url: Url) -> Result<(), Error> {
            // TODO: require the id_token_hint query parameter as per the spec
            // TODO: validate that the token is currently logged in
            // TODO: forget the current login session for the token
            let query = url
                .get_parsed_query()
                .ok_or(Error::custom("Missing query parameters"))?;
            let redirect_uri = require_query_param(&query, "post_logout_redirect_uri")?;

            let response = Response::empty(StatusCode(302)).with_header(
                Header::from_str(&format!("Location: {}", redirect_uri)).map_err(|err| {
                    Error::custom(format!("Error while constructing HTTP Location header: {:?}", err))
                })?,
            );

            request.respond(response).map_err(|err| err.into())
        }

        /// Implement [OAuth 2.0 Token Revocation][rfc7009]
        ///
        /// [rfc7009]: https://tools.ietf.org/html/rfc7009
        fn handle_oauth2_revocation_request(
            mut request: Request,
            login_sessions: &mut LoginSessions,
            known_users: &mut KnownUsers,
        ) -> Result<(), Error> {
            // TODO: handle both access and refresh tokens
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body)?;

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
                    .map_err(|err| err.into())
            } else {
                match login_sessions.remove(&token) {
                    Some(removed_session) => {
                        log_info(&format!("Token '{}' has been revoked", &token));
                        match known_users.remove(&removed_session.id) {
                            Some(_) => {
                                log_info(&format!("User '{}' has been forgotten", &removed_session.id));
                                request
                                    .respond(Response::empty(StatusCode(200)))
                                    .map_err(|err| err.into())
                            }
                            None => {
                                log_warning(&format!("User '{}' could NOT be forgotten", &token));
                                request
                                    .respond(Response::empty(StatusCode(400)))
                                    .map_err(|err| err.into())
                            }
                        }
                    }
                    None => {
                        log_warning(&format!("Token '{}' could NOT be revoked: token is NOT known", &token));
                        // From https://tools.ietf.org/html/rfc7009#section-2.2:
                        //   Note: invalid tokens do not cause an error response since the client
                        //   cannot handle such an error in a reasonable way.  Moreover, the
                        //   purpose of the revocation request, invalidating the particular token,
                        //   is already achieved.
                        request
                            .respond(Response::empty(StatusCode(200)))
                            .map_err(|err| err.into())
                    }
                }
            }
        }

        fn handle_control_is_user_logged_in_request(
            request: Request,
            url: Url,
            known_users: &KnownUsers,
        ) -> Result<(), Error> {
            let query = url
                .get_parsed_query()
                .ok_or(Error::custom("Missing query parameters"))?;
            let username = require_query_param(&query, "username")?;

            match known_users.get(username.as_str()) {
                Some(_user) => {
                    log_info(&format!("User '{}' is known", &username));
                    request
                        .respond(Response::empty(StatusCode(200)))
                        .map_err(|err| err.into())
                }
                None => {
                    log_info(&format!("User '{}' is NOT known", &username));
                    // See: https://tools.ietf.org/html/rfc6749#section-5.2
                    let err_body = json!({
                        "error": "invalid_grant"
                    })
                    .to_string();
                    request
                        .respond(
                            Response::empty(StatusCode(400))
                                .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                .with_data(err_body.as_bytes(), None),
                        )
                        .map_err(|err| err.into())
                }
            }
        }

        fn handle_token_request(
            mut request: Request,
            signing_key: &CoreRsaPrivateSigningKey,
            authz_codes: &mut TempAuthzCodes,
            login_sessions: &mut LoginSessions,
            known_users: &KnownUsers,
        ) -> Result<(), Error> {
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body)?;

            let query_params = parse_qs(body);
            let mut new_key: Option<String> = None;
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
                            let session = LoginSession {
                                id: known_users
                                    .keys()
                                    .find(|k| k.to_string() == authz_code.username)
                                    .ok_or(Error::custom(format!(
                                        "Internal error, unknown user '{}'",
                                        authz_code.username
                                    )))?,
                            };

                            let (token_doc, refresh_token) = if authz_code.username
                                == "non-spec-compliant-idtoken-payload"
                            {
                                // This represents an ID Token with an illegal "acr" value that is not a string but rather a nested
                                // structure. This will be rejected by the Rust OpenID Connect crate. We've seen this problem with
                                // at least one real OpenID Connect provider deployment.
                                let token_doc = r#"{
                                    "access_token":"*****",
                                    "token_type":"bearer",
                                    "expires_in":299,
                                    "id_token":"eyJraWQiOiIyOTM5ODY3ODU5NDEyMzYxNTU4MzQ0MjM1NzUzNzM5OTE2NDQ1IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLmVzc28tdWF0LmNoYXJ0ZXIuY29tOjg0NDMvbmlkcC9vYXV0aC9uYW0iLCJzdWIiOiIyMTJjYzI1ZmVkYjE0YjQ1ODlhNmNmNmI2MTFiZTdhNiIsImF1ZCI6Ijk3YTUwYjFiLWIwNmYtNGIyOC04ZDdmLTk1MjA0MjdkZWFlYSIsImV4cCI6MTYwNjE2NjM1MywiaWF0IjoxNjA2MTY2MDUzLCJub25jZSI6IkRVTU1ZX0ZJWEVEX1ZBTFVFX0ZPUl9OT1ciLCJhY3IiOnsidmFsdWVzIjpbImh0dHBzOi8vbG9naW4uZXNzby11YXQuY2hhcnRlci5jb206ODQ0My9uaWRwL2tlcmJlcm9zL3Zkcy91cmkiXX19.K8TjWJQ3xb11iRxoyxwOVqSJT3nj2tNrk8gsljeLTGgZIcdtrLKiNppU09DQFtYIG-I9sKCzb98ZszIBVw5V1uUr4ztGTBL6quEgtT_14wYA5og_z_piNyhmy7WYpRkCQDZiW-RavfrbbRDwl2LgillxHdIG76O_0YutxnV_LIjfFR9N5pRC511JAI-3GgO7IOd6sMTs2EbeBJLNs2w6gzqwOQiTjyDaRxz6QgisR2JhzW3WgpVX6MaAYz-TpT_6ylodXYUkBW5hwzVdj2Ja-4YNdvIPx1_gclvxlVW2Y_pBXFQgkOaV7k1NH0r_SmqCWARPp7oA56b2ppCkJNphhQ"
                                }"#.to_string();

                                (token_doc, None)
                            } else {
                                let token_response =
                                    make_id_token_response(signing_key, &authz_code, &session, known_users)?;
                                let token_doc = serde_json::to_string(&token_response).map_err(|err| {
                                    Error::custom(format!("Error while building ID Token JSON response: {}", err))
                                })?;
                                let refresh_token = token_response.refresh_token().cloned();

                                (token_doc, refresh_token)
                            };

                            if let Some(token) = refresh_token {
                                new_key = Some(token.secret().clone());
                                new_session = Some(session.clone());
                            }

                            request
                                .respond(
                                    Response::empty(StatusCode(200))
                                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                        .with_data(token_doc.clone().as_bytes(), None),
                                )
                                .map_err(|err| err.into())
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
                        if let Some(session) = login_sessions.get(refresh_token) {
                            let user = get_user_for_session(&session, known_users)?;
                            trace!("session: {:?}", &session.id);
                            // Check the intentional failure responses we might want to
                            // impose on users and return the apprioriate HTTP response.
                            match user.on_refresh_token_failure {
                                None => {}
                                Some(RefreshTokenFailureMode::NoResponse) => {
                                    trace!("Not responding to request");
                                    thread::park();
                                }
                                Some(RefreshTokenFailureMode::SlowResponse(dur)) => {
                                    trace!("Responding slowly after {} seconds", &dur.as_secs());
                                    thread::sleep(dur);
                                }
                                Some(RefreshTokenFailureMode::Error500Response) => {
                                    trace!("Responding with a 500");
                                    return request
                                        .respond(Response::empty(StatusCode(500)))
                                        .map_err(|err| err.into());
                                }
                                Some(RefreshTokenFailureMode::Error503Response) => {
                                    trace!("Responding with a 503");
                                    return request
                                        .respond(Response::empty(StatusCode(503)))
                                        .map_err(|err| err.into());
                                }
                                Some(err_mode) => {
                                    trace!(
                                        "(Intentionally) returning error '{}' for user '{}'",
                                        json!(err_mode),
                                        &session.id
                                    );
                                    return request
                                        .respond(
                                            Response::empty(StatusCode(400))
                                                .with_header(
                                                    Header::from_str("Content-Type: application/json").unwrap(),
                                                )
                                                .with_data(json!(err_mode).to_string().as_bytes(), None),
                                        )
                                        .map_err(|err| err.into());
                                }
                            }
                            if user.refresh {
                                let token_duration = get_token_duration_for_user(&user)?;
                                let access_token = make_access_token()?;

                                let mut token_response = StandardTokenResponse::new(
                                    access_token.clone(),
                                    CoreTokenType::Bearer,
                                    EmptyExtraTokenFields {},
                                );

                                token_response.set_expires_in(Some(&Duration::from_secs(token_duration.into())));

                                let refresh_token = make_refresh_token()?;
                                token_response.set_refresh_token(Some(refresh_token.clone()));

                                let token_doc = serde_json::to_string(&token_response).map_err(|err| {
                                    Error::custom(format!("Error while building Access Token JSON response: {}", err))
                                })?;

                                new_key = Some(refresh_token.secret().to_string());
                                new_session = Some(session.clone());

                                request
                                    .respond(
                                        Response::empty(StatusCode(200))
                                            .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                            .with_data(token_doc.clone().as_bytes(), None),
                                    )
                                    .map_err(|err| err.into())
                            } else {
                                trace!("Internal error for user '{:?}'", &user.role);
                                Err(Error::custom(format!("Internal error: cowardly refusing to generate a new token for user '{}' that should not get refresh tokens", session.id)))
                            }
                        } else {
                            warn!("Invalid refresh token: Responding with 'invalid_grant'");
                            request
                                .respond(
                                    Response::empty(StatusCode(400))
                                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                        .with_data(json!({"error":"invalid_grant"}).to_string().as_bytes(), None),
                                )
                                .map_err(|err| err.into())
                        }
                    } else {
                        warn!("Missing query parameter 'refresh_token': Responding with 'invalid_request'");
                        request
                            .respond(
                                Response::empty(StatusCode(400))
                                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                    .with_data(json!({"error":"invalid_request"}).to_string().as_bytes(), None),
                            )
                            .map_err(|err| err.into())
                    }
                }
                Some(grant_type) => {
                    warn!("Unsupported grant type: {:?}", grant_type);
                    request
                        .respond(
                            Response::empty(StatusCode(400))
                                .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                .with_data(json!({"error":"unsupported_grant_type"}).to_string().as_bytes(), None),
                        )
                        .map_err(|err| err.into())
                }
                None => {
                    warn!("Missing query parameter 'grant_type': Responding with 'invalid_request'");
                    request
                        .respond(
                            Response::empty(StatusCode(400))
                                .with_header(Header::from_str("Content-Type: application/json").unwrap())
                                .with_data(json!({"error":"invalid_request"}).to_string().as_bytes(), None),
                        )
                        .map_err(|err| err.into())
                }
            };

            // do this out here to avoid having both a mutable and immutable reference to login_sessions at the same
            // time, which isn't permitted by the Rust borrow checker. The key could be either an access token or a
            // refresh token, we don't distinguish between the two.
            if let Some(key) = new_key {
                if let Some(session) = new_session {
                    login_sessions.insert(key, session);
                }
            }

            r
        }

        fn handle_user_info_request(request: Request) -> Result<(), Error> {
            let standard_claims: StandardClaims<CoreGenderClaim> =
                StandardClaims::new(SubjectIdentifier::new("sub-123".to_string()));
            let additional_claims = EmptyAdditionalClaims {};
            let claims = UserInfoClaims::new(standard_claims, additional_claims);
            let claims_doc = serde_json::to_string(&claims)
                .map_err(|err| Error::custom(format!("Error while building UserInfo JSON response: {}", err)))?;
            request
                .respond(
                    Response::empty(StatusCode(200))
                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                        .with_data(claims_doc.clone().as_bytes(), None),
                )
                .map_err(|err| err.into())
        }

        fn handle_request(
            config: &OpenIDConnectMockMode,
            request: Request,
            discovery_doc: &str,
            jwks_doc: &str,
            login_doc: &str,
            signing_key: &CoreRsaPrivateSigningKey,
            authz_codes: &mut TempAuthzCodes,
            login_sessions: &mut LoginSessions,
            known_users: &mut KnownUsers,
        ) -> Result<(), Error> {
            let url = urlparse(request.url());

            trace!(
                "request received: {:?} {:?} {:?}",
                &request.method(),
                &url.path,
                &url.query
            );

            // TODO: add some sort of mock server control interface for use by test scripts to control the test
            // conditions
            // TODO: add an endpoint for forcibly logging a session out by login id, so that the test client (which
            // doesn't know the actual login token in use, only the users login id) can cause Krill to encounter unknown
            // token errors from the mock, e.g. when attempting to logout.
            match (request.method(), url.path.as_str()) {
                // OpenID Connect 1.0. Discovery support
                (Method::Get, "/.well-known/openid-configuration") => {
                    return handle_discovery_request(request, discovery_doc);
                }
                // OpenID Connect 1.0. Discovery support
                (Method::Get, "/jwk") => {
                    return handle_jwks_request(request, jwks_doc);
                }
                // OAuth 2.0 Authorization Request support
                (Method::Get, "/authorize") => {
                    return handle_authorize_request(request, url, login_doc);
                }
                (Method::Get, "/login_form_submit") => {
                    return handle_login_request(request, url, authz_codes, known_users);
                }
                // OpenID Connect 1.0. Discovery support
                (Method::Get, "/userinfo") => {
                    return handle_user_info_request(request);
                }
                // OpenID Connect RP-Initiated Logout 1.0 support
                (Method::Get, "/logout") => {
                    if matches!(config, OpenIDConnectMockMode::OIDCProviderWithRPInitiatedLogout) {
                        return handle_logout_request(request, url);
                    }
                }
                (Method::Post, "/token") => {
                    return handle_token_request(request, signing_key, authz_codes, login_sessions, known_users);
                }
                // OAuth 2.0 Token Revocation support
                (Method::Post, "/revoke") => {
                    if matches!(config, OpenIDConnectMockMode::OIDCProviderWithOAuth2Revocation) {
                        return handle_oauth2_revocation_request(request, login_sessions, known_users);
                    }
                }
                // Test control APIs
                (Method::Get, "/test/is_user_logged_in") => {
                    return handle_control_is_user_logged_in_request(request, url, known_users);
                }
                _ => {}
            };

            return Err(Error::custom(format!("Unknown request: {:?}", request)));
        }

        fn log_error(err: Error) {
            eprintln!("[MOCK OPENID CONNECT SERVER] ERROR: {}", err);
        }

        let address = "127.0.0.1:1818";
        info!("Mock OpenID Connect server: starting on {}", address);

        let server = Server::http(address).unwrap();
        MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.store(true, Ordering::Relaxed);
        while MOCK_OPENID_CONNECT_SERVER_RUNNING_FLAG.load(Ordering::Relaxed) {
            match server.recv_timeout(Duration::new(1, 0)) {
                Ok(None) => { /* no request received within the timeout */ }
                Ok(Some(request)) => {
                    log_info(&format!("Received {:?}", &request));
                    if let Err(err) = handle_request(
                        &config,
                        request,
                        &discovery_doc,
                        &jwks_doc,
                        &login_doc,
                        &signing_key,
                        &mut authz_codes,
                        &mut login_sessions,
                        &mut known_users,
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
    });
}
