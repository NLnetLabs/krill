use assert_cmd::prelude::*;
use lazy_static::lazy_static;
use openidconnect::*;
use openidconnect::core::*;
use openidconnect::PrivateSigningKey;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use urlparse::{GetQuery, Query, Url, parse_qs, urlparse};

use krill::commons::error::Error;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CustomAdditionalMetadata {
    end_session_endpoint: String,
}
impl AdditionalProviderMetadata for CustomAdditionalMetadata {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CustomAdditionalClaims {
    role: String,
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

#[derive(Default)]
struct KnownUser {
    role: &'static str,
    _cas: Option<&'static str>,
    token_secs: Option<u32>,
}

struct TempAuthzCodeDetails {
    client_id: String,
    nonce: String,
    username: String,
}
struct LoginSession {
    id: KnownUserId
}

type TempAuthzCode = String;
type TempAuthzCodes = HashMap<TempAuthzCode, TempAuthzCodeDetails>;

type LoggedInAccessToken = String;
type LoginSessions = HashMap<LoggedInAccessToken, LoginSession>;

type KnownUserId = &'static str;
type KnownUsers = HashMap<KnownUserId, KnownUser>;

lazy_static! {
    static ref KNOWN_USERS: KnownUsers = {
        let mut ku = KnownUsers::new();
        ku.insert("admin@krill", KnownUser { role: "admin", ..Default::default() });
        ku.insert("readonly@krill", KnownUser { role: "gui_read_only", ..Default::default() });
        ku.insert("readwrite@krill", KnownUser { role: "gui_read_write", ..Default::default() });
        ku.insert("shorttokenwithoutrefresh@krill", KnownUser { role: "gui_read_write", token_secs: Some(1), ..Default::default() });
        ku
    };
}

const DEFAULT_TOKEN_DURATION_SECS: u32 = 3600;
static KEEP_RUNNING_FLAG: AtomicBool = AtomicBool::new(true);

pub fn run_krill_ui_test(test_name: &str, with_openid_server: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Remove the Krill data directory. Assumes that the .conf file passed to
    // Krill sets data_dir to /tmp/krill... touching the host filesystem like
    // this isn't nice...
    if PathBuf::from("/tmp/krill").exists() {
        Command::new("rm").arg("-R").arg("/tmp/krill").status()?;
    }

    if with_openid_server {
        run_mock_openid_connect_server();
    }

    std::thread::sleep(std::time::Duration::from_millis(3000));

    let mut krill_process = Command::cargo_bin("krill")?
        .arg("-c")
        .arg(format!("test-resources/ui/{}.conf", test_name))
        .spawn()?;
        
    // NOTE: the directory mentioned here must be the same as the directory
    // mentioned in the tests/ui/cypress_plugins/index.js file in the
    // "integrationFolder" property otherwise Cypress mysteriously complains
    // that it cannot find the spec file.
    let cypress_spec_path = format!("tests/ui/cypress_specs/{}.js", test_name);

    let assert = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("--net=host")
        .arg("--ipc=host")
        .arg("-v")
        .arg(format!("{}:/e2e", env::current_dir()?.display()))
        .arg("-w")
        .arg("/e2e")
        .arg("cypress/included:5.5.0")
        .arg("--browser")
        .arg("chrome")
        .arg("--spec")
        .arg(cypress_spec_path)
        .assert();

    krill_process.kill()?;

    if with_openid_server {
        KEEP_RUNNING_FLAG.store(false, Ordering::Relaxed);
    }

    assert.success();

    Ok(())
}

fn run_mock_openid_connect_server() {
    thread::spawn(|| {
        let mut authz_codes = TempAuthzCodes::new();
        let mut login_sessions = LoginSessions::new();

        let provider_metadata: CustomProviderMetadata = ProviderMetadata::new(
            IssuerUrl::new("http://localhost:3001".to_string()).unwrap(),
            AuthUrl::new("http://localhost:3001/authorize".to_string()).unwrap(),
            JsonWebKeySetUrl::new("http://localhost:3001/jwk".to_string()).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Pairwise],
            vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
            CustomAdditionalMetadata { end_session_endpoint: String::new() },
        )
        .set_token_endpoint(Some(TokenUrl::new("http://localhost:3001/token".to_string()).unwrap()))
        .set_userinfo_endpoint(
            Some(UserInfoUrl::new("http://localhost:3001/userinfo".to_string()).unwrap())
        )
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
        let signing_key = CoreRsaPrivateSigningKey::from_pem(
                rsa_pem,
                Some(JsonWebKeyId::new("key1".to_string()))
            ).expect("Invalid RSA private key");

        let jwks = CoreJsonWebKeySet::new(
            vec![
                // RSA keys may also be constructed directly using CoreJsonWebKey::new_rsa(). Providers
                // aiming to support other key types may provide their own implementation of the
                // JsonWebKey trait or submit a PR to add the desired support to this crate.
                signing_key.as_verification_key()
            ]
        );

        let discovery_doc = serde_json::to_string(&provider_metadata)
            .map_err(|err| Error::custom(format!("Error while building discovery JSON response: {}", err))).unwrap();
        let jwks_doc = serde_json::to_string(&jwks)
            .map_err(|err| Error::custom(format!("Error while building jwks JSON response: {}", err))).unwrap();
        let login_doc = std::fs::read_to_string("test-resources/ui/oidc_login.html").unwrap();

        fn make_id_token_response(signing_key: &CoreRsaPrivateSigningKey, authz: &TempAuthzCodeDetails, session: &LoginSession) -> Result<CustomTokenResponse, Error> {
            let mut access_token_bytes: [u8; 4] = [0; 4];
            openssl::rand::rand_bytes(&mut access_token_bytes)
                .map_err(|err: openssl::error::ErrorStack| Error::custom(format!("Rand error: {}", err)))?;
            let access_token = base64::encode(access_token_bytes);
            let access_token = AccessToken::new(access_token);

            let user = KNOWN_USERS.get(&session.id).ok_or(
                Error::custom(format!("Internal error, unknown user: {}", session.id)))?;

            let token_duration = user.token_secs.unwrap_or(DEFAULT_TOKEN_DURATION_SECS);

            if token_duration != DEFAULT_TOKEN_DURATION_SECS {
                log_warning(&format!("Issuing token with non-default expiration time of {} seconds", &token_duration));
            }

            let id_token = CustomIdToken::new(
                CustomIdTokenClaims::new(
                    // Specify the issuer URL for the OpenID Connect Provider.
                    IssuerUrl::new("http://localhost:3001".to_string()).unwrap(),
                    // The audience is usually a single entry with the client ID of the client for whom
                    // the ID token is intended. This is a required claim.
                    vec![Audience::new(authz.client_id.clone())],
                    // The ID token expiration is usually much shorter than that of the access or refresh
                    // tokens issued to clients.
                    chrono::Utc::now() + chrono::Duration::seconds(token_duration.into()),
                    // The issue time is usually the current time.
                    chrono::Utc::now(),
                    // Set the standard claims defined by the OpenID Connect Core spec.
                    StandardClaims::new(
                        // Stable subject identifiers are recommended in place of e-mail addresses or other
                        // potentially unstable identifiers. This is the only required claim.
                        SubjectIdentifier::new(session.id.to_string())
                    ),
                    CustomAdditionalClaims {
                        role: user.role.to_string()
                    }
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
            ).unwrap();

            // TODO: issue a refresh token?
            // TODO: look at how expiration times are issued and handled, as there are
            // two separate times: access token expiration, and id token expiration.
            let mut token_response = CustomTokenResponse::new(
                access_token,
                CoreTokenType::Bearer,
                CustomIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
            );

            // token_response.set_refresh_token()
            token_response.set_expires_in(Some(&Duration::from_secs(token_duration.into())));
            Ok(token_response)
        }
        fn base64_decode(encoded: String) -> Result<String, Error> {
            String::from_utf8(base64::decode(&encoded)
                .map_err(|err: base64::DecodeError| Error::custom(format!("Base64 decode error: {}", err)))?)
                .map_err(|err: std::string::FromUtf8Error| Error::custom(format!("UTF8 decode error: {}", err)))
        }

        fn url_encode(decoded: String) -> Result<String, Error> {
            urlparse::quote(decoded, b"")
                .map_err(|err: std::string::FromUtf8Error| Error::custom(format!("UTF8 decode error: {}", err)))
        }

        fn require_query_param(query: &Query, param: &str) -> Result<String, Error> {
            query.get_first_from_str(param).ok_or(Error::custom(format!("Missing query parameter '{}'", param)))
        }

        fn handle_discovery_request(request: Request, discovery_doc: &str) -> Result<(), Error> {
            request.respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                    .with_data(discovery_doc.clone().as_bytes(), None)
            ).map_err(|err| err.into())
        }

        fn handle_jwks_request(request: Request, jwks_doc: &str) -> Result<(), Error> {
            request.respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                    .with_data(jwks_doc.clone().as_bytes(), None)
            ).map_err(|err: std::io::Error| Error::custom(format!("IO error: {}", err)))
        }

        fn handle_authorize_request(request: Request, url: Url, login_doc: &str) -> Result<(), Error> {
            let query = url.get_parsed_query().ok_or(Error::custom("Missing query parameters"))?;
            let client_id = require_query_param(&query, "client_id")?;
            let nonce = require_query_param(&query, "nonce")?;
            let state = require_query_param(&query, "state")?;
            let redirect_uri = require_query_param(&query, "redirect_uri")?;

            request.respond(
                Response::empty(StatusCode(200))
                    .with_header(Header::from_str("Content-Type: text/html").unwrap())
                    .with_data(login_doc
                        .replace("<NONCE>", &base64::encode(&nonce))
                        .replace("<STATE>", &base64::encode(&state))
                        .replace("<REDIRECT_URI>", &base64::encode(&redirect_uri))
                        .replace("<CLIENT_ID>", &base64::encode(&client_id))
                        .as_bytes(), None)
            ).map_err(|err| err.into())
        }

        fn handle_login_request(request: Request, url: Url, authz_codes: &mut TempAuthzCodes) -> Result<(), Error> {
            let query = url.get_parsed_query().ok_or(Error::custom("Missing query parameters"))?;
            let username = require_query_param(&query, "username")?;

            match KNOWN_USERS.get(username.as_str()) {
                Some(_user) => {
                    let client_id = require_query_param(&query, "client_id")?;
                    let nonce = require_query_param(&query, "nonce")?;
                    let state = require_query_param(&query, "state")?;
                    let redirect_uri = require_query_param(&query, "redirect_uri")?;

                    let client_id = base64_decode(client_id)?;
                    let nonce = base64_decode(nonce)?;
                    let state = base64_decode(state)?;
                    let redirect_uri = base64_decode(redirect_uri)?;

                    let mut code_bytes: [u8; 4] = [0; 4];
                    openssl::rand::rand_bytes(&mut code_bytes)
                        .map_err(|err: openssl::error::ErrorStack| Error::custom(format!("Rand error: {}", err)))?;
                    let code = base64::encode(code_bytes);

                    authz_codes.insert(code.clone(), TempAuthzCodeDetails { client_id, nonce: nonce.clone(), username });

                    let urlsafe_code = url_encode(code)?;
                    let urlsafe_state = url_encode(state)?;
                    let urlsafe_nonce = url_encode(nonce)?;

                    request.respond(
                        Response::empty(StatusCode(302))
                            .with_header(Header::from_str(
                                &format!("Location: {}?code={}&state={}&nonce={}",
                                    redirect_uri, urlsafe_code, urlsafe_state, urlsafe_nonce)
                            ).map_err(|err| Error::custom(format!("Error while constructing HTTP Location header: {:?}", err)))?)
                    ).map_err(|err| err.into())
                },
                None => {
                    Err(Error::custom(format!("Unknown user '{}'", username)))
                }
            }
        }

        fn handle_token_request(mut request: Request, signing_key: &CoreRsaPrivateSigningKey, authz_codes: &mut TempAuthzCodes, login_sessions: &mut LoginSessions) -> Result<(), Error> {
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body)?;

            let query_params = parse_qs(body);

            if let Some(code) = query_params.get("code") {
                let code = &code[0];
                if let Some(authz_code) = authz_codes.remove(code) {
                    // find static user id
                    let session = LoginSession {
                        id: KNOWN_USERS.keys().find(|k| k.to_string() == authz_code.username)
                            .ok_or(Error::custom(format!("Internal error, unknown user '{}'", authz_code.username)))?
                    };

                    let token_response = make_id_token_response(signing_key, &authz_code, &session)?;
                    let token_doc = serde_json::to_string(&token_response)
                    .map_err(|err| Error::custom(format!("Error while building ID Token JSON response: {}", err)))?;
                    
                    login_sessions.insert(token_response.access_token().secret().clone(), session);

                    request.respond(
                        Response::empty(StatusCode(200))
                        .with_header(Header::from_str("Content-Type: application/json").unwrap())
                        .with_data(token_doc.clone().as_bytes(), None)
                    ).map_err(|err| err.into())
                } else {
                    Err(Error::custom(format!("Unknown temporary authorization code '{}'", &code)))
                }
            } else {
                Err(Error::custom("Missing query parameter 'code'"))
            }
        }

        fn handle_user_info_request(request: Request) -> Result<(), Error> {
            let standard_claims: StandardClaims<CoreGenderClaim> = StandardClaims::new(SubjectIdentifier::new("sub-123".to_string()));
            let additional_claims = EmptyAdditionalClaims {};
            let claims = UserInfoClaims::new(standard_claims, additional_claims);
            let claims_doc = serde_json::to_string(&claims)
                .map_err(|err| Error::custom(format!("Error while building UserInfo JSON response: {}", err)))?;
            request.respond(
                Response::empty(StatusCode(200))
                .with_header(Header::from_str("Content-Type: application/json").unwrap())
                .with_data(claims_doc.clone().as_bytes(), None)
            ).map_err(|err| err.into())
        }

        fn handle_request(
            request: Request,
            discovery_doc: &str,
            jwks_doc: &str,
            login_doc: &str,
            signing_key: &CoreRsaPrivateSigningKey,
            authz_codes: &mut TempAuthzCodes,
            login_sessions: &mut LoginSessions)
         -> Result<(), Error> {
            let url = urlparse(request.url());
            match request.method() {
                Method::Get => {
                    match url.path.as_str() {
                        "/.well-known/openid-configuration" => {
                            return handle_discovery_request(request, discovery_doc);
                        },
                        "/jwk" => {
                            return handle_jwks_request(request, jwks_doc);
                        },
                        "/authorize" => {
                            return handle_authorize_request(request, url, login_doc);
                        },
                        "/login_form_submit" => {
                            return handle_login_request(request, url, authz_codes);
                        },
                        "/userinfo" => {
                            return handle_user_info_request(request);
                        }
                        _ => {}
                    }
                },
                Method::Post => {
                    match url.path.as_str() {
                        "/token" => {
                            return handle_token_request(request, signing_key, authz_codes, login_sessions);
                        },
                        _ => {}
                    }
                },
                _ => {}
            };

            return Err(Error::custom(format!("Unknown request: {:?}", request)));
        }

        fn log_internal_error(err: Error) {
            eprintln!(r#"

==================================
Mock OpenID Connect server: ERROR:
==================================
{}

"#, err);
        }

        fn log_warning(warning: &str) {
            eprintln!("Mock OpenID Connect server: WARNING: {}", warning);
        }

        let server = Server::http("127.0.0.1:3001").unwrap();
        while KEEP_RUNNING_FLAG.load(Ordering::Relaxed) {
            match server.recv_timeout(Duration::new(1, 0)) {
                Ok(None) => { /* no request received within the timeout */ },
                Ok(Some(request)) => {
                    if let Err(err) = handle_request(request, &discovery_doc, &jwks_doc, &login_doc, &signing_key, &mut authz_codes, &mut login_sessions) {
                        log_internal_error(err);
                    }
                },
                Err(err) => { 
                    log_internal_error(err.into());
                }
            };
        }
    });
}