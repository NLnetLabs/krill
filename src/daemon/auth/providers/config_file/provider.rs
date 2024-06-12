use std::{collections::HashMap, sync::Arc};

use base64::engine::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use unicode_normalization::UnicodeNormalization;

use crate::{
    commons::{actor::ActorDef, api::Token, error::Error, util::httpclient, KrillResult},
    constants::{PW_HASH_LOG_N, PW_HASH_P, PW_HASH_R},
    daemon::{
        auth::common::{
            crypt::{self, CryptState},
            session::*,
        },
        auth::providers::config_file::config::ConfigUserDetails,
        auth::{Auth, LoggedInUser},
        config::Config,
        http::HttpResponse,
    },
};

const UI_LOGIN_ROUTE_PATH: &str = "/login?withId=true";

struct UserDetails {
    password_hash: Token,
    salt: String,
    attributes: HashMap<String, String>,
}

fn get_checked_config_user(id: &str, user: &ConfigUserDetails) -> KrillResult<UserDetails> {
    let password_hash = user
        .password_hash
        .as_ref()
        .ok_or_else(|| Error::ConfigError(format!("Password hash missing for user '{}'", id)))?
        .to_string();

    let salt = user
        .salt
        .as_ref()
        .ok_or_else(|| Error::ConfigError(format!("Password salt missing for user '{}'", id)))?
        .to_string();

    Ok(UserDetails {
        password_hash: Token::from(password_hash),
        salt,
        attributes: user.attributes.clone(),
    })
}

pub struct ConfigFileAuthProvider {
    users: HashMap<String, UserDetails>,
    session_key: CryptState,
    session_cache: Arc<LoginSessionCache>,
    fake_password_hash: String,
    fake_salt: String,
}

impl ConfigFileAuthProvider {
    pub fn new(config: Arc<Config>, session_cache: Arc<LoginSessionCache>) -> KrillResult<Self> {
        match &config.auth_users {
            Some(auth_users) => {
                let mut users = HashMap::new();
                for (k, v) in auth_users.iter() {
                    users.insert(k.clone(), get_checked_config_user(k, v)?);
                }

                let session_key = Self::init_session_key(&config)?;

                Ok(ConfigFileAuthProvider {
                    users,
                    session_key,
                    session_cache,
                    fake_password_hash: hex::encode("fake password hash"),
                    fake_salt: hex::encode("fake salt"),
                })
            }
            None => Err(Error::ConfigError("Missing [auth_users] config section!".into())),
        }
    }

    fn init_session_key(config: &Config) -> KrillResult<CryptState> {
        debug!("Initializing login session encryption key");
        crypt::crypt_init(config)
    }

    /// Parse HTTP Basic Authorization header
    fn get_auth(&self, request: &hyper::Request<hyper::Body>) -> Option<Auth> {
        let header = request.headers().get(hyper::http::header::AUTHORIZATION)?;
        let auth = header.to_str().ok()?.strip_prefix("Basic ")?;
        let auth = BASE64_ENGINE.decode(auth).ok()?;
        let auth = String::from_utf8(auth).ok()?;
        let (username, password) = auth.split_once(':')?;

        Some(Auth::UsernameAndPassword {
            username: username.to_string(),
            password: password.to_string(),
        })
    }
}

impl ConfigFileAuthProvider {
    pub fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>> {
        if log_enabled!(log::Level::Trace) {
            trace!("Attempting to authenticate the request..");
        }

        let res = match httpclient::get_bearer_token(request) {
            Some(token) => {
                // see if we can decode, decrypt and deserialize the users token
                // into a login session structure
                let session = self.session_cache.decode(token, &self.session_key, true)?;

                trace!("id={}, attributes={:?}", &session.id, &session.attributes);

                Ok(Some(ActorDef::user(session.id, session.attributes, None)))
            }
            _ => Ok(None),
        };

        if log_enabled!(log::Level::Trace) {
            trace!("Authentication result: {:?}", res);
        }

        res
    }

    pub fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // Direct Lagosta to show the user the Lagosta API token login form
        Ok(HttpResponse::text_no_cache(UI_LOGIN_ROUTE_PATH.into()))
    }

    pub fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        if let Some(Auth::UsernameAndPassword { username, password }) = self.get_auth(request) {
            use scrypt::scrypt;

            // Do NOT bail out if the user is not known because then the unknown user path would return very quickly
            // compared to the known user path and timing differences can aid attackers.
            let (user_password_hash, user_salt) = match self.users.get(&username) {
                Some(user) => (user.password_hash.to_string(), user.salt.clone()),
                None => (self.fake_password_hash.clone(), self.fake_salt.clone()),
            };

            let username = username.trim().nfkc().collect::<String>();
            let password = password.trim().nfkc().collect::<String>();

            // hash twice with two different salts
            // legacy hashing strategy to be compatible with lagosta
            let params = scrypt::Params::new(PW_HASH_LOG_N, PW_HASH_R, PW_HASH_P).unwrap();
            let weak_salt = format!("krill-lagosta-{username}");
            let weak_salt = weak_salt.nfkc().collect::<String>();

            let mut interim_hash: [u8; 32] = [0; 32];
            scrypt(password.as_bytes(), weak_salt.as_bytes(), &params, &mut interim_hash).unwrap();

            let strong_salt: Vec<u8> = hex::decode(user_salt).unwrap();
            let mut hashed_hash: [u8; 32] = [0; 32];
            scrypt(&interim_hash, strong_salt.as_slice(), &params, &mut hashed_hash).unwrap();

            let encoded_hash = hex::encode(hashed_hash);

            if encoded_hash == user_password_hash {
                // And now finally check the user, so that both known and unknown user code paths do the same work
                // and don't result in an obvious timing difference between the two scenarios which could potentially
                // be used to discover user names.
                if let Some(user) = self.users.get(&username) {
                    let api_token = self.session_cache.encode(
                        &username,
                        &user.attributes,
                        HashMap::new(),
                        &self.session_key,
                        None,
                    )?;

                    Ok(LoggedInUser {
                        token: api_token,
                        id: username.to_string(),
                        attributes: user.attributes.clone(),
                    })
                } else {
                    trace!("Incorrect password for user {}", username);
                    Err(Error::ApiInvalidCredentials("Incorrect credentials".to_string()))
                }
            } else {
                trace!("Unknown user {}", username);
                Err(Error::ApiInvalidCredentials("Incorrect credentials".to_string()))
            }
        } else {
            trace!("Missing pr incomplete credentials for login attempt");
            Err(Error::ApiInvalidCredentials("Missing credentials".to_string()))
        }
    }

    pub fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        match httpclient::get_bearer_token(request) {
            Some(token) => {
                self.session_cache.remove(&token);

                if let Ok(Some(actor)) = self.authenticate(request) {
                    info!("User logged out: {}", actor.name.as_str());
                }
            }
            _ => {
                warn!("Unexpectedly received a logout request without a session token.");
            }
        }

        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache("/".into()))
    }
}
