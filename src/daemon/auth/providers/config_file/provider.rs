use std::{collections::HashMap, sync::Arc};

use urlparse::{urlparse, GetQuery};

use crate::{
    commons::{
        actor::ActorDef,
        api::Token,
        error::Error,
        util::{httpclient, storage::data_dir_from_storage_uri},
        KrillResult,
    },
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

// This is NOT an actual relative path to redirect to. Instead it is the path
// string of an entry in the Vue router routes table to "route" to (in the
// Lagosta single page application). See the routes array in router.js of the
// Lagosta source code. Ideally we could instead return a route name and then
// Lagosta could change this path without requiring that we update to match.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login?withId=true";
const LOGIN_SESSION_STATE_KEY_PATH: &str = "login_session_state.key"; // TODO: decide on proper location

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

                let session_key = Self::init_session_key(config.clone())?;

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

    fn init_session_key(config: Arc<Config>) -> KrillResult<CryptState> {
        // TODO rewrite this
        let data_dir = data_dir_from_storage_uri(&config.storage_uri).unwrap();
        let key_path = data_dir.join(LOGIN_SESSION_STATE_KEY_PATH);
        info!("Initializing login session encryption key {}", &key_path.display());
        crypt::crypt_init(key_path.as_path())
    }

    fn get_auth(&self, request: &hyper::Request<hyper::Body>) -> Option<Auth> {
        if let Some(password_hash) = httpclient::get_bearer_token(request) {
            if let Some(query) = urlparse(request.uri().to_string()).get_parsed_query() {
                if let Some(id) = query.get_first_from_str("id") {
                    return Some(Auth::IdAndPasswordHash { id, password_hash });
                }
            }
        }
        None
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
        Ok(HttpResponse::text_no_cache(LAGOSTA_LOGIN_ROUTE_PATH.into()))
    }

    pub fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        if let Some(Auth::IdAndPasswordHash { id, password_hash }) = self.get_auth(request) {
            use scrypt::scrypt;

            // Do NOT bail out if the user is not known because then the unknown user path would return very quickly
            // compared to the known user path and timing differences can aid attackers.
            let (user_password_hash, user_salt) = match self.users.get(&id) {
                Some(user) => (user.password_hash.to_string(), user.salt.clone()),
                None => (self.fake_password_hash.clone(), self.fake_salt.clone()),
            };

            // The password has already been hashed once with a weak salt (weak because it is known to the
            // client browser and is trivially based on the users id and a site/Krill specific value). Now hash the
            // given hash again using a locally stored strong salt and compare the resulting hash to the hash we
            // have stored locally for the user.
            let params = scrypt::Params::new(PW_HASH_LOG_N, PW_HASH_R, PW_HASH_P).unwrap();

            let password_hash_bytes = hex::decode(password_hash.as_ref()).unwrap();
            let strong_salt = hex::decode(user_salt).unwrap();
            let mut hashed_hash: [u8; 32] = [0; 32];
            scrypt(
                password_hash_bytes.as_slice(),
                strong_salt.as_slice(),
                &params,
                &mut hashed_hash,
            )
            .unwrap();

            if hex::encode(hashed_hash) == user_password_hash {
                // And now finally check the user, so that both known and unknown user code paths do the same work
                // and don't result in an obvious timing difference between the two scenarios which could potentially
                // be used to discover user names.
                if let Some(user) = self.users.get(&id) {
                    let api_token =
                        self.session_cache
                            .encode(&id, &user.attributes, HashMap::new(), &self.session_key, None)?;

                    Ok(LoggedInUser {
                        token: api_token,
                        id: id.to_string(),
                        attributes: user.attributes.clone(),
                    })
                } else {
                    trace!("Incorrect password for user {}", id);
                    Err(Error::ApiInvalidCredentials("Incorrect credentials".to_string()))
                }
            } else {
                trace!("Unknown user {}", id);
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
