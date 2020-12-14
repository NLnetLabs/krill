use std::{collections::HashMap, sync::Arc};

use urlparse::{urlparse, GetQuery};

use crate::commons::actor::{Actor, ActorDef};
use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;
use crate::daemon::auth::common::crypt;
use crate::daemon::auth::common::session::*;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser};
use crate::daemon::auth::providers::config_file::config::ConfigUserDetails;
use crate::daemon::config::Config;
use crate::daemon::http::HttpResponse;

// This is NOT an actual relative path to redirect to. Instead it is the path
// string of an entry in the Vue router routes table to "route" to (in the
// Lagosta single page application). See the routes array in router.js of the
// Lagosta source code. Ideally we could instead return a route name and then
// Lagosta could change this path without requiring that we update to match.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login?withId=true";
const LOGIN_SESSION_STATE_KEY_PATH: &str = "login_session_state.key"; // TODO: decide on proper location

struct UserDetails {
    password_hash: String,
    attributes: HashMap<String, String>,
}

fn get_checked_config_user(id: &str, user: &ConfigUserDetails) -> KrillResult<UserDetails> {
    let password_hash = user.password_hash.as_ref()
        .ok_or_else(|| KrillError::ConfigError(
            format!("Password hash missing for user '{}'", id)))?
        .to_string();

    Ok(UserDetails {
        password_hash,
        attributes: user.attributes.clone(),
    })
}

pub struct ConfigFileAuthProvider {
    key: Vec<u8>,
    users: HashMap<String, UserDetails>,
    session_cache: Arc<LoginSessionCache>
}

impl ConfigFileAuthProvider {
    pub fn new(config: Arc<Config>, session_cache: Arc<LoginSessionCache>) -> KrillResult<Self> {
        match &config.auth_users {
            Some(auth_users) => {
                let mut users = HashMap::new();
                for (k, v) in auth_users.iter() {
                    users.insert(k.clone(), get_checked_config_user(k, v)?);
                }

                let key = Self::init_session_key(config.clone())?;

                Ok(ConfigFileAuthProvider {
                    key,
                    users,
                    session_cache
                })
            },
            None => Err(KrillError::ConfigError("Missing [auth_users] config section!".into()))
        }
    }

    fn init_session_key(config: Arc<Config>) -> KrillResult<Vec<u8>> {
        let key_path = config.data_dir.join(LOGIN_SESSION_STATE_KEY_PATH);
        info!("Initializing session encryption key {}", &key_path.display());
        crypt::load_or_create_key(key_path.as_path())
    }
}

impl AuthProvider for ConfigFileAuthProvider {
    fn get_auth(&self, request: &hyper::Request<hyper::Body>) -> Option<Auth> {
        if let Some(password_hash) = self.get_bearer_token(request) {
            if let Some(query) = urlparse(request.uri().to_string()).get_parsed_query() {
                if let Some(id) = query.get_first_from_str("id") {
                    return Some(Auth::IdAndPasswordHash(id, password_hash))
                }
            }
        }
        None
    }

    fn get_actor_def(&self, auth: &Auth) -> KrillResult<Option<ActorDef>> {
        match auth {
            Auth::Bearer(token) => {
                // see if we can decode, decrypt and deserialize the users token
                // into a login session structure
                let session = self.session_cache.decode(token.clone(), &self.key)?;

                trace!("id={}, attributes={:?}", &session.id, &session.attributes);

                Ok(Some(Actor::user(session.id, &session.attributes, None)))
            },
            _ => Err(KrillError::ApiInvalidCredentials)
        }
    }

    fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // Direct Lagosta to show the user the Lagosta API token login form
        Ok(HttpResponse::text_no_cache(LAGOSTA_LOGIN_ROUTE_PATH.into()))
    }

    fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser> {
        if let Auth::IdAndPasswordHash(id, password_hash) = auth {
            if let Some(user) = self.users.get(id) {
                if &user.password_hash == password_hash {
                    let api_token = self.session_cache.encode(&id, &user.attributes, &[], &self.key, None)?;

                    return Ok(LoggedInUser {
                        token: api_token,
                        id: id.to_string(),
                        attributes: user.attributes.clone()
                    });
                }
            }
        }
        Err(KrillError::ApiInvalidCredentials)
    }

    fn logout(&self, auth: Option<Auth>) -> KrillResult<HttpResponse> {
        match auth {
            Some(auth) => match auth.clone() {
                Auth::Bearer(token) => {
                    self.session_cache.remove(&token);

                    if let Ok(Some(actor)) = self.get_actor_def(&auth) {
                        info!("User logged out: {}", actor.name.as_str());
                    }
                },
                _ => {
                    warn!("Unexpectedly received a logout request with an unrecognized auth details.");
                }
            },
            _ => {
                warn!("Unexpectedly received a logout request without a session token.");
            }
        }
        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache("/".into()))
    }
}