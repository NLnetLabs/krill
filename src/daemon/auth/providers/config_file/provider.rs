use std::collections::HashMap;

use urlparse::{urlparse, GetQuery};

use crate::commons::actor::Actor;
use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;
use crate::daemon::auth::common::config::Role;
use crate::daemon::auth::common::session::*;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser};
use crate::daemon::auth::providers::config_file::config::ConfigUserDetails;
use crate::daemon::config::CONFIG;

// This is NOT an actual relative path to redirect to. Instead it is the path
// string of an entry in the Vue router routes table to "route" to (in the
// Lagosta single page application). See the routes array in router.js of the
// Lagosta source code. Ideally we could instead return a route name and then
// Lagosta could change this path without requiring that we update to match.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login?withId=true";

struct UserDetails {
    role: Role,
    inc_cas: Vec<String>,
    exc_cas: Vec<String>,
    password_hash: String,
}

impl From<&ConfigUserDetails> for UserDetails {
    fn from(user: &ConfigUserDetails) -> Self {
        let (exc_cas, inc_cas): (Vec<String>, Vec<String>) = user.cas.iter()
            .cloned()    
            .partition(|ca| ca.starts_with("!"));
        let exc_cas = exc_cas.iter()
            .map(|ca| ca.trim_start_matches('!').to_string())
            .collect();
        UserDetails {
            role: user.role.clone(),
            inc_cas: inc_cas,
            exc_cas: exc_cas,
            password_hash: user.password_hash.clone(),
        }
    }
}

pub struct ConfigFileAuthProvider {
    users: HashMap<String, UserDetails>
}

impl ConfigFileAuthProvider {
    pub fn new() -> KrillResult<Self> {
        match &CONFIG.auth_users {
            Some(auth_users) => {
                Ok(ConfigFileAuthProvider {
                    users: auth_users.iter()
                        .map(|(k, v)| (k.clone(), UserDetails::from(v)))
                        .collect()
                })
            },
            None => Err(KrillError::ConfigError("Missing [auth_users] config section!".into()))
        }
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

    fn get_actor(&self, auth: &Auth) -> KrillResult<Option<Actor>> {
        match auth {
            Auth::Bearer(token) => {
                // see if we can decode, decrypt and deserialize the users token
                // into a login session structure
                let session = token_to_session(token.clone())?;

                debug!("ID: {:?}, Role: {:?}, Inc CAs: {:?}, Exc CAs: {:?}", &session.id, &session.role, &session.inc_cas, &session.exc_cas);

                Ok(Some(Actor::user(session.id, Some(session.role), &session.inc_cas, &session.exc_cas, None)))
            },
            _ => Err(KrillError::ApiInvalidCredentials)
        }
    }

    fn get_login_url(&self) -> String {
        // Direct Lagosta to show the user the Lagosta API token login form
        LAGOSTA_LOGIN_ROUTE_PATH.to_string()
    }

    fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser> {
        if let Auth::IdAndPasswordHash(id, password_hash) = auth {
            if let Some(user) = self.users.get(id) {
                if &user.password_hash == password_hash {
                    let api_token = session_to_token(&id, &user.role, &user.inc_cas, &user.exc_cas, &[])?;

                    debug!("ID: {:?}, Role: {:?}, Inc CAs: {:?}, Exc CAs: {:?}", &id, &user.role, &user.inc_cas, &user.exc_cas);

                    return Ok(LoggedInUser { token: api_token, id: base64::encode(&id) });
                }
            }
        }
        Err(KrillError::ApiInvalidCredentials)
    }

    fn logout(&self, _auth: Option<Auth>) -> String {
        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        "/".to_string()
    }

    fn get_bearer_token(&self, request: &hyper::Request<hyper::Body>) -> Option<String> {
        if let Some(header) = request.headers().get("Authorization") {
            if let Ok(header) = header.to_str() {
                if header.len() > 6 {
                    let (bearer, token) = header.split_at(6);
                    let bearer = bearer.trim();

                    if "Bearer" == bearer {
                        return Some(String::from(token.trim()));
                    }
                }
            }
        }

        None
    }
}