use crate::{commons::KrillResult, constants::ACTOR_MASTER_TOKEN, commons::actor::Actor};
use crate::commons::api::Token;
use crate::commons::error::Error as KrillError;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser, Permissions};
use crate::daemon::config::CONFIG;

// This is NOT an actual relative path to redirect to. Instead it is the path
// string of an entry in the Vue router routes table to "route" to (in the
// Lagosta single page application). See the routes array in router.js of the
// Lagosta source code. Ideally we could instead return a route name and then
// Lagosta could change this path without requiring that we update to match.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login";

pub struct MasterTokenAuthProvider {
    token: Token,
}

impl MasterTokenAuthProvider {
    pub fn new() -> Self {
        MasterTokenAuthProvider {
            token: CONFIG.auth_token.clone(),
        }
    }
}

impl AuthProvider for MasterTokenAuthProvider {
    fn get_actor(&self, auth: &Auth) -> KrillResult<Option<Actor>> {
        match auth {
            Auth::Bearer(token) if &self.token == token => Ok(Some(ACTOR_MASTER_TOKEN.clone())),
            _ => Ok(None)
        }
    }

    fn is_api_allowed(&self, auth: &Auth, _wanted_permissions: Permissions) -> KrillResult<Option<Auth>> {
        match auth {
            Auth::Bearer(token) if &self.token == token => Ok(None),
            _ => Err(KrillError::ApiInvalidCredentials)
        }
    }

    fn get_login_url(&self) -> String {
        // Direct Lagosta to show the user the Lagosta API token login form
        return LAGOSTA_LOGIN_ROUTE_PATH.to_string();
    }

    fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser> {
        match auth {
            Auth::Bearer(token) if &self.token == token => {
                // Once login is complete, return the id of the logged in user to 
                Ok(LoggedInUser {
                    token: token.to_string(),
                    id: "master-token@krill.conf".to_string()
                })
            },
            _ => Err(KrillError::ApiInvalidCredentials),
        }
    }

    fn logout(&self, _auth: Option<Auth>) -> String {
        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        return "/".to_string();
    }
}