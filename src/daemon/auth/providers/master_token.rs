use crate::commons::KrillResult;
use crate::commons::api::Token;
use crate::commons::error::Error as KrillError;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser, Permissions};
use crate::daemon::config::CONFIG;
use crate::daemon::http::auth::AUTH_LOGIN_ENDPOINT;

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
    fn is_api_allowed(&self, auth: &Auth, _wanted_permissions: Permissions) -> KrillResult<Option<Auth>> {
        match auth {
            Auth::Bearer(token) if &self.token == token => Ok(None),
            _ => Err(KrillError::ApiInvalidCredentials)
        }
    }

    fn get_login_url(&self) -> String {
        // Direct Lagosta to show the user the Lagosta API token login form
        return AUTH_LOGIN_ENDPOINT.to_string();
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