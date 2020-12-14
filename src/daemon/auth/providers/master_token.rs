use std::sync::Arc;

use crate::commons::actor::ActorDef;
use crate::commons::error::Error;
use crate::commons::api::Token;
use crate::commons::KrillResult;
use crate::constants::ACTOR_MASTER_TOKEN;
use crate::daemon::auth::{Auth, AuthProvider, LoggedInUser};
use crate::daemon::config::Config;
use crate::daemon::http::HttpResponse;

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
    pub fn new(config: Arc<Config>) -> Self {
        MasterTokenAuthProvider {
            token: config.auth_token.clone(),
        }
    }
}

impl AuthProvider for MasterTokenAuthProvider {
    fn get_auth(&self, request: &hyper::Request<hyper::Body>) -> Option<Auth> {
        match self.get_bearer_token(request) {
            Some(token) => Some(Auth::Bearer(Token::from(token))),
            None => None
        }
    }

    fn get_actor_def(&self, auth: &Auth) -> KrillResult<Option<ActorDef>> {
        match auth {
            Auth::Bearer(token) if &self.token == token => {
                Ok(Some(ACTOR_MASTER_TOKEN.clone()))
            },
            _ => Ok(None)
        }
    }

    fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // Direct Lagosta to show the user the Lagosta API token login form
        Ok(HttpResponse::text_no_cache(LAGOSTA_LOGIN_ROUTE_PATH.into()))
    }

    fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser> {
        if let Auth::Bearer(token) = auth {
            if let Ok(Some(def)) = self.get_actor_def(auth) {
                return Ok(LoggedInUser {
                    token: token.clone(),
                    id: def.name.as_str().to_string(),
                    attributes: def.attributes.as_map()
                });
            }
        }

        Err(Error::ApiInvalidCredentials)
    }

    fn logout(&self, auth: Option<Auth>) -> KrillResult<HttpResponse> {
        if let Some(auth) = auth {
            if let Ok(Some(actor)) = self.get_actor_def(&auth) {
                info!("User logged out: {}", actor.name.as_str());
            }
        }

        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache(b"/".to_vec()))
    }
}