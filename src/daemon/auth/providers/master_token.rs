use std::sync::Arc;

use crate::commons::error::Error;
use crate::commons::KrillResult;
use crate::commons::{actor::ActorDef, api::Token};
use crate::constants::ACTOR_DEF_MASTER_TOKEN;
use crate::daemon::auth::{AuthProvider, LoggedInUser};
use crate::daemon::config::Config;
use crate::daemon::http::HttpResponse;

// This is NOT an actual relative path to redirect to. Instead it is the path
// string of an entry in the Vue router routes table to "route" to (in the
// Lagosta single page application). See the routes array in router.js of the
// Lagosta source code. Ideally we could instead return a route name and then
// Lagosta could change this path without requiring that we update to match.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login";

pub struct MasterTokenAuthProvider {
    required_token: Token,
}

impl MasterTokenAuthProvider {
    pub fn new(config: Arc<Config>) -> Self {
        MasterTokenAuthProvider {
            required_token: config.auth_token.clone(),
        }
    }
}

impl AuthProvider for MasterTokenAuthProvider {
    fn get_actor_def(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>> {
        match self.get_bearer_token(request) {
            Some(token) if token == self.required_token => Ok(Some(ACTOR_DEF_MASTER_TOKEN.clone())),
            Some(_) => Err(Error::ApiInvalidCredentials("Invalid bearer token".to_string())),
            None => Ok(None),
        }
    }

    fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // Direct Lagosta to show the user the Lagosta API token login form
        Ok(HttpResponse::text_no_cache(LAGOSTA_LOGIN_ROUTE_PATH.into()))
    }

    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        match self.get_actor_def(request)? {
            Some(actor_def) => Ok(LoggedInUser {
                token: self.required_token.clone(),
                id: actor_def.name.as_str().to_string(),
                attributes: actor_def.attributes.as_map(),
            }),
            None => Err(Error::ApiInvalidCredentials("Missing bearer token".to_string())),
        }
    }

    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        if let Ok(Some(actor)) = self.get_actor_def(request) {
            info!("User logged out: {}", actor.name.as_str());
        }

        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache(b"/".to_vec()))
    }
}