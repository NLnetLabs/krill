use std::sync::Arc;

use crate::daemon::http::{HttpResponse, HyperRequest};
use crate::{
    commons::{
        api::Token, error::Error, util::httpclient,
        KrillResult,
    },
    daemon::{auth::{AuthInfo, LoggedInUser, Role}, config::Config},
};

// This is NOT an actual relative path to redirect to. Instead it is the path
// string of an entry in the Vue router routes table to "route" to (in the
// Lagosta single page application). See the routes array in router.js of the
// Lagosta source code. Ideally we could instead return a route name and then
// Lagosta could change this path without requiring that we update to match.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login";

pub struct AdminTokenAuthProvider {
    required_token: Token,
    user_id: Arc<str>,
    role: Arc<Role>,
}

impl AdminTokenAuthProvider {
    pub fn new(config: Arc<Config>) -> Self {
        AdminTokenAuthProvider {
            required_token: config.admin_token.clone(),
            // XXX Get from config.
            user_id: "admin".into(),
            role: Role::admin().into(),
        }
    }
}

impl AdminTokenAuthProvider {
    pub fn authenticate(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<Option<AuthInfo>> {
        if log_enabled!(log::Level::Trace) {
            trace!("Attempting to authenticate the request..");
        }

        let res = match httpclient::get_bearer_token(request) {
            Some(token) if token == self.required_token => {
                Ok(Some(AuthInfo::user(
                    self.user_id.clone(), self.role.clone()
                )))
            }
            Some(_) => Err(Error::ApiInvalidCredentials(
                "Invalid bearer token".to_string(),
            )),
            None => Ok(None),
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

    pub fn login(&self, request: &HyperRequest) -> KrillResult<LoggedInUser> {
        match self.authenticate(request)? {
            Some(_actor) => Ok(LoggedInUser {
                token: self.required_token.clone(),
                id: self.user_id.as_ref().into(),
            }),
            None => Err(Error::ApiInvalidCredentials(
                "Missing bearer token".to_string(),
            )),
        }
    }

    pub fn logout(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<HttpResponse> {
        if let Ok(Some(info)) = self.authenticate(request) {
            info!("User logged out: {}", info.actor().name());
        }

        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache(b"/".to_vec()))
    }
}

