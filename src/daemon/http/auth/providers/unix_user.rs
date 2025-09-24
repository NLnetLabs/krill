//! Auth provider using a pre-defined token.

use std::sync::Arc;
use log::{info, log_enabled, trace};
use tokio::net::unix;
use crate::api::admin::Token;
use crate::commons::KrillResult;
use crate::commons::error::{ApiAuthError, Error};
use crate::config::Config;
use crate::daemon::http::auth::{AuthInfo, LoggedInUser, Role};
use crate::daemon::http::request::HyperRequest;
use crate::daemon::http::response::HttpResponse;


//------------ Constants -----------------------------------------------------

/// The path defined in Krill UI for the login view.
const LAGOSTA_LOGIN_ROUTE_PATH: &str = "/login";


//------------ AuthProvider --------------------------------------------------

/// The unix user auth provider.
///
/// This auth provider checks the user making the request vs. the users
/// allowed to make a request.
///
/// Currently, this provider is hard-coded to translate this grant into
/// a user named “admin” having the admin special role which allows
/// everything everywhere all at once.
pub struct AuthProvider {
    /// The allowed users
    unix_users: Vec<unix::uid_t>,

    /// The admin token
    admin_token: Token,

    /// The user name of the actor if authentication succeeds.
    user_id: Arc<str>,

    /// The role to use if authentication succeeds.
    role: Arc<Role>,
}

impl AuthProvider {
    /// Creates a new unix user auth provider from the given config.
    pub fn new(config: Arc<Config>) -> Self {
        AuthProvider {
            unix_users: config.unix_users().clone(),
            admin_token: config.admin_token.clone(),
            user_id: "admin-token".into(),
            role: Role::admin().into(),
        }
    }
    
    /// Authenticates a user from information included in the UNIX socket.
    ///
    /// If the request is from a UNIX socket and the user matches the allowed
    /// list, return Some()
    pub fn authenticate(
        &self, request: &HyperRequest,
    ) -> Result<Option<(AuthInfo, Option<Token>)>, ApiAuthError> {
        if log_enabled!(log::Level::Trace) {
            trace!("Attempting to authenticate the request..");
        }

        let uid: Option<&unix::uid_t> = request.extensions().get();
        let res = match uid {
            Some(uid) => {
                if self.unix_users.contains(uid) {
                    Ok(Some((
                        AuthInfo::user(self.user_id.clone(), self.role.clone()),
                        None
                    )))
                } else {
                    Err(ApiAuthError::ApiInvalidCredentials(
                        "Unauthorised unix user".to_string(),
                    ))
                }
            },
            None => Ok(None)
        };

        if log_enabled!(log::Level::Trace) {
            trace!("Authentication result: {res:?}");
        }

        res
    }

    /// Returns an HTTP text response with the login URL.
    pub fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // Direct Lagosta to show the user the Lagosta API token login form
        Ok(HttpResponse::text_no_cache(LAGOSTA_LOGIN_ROUTE_PATH.into()))
    }

    /// Establishes a client session from credentials in an HTTP request.
    pub fn login(&self, request: &HyperRequest) -> KrillResult<LoggedInUser> {
        match self.authenticate(request)? {
            Some(_actor) => Ok(LoggedInUser::new(
                self.admin_token.clone(),
                self.user_id.as_ref().into(),
                "admin".into(),
            )),
            None => Err(Error::ApiInvalidCredentials(
                "Not from a UNIX socket".to_string(),
            )),
        }
    }

    /// Returns an HTTP text response with the logout URL.
    pub fn logout(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<HttpResponse> {
        if let Ok(Some((info, _))) = self.authenticate(request) {
            info!("User logged out: {}", info.actor().name());
        }

        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache(b"/".to_vec()))
    }
}

