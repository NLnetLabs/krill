//! Auth provider using unix user matching.

use std::collections::HashMap;
use std::sync::Arc;
use log::{log_enabled, trace};
use crate::api::admin::Token;
use crate::commons::error::ApiAuthError;
use crate::config::Config;
use crate::daemon::http::auth::{AuthInfo, RoleMap};
use crate::daemon::http::request::HyperRequest;


//------------ Constants -----------------------------------------------------



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
    unix_users: HashMap<String, String>,

    /// The roles configured
    role_map: Arc<RoleMap>,
}

impl AuthProvider {
    /// Creates a new unix user auth provider from the given config.
    pub fn new(config: Arc<Config>) -> Self {
        AuthProvider {
            unix_users: config.unix_users().clone(),
            role_map: config.auth_roles.clone(),
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

        let user: Option<&nix::unistd::User> = request.extensions().get();
        let res = match user {
            Some(user) => {
                if let Some(role) = self.unix_users.get(&user.name) {
                    if let Some(role) = self.role_map.get(role) {
                        Ok(Some((
                            AuthInfo::user(
                                user.name.clone(), 
                                role
                            ),
                            None
                        )))
                    } else {
                    Err(ApiAuthError::ApiInsufficientRights(
                        format!("Role mapping for system user '{}' not found", 
                            user.name)
                    ))
                    }
                } else {
                    Err(ApiAuthError::ApiInvalidCredentials(
                        format!("Unauthorised system user '{}'", user.name)
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
}

