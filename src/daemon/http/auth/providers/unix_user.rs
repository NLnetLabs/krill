//! Auth provider using unix user matching.

use std::collections::HashMap;
use std::sync::Arc;
use log::{log_enabled, trace};
use crate::api::admin::Token;
use crate::commons::{Error, KrillResult};
use crate::commons::error::ApiAuthError;
use crate::config::Config;
use crate::daemon::http::auth::{AuthInfo, Role};
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
    unix_users: HashMap<String, Arc<Role>>,
}

impl AuthProvider {
    /// Creates a new unix user auth provider from the given config.
    pub fn new(config: Arc<Config>) -> KrillResult<Self> {
        let mut unix_users  = HashMap::new();
        for (k, v) in config.unix_users().iter() {
            if let Some(role) = config.auth_roles.get(v) {
                unix_users.insert(k.clone(), role);
            } else {
                return Err(Error::ConfigError(
                    format!("Missing role mapping for {}!", v)
                ));
            }
        }
        Ok(AuthProvider {
            unix_users,
        })
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
                    Ok(Some((
                        AuthInfo::user(
                            user.name.clone(), 
                            role.clone()
                        ),
                        None
                    )))
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

