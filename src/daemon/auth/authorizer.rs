//! Authorization for the API

use std::sync::Arc;
use rpki::ca::idexchange::MyHandle;
use serde::Serialize;
use crate::commons::KrillResult;
use crate::commons::actor::Actor;
use crate::commons::api::Token;
use crate::commons::error::ApiAuthError;
use crate::daemon::config::{AuthType, Config};
use crate::daemon::http::{HttpResponse, HyperRequest};
use super::{Permission, Role};
use super::providers::admin_token;
#[cfg(feature = "multi-user")]
use super::providers::{config_file, openid_connect};


//------------ AuthProvider --------------------------------------------------

/// An AuthProvider authenticates and authorizes a given token.
///
/// An AuthProvider is expected to configure itself using the global Krill
/// from configuration. This avoids propagation of potentially many provider
/// specific configuration values from the calling code to the provider
/// implementation.
///
/// Each AuthProvider is responsible for answering questions related to:
///
///  * authentication - who are you and is it really you?
///  * authorization  - do you have the right to do the thing you want to do?
///  * discovery      - as an interactive client where should I send my users
///    to login and logout?
///  * introspection  - who is the currently "logged in" user?
///
/// This type is a wrapper around the available backend specific auth
/// providers that can be found in the [super::providers] module.
enum AuthProvider {
    Token(admin_token::AuthProvider),

    #[cfg(feature = "multi-user")]
    ConfigFile(config_file::AuthProvider),

    #[cfg(feature = "multi-user")]
    OpenIdConnect(openid_connect::AuthProvider),
}

impl From<admin_token::AuthProvider> for AuthProvider {
    fn from(provider: admin_token::AuthProvider) -> Self {
        AuthProvider::Token(provider)
    }
}

#[cfg(feature = "multi-user")]
impl From<config_file::AuthProvider> for AuthProvider {
    fn from(provider: config_file::AuthProvider) -> Self {
        AuthProvider::ConfigFile(provider)
    }
}

#[cfg(feature = "multi-user")]
impl From<openid_connect::AuthProvider> for AuthProvider {
    fn from(provider: openid_connect::AuthProvider) -> Self {
        AuthProvider::OpenIdConnect(provider)
    }
}

impl AuthProvider {
    /// Authenticate a user from information included in an HTTP request.
    ///
    /// Returns `Ok(None)` to indicate that no authentication information
    /// was present in the request and the request should thus be treated
    /// as not anonymous.
    ///
    /// If authentication succeeded, returns the auth info. If it failed,
    /// it either returns an auth info created via [`AuthInfo::error`] or
    /// just a plain error which the caller needs to convert.
    pub async fn authenticate(
        &self,
        request: &HyperRequest,
    ) -> Result<Option<AuthInfo>, ApiAuthError> {
        match &self {
            AuthProvider::Token(provider) => provider.authenticate(request),
            #[cfg(feature = "multi-user")]
            AuthProvider::ConfigFile(provider) => {
                provider.authenticate(request)
            }
            #[cfg(feature = "multi-user")]
            AuthProvider::OpenIdConnect(provider) => {
                provider.authenticate(request).await
            }
        }
    }

    /// Returns an HTTP text response with the login URL.
    pub async fn get_login_url(&self) -> KrillResult<HttpResponse> {
        match &self {
            AuthProvider::Token(provider) => provider.get_login_url(),
            #[cfg(feature = "multi-user")]
            AuthProvider::ConfigFile(provider) => provider.get_login_url(),
            #[cfg(feature = "multi-user")]
            AuthProvider::OpenIdConnect(provider) => {
                provider.get_login_url().await
            }
        }
    }

    /// Establishes a client session from credentials in an HTTP request.
    pub async fn login(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<LoggedInUser> {
        match &self {
            AuthProvider::Token(provider) => provider.login(request),
            #[cfg(feature = "multi-user")]
            AuthProvider::ConfigFile(provider) => provider.login(request),
            #[cfg(feature = "multi-user")]
            AuthProvider::OpenIdConnect(provider) => {
                provider.login(request).await
            }
        }
    }

    /// Returns an HTTP text response with the logout URL.
    pub async fn logout(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<HttpResponse> {
        match &self {
            AuthProvider::Token(provider) => provider.logout(request),
            #[cfg(feature = "multi-user")]
            AuthProvider::ConfigFile(provider) => provider.logout(request),
            #[cfg(feature = "multi-user")]
            AuthProvider::OpenIdConnect(provider) => {
                provider.logout(request).await
            }
        }
    }

    /// Sweeps out client session information.
    ///
    /// This method should be called regularly to remove expired sessions
    /// from the cache.
    pub fn sweep(&self) -> KrillResult<()> {
        match self {
            AuthProvider::Token(_) => Ok(()),
            #[cfg(feature = "multi-user")]
            AuthProvider::ConfigFile(provider) => provider.sweep(),
            #[cfg(feature = "multi-user")]
            AuthProvider::OpenIdConnect(provider) => provider.sweep(),
        }
    }

    /// Returns the size of the login session cache.
    pub fn login_session_cache_size(&self) -> usize {
        match self {
            AuthProvider::Token(_) => 0,
            #[cfg(feature = "multi-user")]
            AuthProvider::ConfigFile(provider) => provider.cache_size(),
            #[cfg(feature = "multi-user")]
            AuthProvider::OpenIdConnect(provider) => provider.cache_size(),
        }
    }
}


//------------ Authorizer ----------------------------------------------------

/// Checks authorizations when the API is accessed.
pub struct Authorizer {
    /// The auth provider configured by the user.
    primary_provider: AuthProvider,

    /// A fallback token auth provider when it isn’t the primary provider.
    ///
    /// This is necessary to support the command line client which only
    /// supports admin token authentication.
    legacy_provider: Option<admin_token::AuthProvider>,
}

impl Authorizer {
    /// Creates an instance of the Authorizer.
    ///
    /// The authorizer will be created according to information provided via
    /// `config`.
    pub fn new(
        config: Arc<Config>,
    ) -> KrillResult<Self> {
        let (primary_provider, legacy_provider) = match config.auth_type {
            AuthType::AdminToken => {
                (admin_token::AuthProvider::new(config).into(), None)
            }
            #[cfg(feature = "multi-user")]
            AuthType::ConfigFile => {
                (
                    config_file::AuthProvider::new(&config)?.into(),
                    Some(admin_token::AuthProvider::new(config))
                )
            }
            #[cfg(feature = "multi-user")]
            AuthType::OpenIDConnect => {
                (
                    openid_connect::AuthProvider::new(config.clone())?.into(),
                    Some(admin_token::AuthProvider::new(config))
                )
            }
        };

        Ok(Authorizer {
            primary_provider,
            legacy_provider,
        })
    }

    /// Authenticates an HTTP request.
    ///
    /// The method will always return authentication information.
    ///
    /// If there was no authentiation information in the request, the returned
    /// auth info will indicate an anonymous user which will fail all
    /// permission checks with “insufficient permissions.”
    ///
    /// If authentication failed, the returned auth info will also indicate
    /// an anonymous user but it will fail permission checks with appropriate 
    /// error information.
    pub async fn authenticate_request(
        &self, request: &HyperRequest
    ) -> AuthInfo {
        trace!("Determining actor for request {:?}", &request);

        // Try the legacy provider first, if any.
        let authenticate_res = match &self.legacy_provider {
            Some(provider) => provider.authenticate(request),
            None => Ok(None),
        };

        // Try the real provider if we did not already successfully
        // authenticate. This ignores any possible errors thrown by the
        // legacy provider.
        let authenticate_res = match authenticate_res {
            Ok(Some(res)) => Ok(Some(res)),
            _ => self.primary_provider.authenticate(request).await,
        };

        // Create an actor based on the authentication result
        let res = match authenticate_res {
            // authentication success
            Ok(Some(res)) => res,

            // authentication failure
            Ok(None) => AuthInfo::anonymous(),

            // error during authentication
            Err(err) => AuthInfo::error(err),
        };

        trace!("Actor determination result: {:?}", res);

        res
    }

    /// Returns an HTTP text response with the login URL.
    pub async fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.primary_provider.get_login_url().await
    }

    /// Establishes a client session from credentials in an HTTP request.
    pub async fn login(
        &self, request: &HyperRequest
    ) -> KrillResult<LoggedInUser> {
        let user = self.primary_provider.login(request).await?;

        if log_enabled!(log::Level::Trace) {
            trace!("User logged in: {:?}", &user);
        } else {
            info!("User logged in: {}", &user.id);
        }

        Ok(user)
    }

    /// Returns an HTTP text response with the logout URL.
    pub async fn logout(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<HttpResponse> {
        self.primary_provider.logout(request).await
    }

    /// Sweeps out session information.
    ///
    /// This method should be called regularly to remove expired sessions
    /// from the cache.
    pub fn sweep(&self) -> KrillResult<()> {
        self.primary_provider.sweep()
    }

    /// Returns the size of the login session cache.
    pub fn login_session_cache_size(&self) -> usize {
        self.primary_provider.login_session_cache_size()
    }
}


//------------ LoggedInUser --------------------------------------------------

/// Information to be returned to the caller after login.
///
/// This may be serialized into a JSON response.
#[derive(Serialize, Debug)]
pub struct LoggedInUser {
    /// The API token to use in subsequent calls.
    pub token: Token,

    /// The user ID.
    //  XXX Swith to using Arc<str>. May require Serialize shenanigans.
    pub id: String,
}


//------------ AuthInfo ------------------------------------------------------

/// Information about the result of trying to authenticate a request.
#[derive(Clone, Debug)]
pub struct AuthInfo {
    /// The actor for the authenticated user.
    actor: Actor,

    /// Optional updated bearer token.
    new_token: Option<Token>,

    /// Access permissions.
    ///
    /// This is either a role which we consult to determine access
    /// permissions or an authentication error to return instead.
    permissions: Result<Arc<Role>, ApiAuthError>,
}

impl AuthInfo {
    /// Creates auth info for the given user ID and role.
    pub fn user(
        user_id: impl Into<Arc<str>>,
        role: Arc<Role>,
    ) -> Self {
        Self {
            actor: Actor::user(user_id),
            new_token: None,
            permissions: Ok(role),
        }
    }

    /// Creates auth info for the testbed actor.
    pub fn testbed() -> Self {
        Self::user("testbed", Role::testbed().into())
    }

    /// Creates auth info for the anonymous actor.
    ///
    /// This actor fails all permission checks with insufficient permissions.
    fn anonymous() -> Self {
        Self {
            actor: Actor::anonymous(),
            new_token: None,
            permissions: Ok(Role::anonymous().into()),
        }
    }

    /// Creates auth info for an authentication failure.
    fn error(err: ApiAuthError) -> Self {
        Self {
            actor: Actor::anonymous(),
            new_token: None,
            permissions: Err(err)
        }
    }

    /// Sets the updated bearer token.
    ///
    /// If set, this new token needs to be included in an HTTP response.
    pub fn set_new_token(&mut self, new_token: Token) {
        self.new_token = Some(new_token);
    }

    /// Takes out an updated bearer token if presnet
    pub fn take_new_token(&mut self) -> Option<Token> {
        self.new_token.take()
    }

    /// Returns a reference to the actor.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Checks permissions for an operation.
    ///
    /// Returns an authentication error if either the request was not
    /// authenticated or it was but the authenticated user does not have
    /// sufficient permissions.
    pub fn check_permission(
        &self,
        permission: Permission,
        resource: Option<&MyHandle>
    ) -> Result<(), ApiAuthError> {
        if self.permissions.as_ref().map_err(Clone::clone)?
            .is_allowed(permission, resource)
        {
            Ok(())
        }
        else {
            Err(ApiAuthError::insufficient_rights(
                &self.actor, permission, resource
            ))
        }
    }
}

