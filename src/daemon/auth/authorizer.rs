//! Authorization for the API

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use rpki::ca::idexchange::{InvalidHandle, MyHandle};
use serde::{Deserialize, Serialize};
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
/// [`CONFIG`] object. This avoids propagation of potentially many provider
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
pub enum AuthProvider {
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
    pub async fn authenticate(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<Option<AuthInfo>> {
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

    /// Sweeps out session information.
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

/// This type is responsible for checking authorizations when the API is
/// accessed.
pub struct Authorizer {
    primary_provider: AuthProvider,
    legacy_provider: Option<admin_token::AuthProvider>,
}

impl Authorizer {
    /// Creates an instance of the Authorizer.
    ///
    /// The given [AuthProvider] will be used to verify API access requests,
    /// to handle direct login attempts (if supported) and to determine
    /// the URLs to pass on to clients (e.g. Lagosta) that want to know
    /// where to direct end-users to login and logout.
    ///
    /// # Legacy support for krillc
    ///
    /// As krillc only supports [admin_token::AuthProvider]
    /// based authentication, if `P` an instance of some other provider, an
    /// instance of [admin_token::AuthProvider] will also be created. This
    /// will be used as a fallback when Lagosta is configured to use some
    /// other authentication provider.
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
    pub async fn authenticate_request(
        &self, request: &HyperRequest
    ) -> AuthInfo {
        trace!("Determining actor for request {:?}", &request);

        // Try the legacy provider first, if any
        let authenticate_res = match &self.legacy_provider {
            Some(provider) => provider.authenticate(request),
            None => Ok(None),
        };

        // Try the real provider if we did not already successfully
        // authenticate
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

    /// Return the URL at which an end-user should be directed to login with
    /// the configured provider.
    pub async fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.primary_provider.get_login_url().await
    }

    /// Establish an authenticated session from credentials in an HTTP request.
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

    /// Return the URL at which an end-user should be directed to logout with
    /// the configured provider.
    pub async fn logout(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<HttpResponse> {
        self.primary_provider.logout(request).await
    }

    /// Sweeps out session information.
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

    /// Optional authentication information to be included in a response.
    new_auth: Option<Auth>,

    /// Access permissions.
    ///
    /// This is either a role which we consult to determine access
    /// permissions or an authentication error to return instead.
    permissions: Result<Arc<Role>, ApiAuthError>,
}

impl AuthInfo {
    pub fn user(
        user_id: impl Into<Arc<str>>,
        role: Arc<Role>,
    ) -> Self {
        Self {
            actor: Actor::user(user_id),
            new_auth: None,
            permissions: Ok(role),
        }
    }

    pub fn testbed() -> Self {
        Self::user("testbed", Role::testbed().into())
    }

    fn anonymous() -> Self {
        Self {
            actor: Actor::anonymous(),
            new_auth: None,
            permissions: Ok(Role::anonymous().into()),
        }
    }

    fn error(err: impl Into<ApiAuthError>) -> Self {
        Self {
            actor: Actor::anonymous(),
            new_auth: None,
            permissions: Err(err.into())
        }
    }

    pub fn set_new_auth(&mut self, new_auth: Auth) {
        self.new_auth = Some(new_auth);
    }

    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    pub fn take_new_auth(&mut self) -> Option<Auth> {
        self.new_auth.take()
    }

    pub fn check_permission(
        &self,
        permission: Permission,
        resource: Option<&Handle>
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


//------------ Auth ----------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Auth {
    Bearer(Token),
    AuthorizationCode {
        code: Token,
        state: String,
        nonce: String,
        csrf_token_hash: String,
    },
    UsernameAndPassword {
        username: String,
        password: String,
    },
}

impl Auth {
    pub fn bearer(token: Token) -> Self {
        Auth::Bearer(token)
    }
    pub fn authorization_code(
        code: Token,
        state: String,
        nonce: String,
        csrf_token_hash: String,
    ) -> Self {
        Auth::AuthorizationCode {
            code,
            state,
            nonce,
            csrf_token_hash,
        }
    }

    pub fn username_and_password_hash(
        username: String,
        password: String,
    ) -> Self {
        Auth::UsernameAndPassword { username, password }
    }
}

//------------ Handle --------------------------------------------------------

/// Handle for Authorization purposes.
// This type is a wrapper so the we can implement the PolarClass trait which
// is required when multi-user is enabled. We always need to pass the handle
// into the authorization macro, even if multi-user is not enabled. So we need
// this type even then.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Handle(MyHandle);

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&MyHandle> for Handle {
    fn from(h: &MyHandle) -> Self {
        Handle(h.clone())
    }
}

impl FromStr for Handle {
    type Err = InvalidHandle;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MyHandle::from_str(s).map(Handle)
    }
}

impl AsRef<MyHandle> for Handle {
    fn as_ref(&self) -> &MyHandle {
        &self.0
    }
}

