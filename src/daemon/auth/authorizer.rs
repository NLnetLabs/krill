//! Authorization for the API

use std::any::Any;

use crate::commons::{actor::Actor, KrillResult};
use crate::commons::api::Token;
use crate::daemon::auth::providers::MasterTokenAuthProvider;
use crate::daemon::auth::Permissions;

//------------ Authorizer ----------------------------------------------------

/// An AuthProvider authenticates and authorizes a given token.
///
/// An AuthProvider is expected to configure itself using the global Krill
/// [`CONFIG`] object. This avoids propagatation of potentially many provider
/// specific configuration values from the calling code to the provider
/// implementation.
/// 
/// Each AuthProvider is responsible for answering questions related to:
/// 
///  * authentication - who are you and is it really you?
///  * authorization  - do you have the right to do the thing you want to do?
///  * discovery      - as an interactive client where should I send my users to
///                     login and logout?
///  * introspection  - who is the currently "logged in" user?
pub trait AuthProvider: Send + Sync {
    fn get_actor(&self, auth: &Auth) -> KrillResult<Option<Actor>>;
    fn is_api_allowed(&self, auth: &Auth, wanted_permissions: Permissions) -> KrillResult<Option<Auth>>;
    fn get_login_url(&self) -> String;
    fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser>;
    fn logout(&self, auth: Option<Auth>) -> String;
}

/// This type is responsible for checking authorizations when the API is
/// accessed.
pub struct Authorizer {
    primary_provider: Box<dyn AuthProvider>,
    fallback_provider: Option<MasterTokenAuthProvider>
}

impl Authorizer {
    /// Creates an instance of the Authorizer.
    ///
    /// The given [AuthProvider] will be used to verify API access requests, to
    /// handle direct login attempts (if supported) and to determine the URLs to
    /// pass on to clients (e.g. Lagosta) that want to know where to direct
    /// end-users to login and logout.
    /// 
    /// # Legacy support for krillc
    /// 
    /// As krillc only supports [MasterTokenAuthProvider] based authentication, if
    /// `P` an instance of some other provider, an instance of
    /// [MasterTokenAuthProvider] will also be created. This will be used as a 
    /// fallback when Lagosta are configured to use some other [AuthProvider]. 
    /// See [`is_api_allowed`] for more information.
    /// 
    /// [`get`]: #method.is_api_allowed
    pub fn new<P>(provider: P) -> Self
    where
        P: AuthProvider + Any
    {
        let value_any = &provider as &dyn Any;
        let fallback_provider = match value_any.downcast_ref::<MasterTokenAuthProvider>() {
            Some(_) => None,
            None    => Some(MasterTokenAuthProvider::new())
        };
        Authorizer {
            primary_provider: Box::new(provider),
            fallback_provider: fallback_provider
        }
    }

    pub fn get_actor(&self, auth: &Auth) -> KrillResult<Option<Actor>> {
        self.primary_provider.get_actor(auth)
            // permission denied, do we have a fallback provider we can try?
            .or_else(|err| match self.fallback_provider.as_ref() {
                Some(provider) => {
                    // yes we do, try checking the credentials against it
                    provider.get_actor(auth)
                },
                None => {
                    // no fallback provider configured, permission denied
                    Err(err)
                }
            })
    }

    /// Return true if the given authentication details are valid, else false.
    /// 
    /// Verifies the given authentication details with the configured provider.
    /// If that fails then, if configured, also attempts to verify the details
    /// details with the fallback provider. See [`new`] for more information.
    /// 
    /// [`new`]: #method.new
    pub fn is_api_allowed(&self, auth: &Auth, wanted_permissions: Permissions) -> KrillResult<Option<Auth>> {
        self.primary_provider.is_api_allowed(auth, wanted_permissions)
            // permission denied, do we have a fallback provider we can try?
            .or_else(|err| match self.fallback_provider.as_ref() {
                Some(provider) => {
                    // yes we do, try checking the credentials against it
                    provider.is_api_allowed(auth, wanted_permissions)
                },
                None => {
                    // no fallback provider configured, permission denied
                    Err(err)
                }
            })
    }

    /// Return the URL at which an end-user should be directed to login with the
    /// configured provider.
    pub fn get_login_url(&self) -> String {
        self.primary_provider.get_login_url()
    }

    /// Submit credentials directly to the configured provider to establish a
    /// login session, if supported by the configured provider.
    pub fn login(&self, auth: &Auth) -> KrillResult<LoggedInUser> {
        self.primary_provider.login(auth)
    }

    /// Return the URL at which an end-user should be directed to logout with
    /// the configured provider.
    pub fn logout(&self, auth: Option<Auth>) -> String {
        self.primary_provider.logout(auth)
    }
}

pub struct LoggedInUser {
    pub token: String,
    pub id: String,
}

pub enum Auth {
    Bearer(Token),
    AuthorizationCode(String, String)
}

impl Auth {
    pub fn bearer(token: Token) -> Self {
        Auth::Bearer(token)
    }
    pub fn authorization_code(code: String, state: String) -> Self {
        Auth::AuthorizationCode(code, state)
    }
}