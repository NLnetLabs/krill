//! Authorization for the API

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::commons::actor::{Actor, ActorDef};
use crate::commons::error::Error;
use crate::commons::KrillResult;
use crate::constants::{ACTOR_DEF_ANON, NO_RESOURCE};
use crate::daemon::auth::policy::AuthPolicy;
use crate::daemon::auth::providers::AdminTokenAuthProvider;
use crate::daemon::config::Config;
use crate::daemon::http::HttpResponse;
use crate::{commons::api::Token, daemon::auth::common::permissions::Permission};

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
    fn get_bearer_token(&self, request: &hyper::Request<hyper::Body>) -> Option<Token> {
        if let Some(header) = request.headers().get("Authorization") {
            if let Ok(header) = header.to_str() {
                if header.len() > 6 {
                    let (bearer, token) = header.split_at(6);
                    let bearer = bearer.trim();

                    if "Bearer" == bearer {
                        return Some(Token::from(token.trim()));
                    }
                }
            }
        }

        None
    }

    fn authenticate(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>>;
    fn get_login_url(&self) -> KrillResult<HttpResponse>;
    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser>;
    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse>;
}

/// This type is responsible for checking authorizations when the API is
/// accessed.
pub struct Authorizer {
    primary_provider: Box<dyn AuthProvider>,
    legacy_provider: Option<AdminTokenAuthProvider>,
    policy: AuthPolicy,
    private_attributes: Vec<String>,
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
    /// As krillc only supports [AdminTokenAuthProvider] based authentication, if
    /// `P` an instance of some other provider, an instance of
    /// [AdminTokenAuthProvider] will also be created. This will be used as a
    /// fallback when Lagosta is configured to use some other [AuthProvider].
    pub fn new<P>(config: Arc<Config>, provider: P) -> KrillResult<Self>
    where
        P: AuthProvider + Any,
    {
        let value_any = &provider as &dyn Any;
        let is_admin_token_provider = value_any.downcast_ref::<AdminTokenAuthProvider>().is_some();

        let legacy_provider = if is_admin_token_provider {
            // the configured provider is the admin token provider so no
            // admin token provider is needed for backward compatibility
            None
        } else {
            // the configured provider is not the admin token provider so we
            // also need an instance of the admin token provider in order to
            // provider backward compatibility for krillc and other API clients
            // that only understand the original, legacy, admin token based
            // authentication.
            Some(AdminTokenAuthProvider::new(config.clone()))
        };

        #[cfg(feature = "multi-user")]
        let private_attributes = config.auth_private_attributes.clone();
        #[cfg(not(feature = "multi-user"))]
        let private_attributes = vec!["role".to_string()];

        Ok(Authorizer {
            primary_provider: Box::new(provider),
            legacy_provider,
            policy: AuthPolicy::new(config)?,
            private_attributes,
        })
    }

    pub fn actor_from_request(&self, request: &hyper::Request<hyper::Body>) -> Actor {
        trace!("Determining actor for request {:?}", &request);

        // Try the legacy provider first, if any
        let mut authenticate_res = match &self.legacy_provider {
            Some(provider) => provider.authenticate(request),
            None => Ok(None),
        };

        // Try the real provider if we did not already successfully authenticate
        authenticate_res = match authenticate_res {
            Ok(Some(res)) => Ok(Some(res)),
            _ => self.primary_provider.authenticate(request),
        };

        // Create an actor based on the authentication result
        let actor = match authenticate_res {
            // authentication success
            Ok(Some(actor_def)) => self.actor_from_def(actor_def),

            // authentication failure
            Ok(None) => self.actor_from_def(ACTOR_DEF_ANON),

            // error during authentication
            Err(err) => {
                // reveives a commons::error::Error, but we need an ApiAuthError
                self.actor_from_def(ACTOR_DEF_ANON.with_auth_error(err))
            }
        };

        trace!("Actor determination result: {:?}", &actor);

        actor
    }

    pub fn actor_from_def(&self, def: ActorDef) -> Actor {
        Actor::new(def, self.policy.clone())
    }

    /// Return the URL at which an end-user should be directed to login with the
    /// configured provider.
    pub fn get_login_url(&self) -> KrillResult<HttpResponse> {
        self.primary_provider.get_login_url()
    }

    /// Submit credentials directly to the configured provider to establish a
    /// login session, if supported by the configured provider.
    pub fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser> {
        let user = self.primary_provider.login(request)?;

        // The user has passed authentication, but may still not be
        // authorized to login as that requires a check against the policy
        // which cannot be done by the AuthProvider. Check that now.
        let actor_def = ActorDef::user(user.id.clone(), user.attributes.clone(), None);
        let actor = self.actor_from_def(actor_def);
        if !actor.is_allowed(Permission::LOGIN, NO_RESOURCE)? {
            let reason = format!("Login denied for user '{}': User is not permitted to 'LOGIN'", user.id);
            warn!("{}", reason);
            return Err(Error::ApiInsufficientRights(reason));
        }

        // Exclude private attributes before passing them to Lagosta to be
        // shown in the web UI.
        let visible_attributes = user
            .attributes
            .clone()
            .into_iter()
            .filter(|(k, _)| !self.private_attributes.contains(k))
            .collect::<HashMap<_, _>>();

        let filtered_user = LoggedInUser {
            token: user.token,
            id: user.id,
            attributes: visible_attributes,
        };

        if log_enabled!(log::Level::Trace) {
            trace!("User logged in: {:?}", &filtered_user);
        } else {
            info!("User logged in: {}", &filtered_user.id);
        }

        Ok(filtered_user)
    }

    /// Return the URL at which an end-user should be directed to logout with
    /// the configured provider.
    pub fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse> {
        self.primary_provider.logout(request)
    }
}

#[derive(Serialize, Debug)]
pub struct LoggedInUser {
    pub token: Token,
    pub id: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub enum Auth {
    Bearer(Token),
    AuthorizationCode {
        code: Token,
        state: String,
        nonce: String,
        csrf_token_hash: String,
    },
    IdAndPasswordHash {
        id: String,
        password_hash: Token,
    },
}

impl Auth {
    pub fn bearer(token: Token) -> Self {
        Auth::Bearer(token)
    }
    pub fn authorization_code(code: Token, state: String, nonce: String, csrf_token_hash: String) -> Self {
        Auth::AuthorizationCode {
            code,
            state,
            nonce,
            csrf_token_hash,
        }
    }

    pub fn id_and_password_hash(id: String, password_hash: Token) -> Self {
        Auth::IdAndPasswordHash { id, password_hash }
    }
}
