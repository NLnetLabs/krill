//! Authorization for the API

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::commons::actor::{Actor, ActorDef};
use crate::commons::api::Token;
use crate::commons::error::Error;
use crate::commons::KrillResult;
use crate::constants::ACTOR_DEF_ANON;
use crate::daemon::auth::policy::AuthPolicy;
use crate::daemon::auth::providers::MasterTokenAuthProvider;
use crate::daemon::config::Config;
use crate::daemon::http::HttpResponse;

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

    fn get_actor_def(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<Option<ActorDef>>;
    fn get_login_url(&self) -> KrillResult<HttpResponse>;
    fn login(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<LoggedInUser>;
    fn logout(&self, request: &hyper::Request<hyper::Body>) -> KrillResult<HttpResponse>;
}

/// This type is responsible for checking authorizations when the API is
/// accessed.
pub struct Authorizer {
    primary_provider: Box<dyn AuthProvider>,
    fallback_provider: Option<MasterTokenAuthProvider>,
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
    /// As krillc only supports [MasterTokenAuthProvider] based authentication, if
    /// `P` an instance of some other provider, an instance of
    /// [MasterTokenAuthProvider] will also be created. This will be used as a
    /// fallback when Lagosta is configured to use some other [AuthProvider].
    pub fn new<P>(config: Arc<Config>, provider: P) -> KrillResult<Self>
    where
        P: AuthProvider + Any,
    {
        let value_any = &provider as &dyn Any;
        let fallback_provider = match value_any.downcast_ref::<MasterTokenAuthProvider>() {
            Some(_) => None,
            None => Some(MasterTokenAuthProvider::new(config.clone())),
        };

        #[cfg(feature = "multi-user")]
        let private_attributes = config.auth_private_attributes.clone();
        #[cfg(not(feature = "multi-user"))]
        let private_attributes = vec!["role".to_string()];

        Ok(Authorizer {
            primary_provider: Box::new(provider),
            fallback_provider,
            policy: AuthPolicy::new(config)?,
            private_attributes,
        })
    }

    pub fn actor_from_request(&self, request: &hyper::Request<hyper::Body>) -> Actor {
        trace!("Determining actor for request {:?}", &request);
        trace!("Trying primary provider");
        let actor_def_result = self
            .primary_provider
            .get_actor_def(request)
            .map(|res| {
                trace!("Primary provider returned an actor? {}", res.is_some());
                res
            })
            .map_err(|err| {
                trace!("Primary provider returned an error: {}", &err);
                err
            })
            .and_then(|res| match (res, self.fallback_provider.as_ref()) {
                (Some(actor_def), _) => {
                    // successful login, use the found actor definition
                    Ok(Some(actor_def))
                }
                (None, Some(provider)) => {
                    // the given credentials were of the wrong type for the
                    // primary provider, try the fallback provider instead
                    trace!("Trying secondary provider");
                    provider
                        .get_actor_def(request)
                        .map(|res| {
                            trace!("Fallback provider returned an actor? {}", res.is_some());
                            res
                        })
                        .map_err(|err| {
                            trace!("Fallback provider returned an error: {}", &err);
                            err
                        })
                }
                (None, None) => {
                    // the given credentials were of the wrong type for the
                    // primary provider and there is no fallback provider:
                    // permission denied
                    Err(Error::ApiInvalidCredentials(
                        "Invalid or missing credentials".to_string(),
                    ))
                }
            });

        let res = match actor_def_result {
            Ok(Some(actor_def)) => self.actor_from_def(&actor_def),
            Ok(None) => self.actor_from_def(ACTOR_DEF_ANON),
            Err(err) => self.actor_from_def(&Actor::anonymous().with_auth_error(err.to_string())),
        };

        trace!("Actor determination result: {:?}", &res);

        res
    }

    pub fn actor_from_def(&self, def: &ActorDef) -> Actor {
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
        self.primary_provider.login(request).map(|user| {
            let visible_attributes = user
                .attributes
                .clone()
                .into_iter()
                .filter(|(k, _)| !self.private_attributes.contains(k))
                .collect::<HashMap<_, _>>();

            let user = LoggedInUser {
                token: user.token,
                id: user.id,
                attributes: visible_attributes,
            };

            if log_enabled!(log::Level::Trace) {
                trace!("User logged in: {:?}", &user);
            } else {
                info!("User logged in: {}", &user.id);
            }

            user
        })
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

#[derive(Clone)]
pub enum Auth {
    Bearer(Token),
    AuthorizationCode(Token, String, String),
    IdAndPasswordHash(String, Token),
}

impl Auth {
    pub fn bearer(token: Token) -> Self {
        Auth::Bearer(token)
    }
    pub fn authorization_code(code: Token, state: String, nonce: String) -> Self {
        Auth::AuthorizationCode(code, state, nonce)
    }

    pub fn id_and_password_hash(id: String, password_hash: Token) -> Self {
        Auth::IdAndPasswordHash(id, password_hash)
    }
}
