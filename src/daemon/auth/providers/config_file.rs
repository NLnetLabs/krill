use std::collections::HashMap;
use std::sync::Arc;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::engine::Engine as _;
use unicode_normalization::UnicodeNormalization;
use crate::commons::KrillResult;
use crate::commons::util::httpclient;
use crate::commons::api::Token;
use crate::commons::error::{ApiAuthError, Error};
use crate::constants::{PW_HASH_LOG_N, PW_HASH_P, PW_HASH_R};
use crate::daemon::auth::{Auth, AuthInfo, LoggedInUser, Permission, RoleMap};
use crate::daemon::auth::common::crypt;
use crate::daemon::auth::common::session::{ClientSession, LoginSessionCache};
use crate::daemon::config::Config;
use crate::daemon::http::{HttpResponse, HyperRequest};


//------------ Constants -----------------------------------------------------

/// The location of the login page in Krill UI.
const UI_LOGIN_ROUTE_PATH: &str = "/login?withId=true";


//------------ ConfigFileAuthProvider ----------------------------------------

pub struct ConfigFileAuthProvider {
    users: HashMap<String, UserDetails>,
    roles: Arc<RoleMap>,
    session_key: crypt::CryptState,
    session_cache: SessionCache,
    fake_password_hash: String,
    fake_salt: String,
}

impl ConfigFileAuthProvider {
    pub fn new(
        config: &Config,
    ) -> KrillResult<Self> {
        let users = config.auth_users.as_ref().ok_or_else(|| {
            Error::ConfigError("Missing [auth_users] config section!".into())
        })?.clone();
        let roles = config.auth_roles.clone();
        let session_key = Self::init_session_key(config)?;

        Ok(Self {
            users,
            roles,
            session_key,
            session_cache: SessionCache::new(),
            fake_password_hash: hex::encode("fake password hash"),
            fake_salt: hex::encode("fake salt"),
        })
    }

    fn init_session_key(config: &Config) -> KrillResult<crypt::CryptState> {
        debug!("Initializing login session encryption key");
        crypt::crypt_init(config)
    }

    /// Parse HTTP Basic Authorization header
    fn get_auth(&self, request: &HyperRequest) -> Option<Auth> {
        let header =
            request.headers().get(hyper::http::header::AUTHORIZATION)?;
        let auth = header.to_str().ok()?.strip_prefix("Basic ")?;
        let auth = BASE64_ENGINE.decode(auth).ok()?;
        let auth = String::from_utf8(auth).ok()?;
        let (username, password) = auth.split_once(':')?;

        Some(Auth::UsernameAndPassword {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    fn auth_from_session(
        &self, session: &Session
    ) -> Result<AuthInfo, ApiAuthError> {
        self.roles.get(&session.secrets.role).map(|role| {
            AuthInfo::user(session.user_id.clone(), role)
        })
    }
}

impl ConfigFileAuthProvider {
    pub fn authenticate(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<Option<AuthInfo>> {
        if log_enabled!(log::Level::Trace) {
            trace!("Attempting to authenticate the request..");
        }

        let res = match httpclient::get_bearer_token(request) {
            Some(token) => {
                // see if we can decode, decrypt and deserialize the users
                // token into a login session structure
                let session = self.session_cache.decode(
                    token,
                    &self.session_key,
                    true,
                )?;

                trace!("user_id={}", session.user_id);

                Ok(Some(self.auth_from_session(&session)?))
            }
            _ => Ok(None),
        };

        if log_enabled!(log::Level::Trace) {
            trace!("Authentication result: {:?}", res);
        }

        res
    }

    pub fn get_login_url(&self) -> KrillResult<HttpResponse> {
        // Direct Lagosta to show the user the Lagosta API token login form
        Ok(HttpResponse::text_no_cache(UI_LOGIN_ROUTE_PATH.into()))
    }

    pub fn login(&self, request: &HyperRequest) -> KrillResult<LoggedInUser> {
        use scrypt::scrypt;

        let (username, password) = match self.get_auth(request) {
            Some(Auth::UsernameAndPassword { username, password }) => {
                (username, password)
            }
            _ => {
                trace!("Missing pr incomplete credentials for login attempt");
                return Err(Error::ApiInvalidCredentials(
                    "Missing credentials".to_string(),
                ))
            }
        };

        // Do NOT bail out if the user is not known because then the
        // unknown user path would return very quickly
        // compared to the known user path and timing differences can aid
        // attackers.
        let (user_password_hash, user_salt) =
            match self.users.get(&username) {
                Some(user) => {
                    (user.password_hash.to_string(), user.salt.clone())
                }
                None => (
                    self.fake_password_hash.clone(),
                    self.fake_salt.clone(),
                ),
            };

        let username = username.trim().nfkc().collect::<String>();
        let password = password.trim().nfkc().collect::<String>();

        // hash twice with two different salts
        // legacy hashing strategy to be compatible with lagosta
        let params = scrypt::Params::new(
            PW_HASH_LOG_N,
            PW_HASH_R,
            PW_HASH_P,
            scrypt::Params::RECOMMENDED_LEN,
        )
        .unwrap();
        let weak_salt = format!("krill-lagosta-{username}");
        let weak_salt = weak_salt.nfkc().collect::<String>();

        let mut interim_hash: [u8; 32] = [0; 32];
        scrypt(
            password.as_bytes(),
            weak_salt.as_bytes(),
            &params,
            &mut interim_hash,
        )
        .unwrap();

        let strong_salt: Vec<u8> = hex::decode(user_salt).unwrap();
        let mut hashed_hash: [u8; 32] = [0; 32];
        scrypt(
            &interim_hash,
            strong_salt.as_slice(),
            &params,
            &mut hashed_hash,
        )
        .unwrap();

        let encoded_hash = hex::encode(hashed_hash);

        // And now finally check the user, so that both known and
        // unknown user code paths do the same work
        // and don't result in an obvious timing difference between
        // the two scenarios which could potentially
        // be used to discover user names.
        if encoded_hash != user_password_hash {
            trace!("Unknown user {}", username);
            return Err(Error::ApiInvalidCredentials(
                "Incorrect credentials".to_string(),
            ))
        }

        let user = match self.users.get(username.as_str()) {
            Some(user) => user,
            None => {
                trace!("Incorrect password for user {}", username);
                return Err(Error::ApiInvalidCredentials(
                    "Incorrect credentials".to_string(),
                ));
            }
        };

        // Check that the user is allowed to log in.
        let role = self.roles.get(&user.role)?;

        if !role.is_allowed(Permission::LOGIN, None) {
            let reason = format!(
                "Login denied for user '{}': \
                 User is not permitted to 'LOGIN'",
                 username,
            );
            warn!("{}", reason);
            return Err(Error::ApiInsufficientRights(reason));
        }

        // All good: create a token and return.
        let api_token = self.session_cache.encode(
            username.clone().into(),
            SessionSecret { role: user.role.clone() },
            &self.session_key,
            None,
        )?;

        Ok(LoggedInUser {
            token: api_token,
            id: username,
        })
    }

    pub fn logout(
        &self,
        request: &HyperRequest,
    ) -> KrillResult<HttpResponse> {
        match httpclient::get_bearer_token(request) {
            Some(token) => {
                self.session_cache.remove(&token);

                if let Ok(Some(info)) = self.authenticate(request) {
                    info!("User logged out: {}", info.actor().name());
                }
            }
            _ => {
                warn!(
                    "Unexpectedly received a logout request \
                    without a session token."
                );
            }
        }

        // Logout is complete, direct Lagosta to show the user the Lagosta
        // index page
        Ok(HttpResponse::text_no_cache("/".into()))
    }

    pub fn sweep(&self) -> KrillResult<()> {
        self.session_cache.sweep()
    }

    pub fn cache_size(&self) -> usize {
        self.session_cache.size()
    }
}


//------------ ConfigAuthUsers -----------------------------------------------

pub type ConfigAuthUsers = HashMap<String, UserDetails>;


//------------ LegacyUserDetails ---------------------------------------------

/// The actual user details type used in the config file.
///
/// Previous versions of Krill used a concept of user-defined attributes. This
/// has now been simplified to just a singled attribute “role.” In order to
/// allow tranistioning from the old world to the new, we allow the role name
/// to be in an “attributes” hash map or its own field. In the former case,
/// we will accept the config file but warn. We will also accept additional
/// attributes but warn about those, too.
///
/// However, the password-related fields are now mandatory since we are not
/// using this configuration for the OpenID Connect provider any more.
///
/// This is all implemented by using the `try_from` Serde container attribute.
#[derive(Clone, Debug, Deserialize)]
struct LegacyUserDetails {
    password_hash: String,
    salt: String,
    role: Option<String>,
    attributes: Option<HashMap<String, String>>,
}


//------------ UserDetails ---------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "LegacyUserDetails")]
pub struct UserDetails {
    password_hash: Token,
    salt: String,
    role: Arc<str>,
}

impl TryFrom<LegacyUserDetails> for UserDetails {
    type Error = String;

    fn try_from(src: LegacyUserDetails) -> Result<Self, Self::Error> {
        let role = if let Some(mut attributes) = src.attributes {
            warn!(
                "The 'attributes' auth_user field is deprecated. \
                Please use the 'role' field directly."
            );
            match attributes.remove("role") {
                Some(role) => role,
                None => {
                    return Err("missing 'role' attribute".into());
                }
            }
        }
        else {
            match src.role {
                Some(role) => role,
                None => {
                    return Err("missing 'role' field".into());
                }
            }
        };
        Ok(Self {
            password_hash: src.password_hash.into(),
            salt: src.salt,
            role: role.into()
        })
    }
}


//------------ SessionSecret et al -------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SessionSecret {
    role: Arc<str>,
}

type SessionCache = LoginSessionCache<SessionSecret>;
type Session = ClientSession<SessionSecret>;

