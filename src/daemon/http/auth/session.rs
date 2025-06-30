//! A cache for login session.

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::engine::Engine as _;
use log::{debug, trace, warn};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use tokio::runtime;
use tokio::sync::RwLock;
use crate::api::admin::Token;
use crate::commons::KrillResult;
use crate::commons::error::{ApiAuthError, Error};
use super::crypt;
use super::crypt::{CryptState, NonceState};


//------------ Constants -----------------------------------------------------

/// The time in seconds an item will remain in the cache.
const MAX_CACHE_SECS: u64 = 30;


//------------ ClientSession -------------------------------------------------

/// The data of a client session.
///
/// This information will be serialized and encrypted and then sent to the
/// client which has to include it in subsequent requests.
///
/// The type argument `S` contains additional data that an authentication
/// provider wishes to include in the session. It needs to be serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientSession<S> {
    pub start_time: u64,
    pub expires_in: Option<Duration>,
    pub user_id: Arc<str>,
    pub secrets: S,
}

impl<S> ClientSession<S> {
    /// Returns the status of the session.
    pub fn status(&self) -> SessionStatus {
        if let Some(expires_in) = &self.expires_in {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(now) => {
                    let cur_age_secs = now.as_secs() - self.start_time;
                    let max_age_secs = expires_in.as_secs();

                    let status = if cur_age_secs > max_age_secs {
                        SessionStatus::Expired
                    }
                    else if cur_age_secs
                        > (max_age_secs.checked_div(2).unwrap())
                    {
                        SessionStatus::NeedsRefresh
                    }
                    else {
                        SessionStatus::Active
                    };

                    trace!(
                        "Login session status check: user_id={}, \
                         status={:?}, max age={} secs, cur age={} secs",
                        &self.user_id, &status, max_age_secs, cur_age_secs
                    );

                    return status;
                }
                Err(err) => {
                    warn!(
                        "Login session status check: unable to determine \
                         the current time: {err}"
                    );
                }
            }
        }

        SessionStatus::Active
    }
}


//------------ SessionStatus -------------------------------------------------

/// The status of a client session.
#[derive(Debug, Eq, PartialEq)]
pub enum SessionStatus {
    /// The session is still active and has not yet expired.
    Active,

    /// The session is still active but needs refresh.
    NeedsRefresh,

    /// The session has expired.
    Expired,
}


//------------ LoginSessionCache ---------------------------------------------

/// A short term cache for login session.
///
/// The main purpose of the cache is to reduce the impact of session token
/// decryption and deserialization (e.g. for multiple requests in a short
/// space of time by the same client) while keeping potentially sensitive
/// data in-memory for as short as possible.
///
/// The cache takes care of encrypting client sessions into session tokens
/// and decrypting them back. It is, however, _not_ responsible for enforcing
/// token expiration – that is handled separately by the authentication
/// provider.
///
/// The cache is swept by an async task that is to be spawned onto a Tokio
/// runtime via the [`spawn_sweep`][Self::spawn_sweep] method.
pub struct LoginSessionCache<S> {
    /// The actual cache.
    cache: Arc<RwLock<HashMap<Token, CachedSession<S>>>>,

    /// The function to encrypt a session into a token.
    encrypt_fn: EncryptFn,

    /// The function to decrypt a token into a session.
    decrypt_fn: DecryptFn,

    /// The time-to-live for cache entries.
    ttl: Duration,
}

impl<S> Default for LoginSessionCache<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> LoginSessionCache<S> {
    /// Creates a new login session cache.
    pub fn new() -> Self {
        LoginSessionCache {
            cache: Arc::new(RwLock::new(HashMap::new())),
            encrypt_fn: crypt::encrypt,
            decrypt_fn: crypt::decrypt,
            ttl: Duration::from_secs(MAX_CACHE_SECS),
        }
    }

    /// Creates a client session, stores it in the cache and returns it.
    ///
    /// Upon success, the method returns the encrypted session token which
    /// can be given to the client as is.
    pub async fn encode(
        &self,
        user_id: Arc<str>,
        secrets: S,
        crypt_state: &CryptState,
        expires_in: Option<Duration>,
    ) -> KrillResult<Token>
    where S: Debug + Serialize {
        let session = ClientSession {
            start_time: Self::time_now_secs_since_epoch()?,
            expires_in,
            user_id,
            secrets
        };

        debug!("Creating token for session: {:?}", &session);

        let session_json_str =
            serde_json::to_string(&session).map_err(|err| {
                Error::Custom(format!(
                    "Error while serializing session data: {err}"
                ))
            })?;
        let unencrypted_bytes = session_json_str.as_bytes();

        let encrypted_bytes = (self.encrypt_fn)(
            &crypt_state.key,
            unencrypted_bytes,
            &crypt_state.nonce,
        )?;
        let token = Token::from(BASE64_ENGINE.encode(encrypted_bytes));

        self.cache_session(&token, session).await;
        Ok(token)
    }

    /// Returns the current number of seconds since the Unix epoch.
    fn time_now_secs_since_epoch() -> KrillResult<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                Error::Custom(format!(
                    "Unable to determine the current time: {err}"
                ))
            })?
            .as_secs())
    }

    /// Stores the given session in the cache.
    async fn cache_session(&self, token: &Token, session: ClientSession<S>) {
        match SystemTime::now().checked_add(self.ttl) {
            Some(evict_after) => {
                self.cache.write().await.insert(
                    token.clone(),
                    CachedSession { evict_after, session },
                );
            }
            None => {
                warn!(
                    "Unable to cache decrypted session token: \
                     eviction time out of system time bounds."
                )
            }
        }
    }

    /// Decodes the given session token into a client session.
    ///
    /// Returns a copy of the client session.
    /// 
    /// If the session is still in the cache, will just copy that, otherwise
    /// will decrypt and deserialize the token.
    ///
    /// If `add_to_cache` is `true`, the session will be added to the cache
    /// again if it had to be decrypted.
    pub async fn decode(
        &self, token: Token, key: &CryptState, add_to_cache: bool,
    ) -> Result<ClientSession<S>, ApiAuthError>
    where S: Clone + DeserializeOwned {
        if let Some(session) = self.lookup_session(&token).await {
            trace!("Session cache hit for session id {}", &session.user_id);
            return Ok(session);
        }
        else {
            trace!("Session cache miss, deserializing...");
        }

        let bytes = BASE64_ENGINE.decode(token.as_ref().as_bytes()).map_err(
            |err| {
                debug!("Invalid bearer token: cannot decode: {err}");
                ApiAuthError::ApiInvalidCredentials(
                    "Invalid bearer token".to_string(),
                )
            },
        )?;

        let unencrypted_bytes = (self.decrypt_fn)(&key.key, &bytes)?;

        let session = serde_json::from_slice::<ClientSession<S>>(
            &unencrypted_bytes
        ).map_err(|err| {
            debug!(
                "Invalid bearer token: cannot deserialize: {err}"
            );
            ApiAuthError::ApiInvalidCredentials(
                "Invalid bearer token".to_string(),
            )
        })?;

        trace!(
            "Session cache miss, deserialized session id {}",
            &session.user_id
        );

        if add_to_cache {
            self.cache_session(&token, session.clone()).await;
        }

        Ok(session)
    }

    /// Looks up the session for the given token in the cache.
    async fn lookup_session(&self, token: &Token) -> Option<ClientSession<S>>
    where S: Clone {
        self.cache.read().await.get(token).map(|item| {
            item.session.clone()
        })
    }

    /// Removes the given token from the cache.
    ///
    /// If the token isn’t in the cache, does nothing.
    pub async fn remove(&self, token: &Token) {
        self.cache.write().await.remove(token);
    }

    /// Returns the current size of the cache.
    pub async fn size(&self) -> usize {
        self.cache.read().await.len()
    }

    /// Spawns a tokio task regularly removing expired entries.
    ///
    /// This task will be spawned onto the provided runtime. It runs every
    /// sixty seconds and removes all cache entries that have been added more
    /// than thirty seconds ago.
    pub fn spawn_sweep(&self, runtime: &runtime::Handle)
    where S: Send + Sync + 'static {
        self.spawn_sweep_with_duration(runtime, Duration::from_secs(60));
    }

    /// Spawns a sweeper task waiting the given duration between sweeps.
    ///
    /// This is here in its own method for speeding up the test below.
    fn spawn_sweep_with_duration(
        &self, runtime: &runtime::Handle, duration: Duration,
    )
    where S: Send + Sync + 'static {
        let cache_weak = Arc::downgrade(&self.cache);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(duration).await;

                let Some(cache) = cache_weak.upgrade() else {
                    // The cache is gone, no reason to stay around.
                    break;
                };

                debug!(
                    "Login session sweep at {}",
                    SystemTime::now().duration_since(
                        SystemTime::UNIX_EPOCH
                    ).map(|x| x.as_secs()).unwrap_or(0),
                );

                let mut cache = cache.write().await;

                let size_before = cache.len();

                // Only retain cache items that have been cached for less
                // than the maximum time allowed.
                let now = SystemTime::now();
                cache.retain(|_, v| v.evict_after > now);

                let size_after = cache.len();

                if size_after != size_before {
                    debug!(
                        "Login session cache purge: \
                         size before={size_before}, size after={size_after}"
                    );
                }
            }
        });
    }
}


//------------ CachedSession -------------------------------------------------

/// A client session as stored in the session cache.
struct CachedSession<S> {
    /// The time when the session should be evicted.
    evict_after: SystemTime,

    /// The actual client session.
    session: ClientSession<S>,
}

//------------ Type Aliases --------------------------------------------------

/// The function to encrypt a session.
type EncryptFn = fn(&[u8], &[u8], &NonceState) -> KrillResult<Vec<u8>>;

/// The function to decrypt a session.
type DecryptFn = fn(&[u8], &[u8]) -> Result<Vec<u8>, ApiAuthError>;


//============ Tests =========================================================

mod tests {
    #[tokio::test]
    async fn basic_login_session_cache_test() {
        use super::*;

        let _  = stderrlog::new().verbosity(99).init();

        let key_bytes: [u8; 32] = [0; 32];
        let key: CryptState = CryptState::from_key_bytes(key_bytes).unwrap();

        fn one_attr_map(k: &str, v: &str) -> HashMap<String, String> {
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert(k.into(), v.into());
            m
        }

        // Create a new cache whose items are elligible for eviction after
        // three seconds and which does no actual encryption or decryption.
        let mut cache = LoginSessionCache::new();
        cache.ttl = Duration::from_secs(5);
        cache.encrypt_fn = |_, v, _| Ok(v.to_vec());
        cache.decrypt_fn = |_, v| Ok(v.to_vec());
        let cache = cache;

        // Start the sweeper to sweep every five seconds.
        cache.spawn_sweep_with_duration(
            &tokio::runtime::Handle::current(),
            Duration::from_secs(5),
        );

        // Second 0: add item to the cache. It should expire at second 3.
        let item1_token = cache.encode(
            "some id".into(), HashMap::new(), &key, None
        ).await.unwrap();

        // Verify that the item is present and correct.
        assert_eq!(cache.size().await, 1);
        let item1 = cache.decode(item1_token, &key, true).await.unwrap();
        assert_eq!(item1.user_id.as_ref(), "some id");
        assert_eq!(item1.expires_in, None);
        assert_eq!(item1.secrets, HashMap::new());

        tokio::time::sleep(Duration::from_secs(4)).await;

        // Second 4: first item has expired but has not been removed from the
        // cache.
        assert_eq!(cache.size().await, 1);

        // Still second 4: add second item. It should expire at second 7.
        let some_secrets = one_attr_map("some secret key", "some secret val");
        let item2_token = cache.encode(
            "other id".into(), some_secrets, &key,
            Some(Duration::from_secs(5)),
        ).await.unwrap();
        assert_eq!(cache.size().await, 2);

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Second 6. The cache was swept so the first item should have gone
        // but the second one should still be here.
        assert_eq!(cache.size().await, 1);

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Second 8. The second item has also expired but not yet been swept
        // out of the cache.
        assert_eq!(cache.size().await, 1);

        let item2 = cache.decode(item2_token, &key, true).await.unwrap();
        assert_eq!(item2.user_id.as_ref(), "other id");
        assert_eq!(item2.expires_in, Some(Duration::from_secs(5)));
        assert_eq!(
            item2.secrets,
            one_attr_map("some secret key", "some secret val")
        );

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Second 11: the cache has been swept again and should be empty.
        assert_eq!(cache.size().await, 0);
    }
}

