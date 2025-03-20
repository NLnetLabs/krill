use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::engine::Engine as _;
use log::{debug, trace, warn};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use crate::api::admin::Token;
use crate::commons::KrillResult;
use crate::commons::error::{ApiAuthError, Error};
use crate::daemon::auth::crypt;
use crate::daemon::auth::crypt::{CryptState, NonceState};


const MAX_CACHE_SECS: u64 = 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientSession<S> {
    pub start_time: u64,
    pub expires_in: Option<Duration>,
    pub user_id: Arc<str>,
    pub secrets: S,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Active,
    NeedsRefresh,
    Expired,
}

impl<S: Clone> Clone for ClientSession<S> {
    fn clone(&self) -> Self {
        Self {
            start_time: self.start_time,
            expires_in: self.expires_in,
            user_id: self.user_id.clone(),
            secrets: self.secrets.clone(),
        }
    }
}

impl<S> ClientSession<S> {
    pub fn status(&self) -> SessionStatus {
        if let Some(expires_in) = &self.expires_in {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(now) => {
                    let cur_age_secs = now.as_secs() - self.start_time;
                    let max_age_secs = expires_in.as_secs();

                    let status = if cur_age_secs > max_age_secs {
                        SessionStatus::Expired
                    } else if cur_age_secs
                        > (max_age_secs.checked_div(2).unwrap())
                    {
                        SessionStatus::NeedsRefresh
                    } else {
                        SessionStatus::Active
                    };

                    trace!(
                        "Login session status check: user_id={}, status={:?}, max age={} secs, cur age={} secs",
                        &self.user_id,
                        &status,
                        max_age_secs,
                        cur_age_secs
                    );

                    return status;
                }
                Err(err) => {
                    warn!(
                        "Login session status check: unable to determine the current time: {}",
                        err
                    );
                }
            }
        }

        SessionStatus::Active
    }
}

struct CachedSession<S> {
    pub evict_after: u64,
    pub session: ClientSession<S>,
}

pub type EncryptFn = fn(&[u8], &[u8], &NonceState) -> KrillResult<Vec<u8>>;
pub type DecryptFn = fn(&[u8], &[u8]) -> Result<Vec<u8>, ApiAuthError>;

/// A short term cache to reduce the impact of session token decryption and
/// deserialization (e.g. for multiple requests in a short space of time by
/// the Lagosta UI client) while keeping potentially sensitive data in-memory
/// for as short as possible. This cache is NOT responsible for enforcing
/// token expiration, that is handled separately by the AuthProvider.
pub struct LoginSessionCache<S> {
    cache: RwLock<HashMap<Token, CachedSession<S>>>,
    encrypt_fn: EncryptFn,
    decrypt_fn: DecryptFn,
    ttl_secs: u64,
}

impl<S> Default for LoginSessionCache<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> LoginSessionCache<S> {
    pub fn new() -> Self {
        LoginSessionCache {
            cache: RwLock::new(HashMap::new()),
            encrypt_fn: crypt::encrypt,
            decrypt_fn: crypt::decrypt,
            ttl_secs: MAX_CACHE_SECS,
        }
    }

    fn time_now_secs_since_epoch() -> KrillResult<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                Error::Custom(format!(
                    "Unable to determine the current time: {}",
                    err
                ))
            })?
            .as_secs())
    }

    fn lookup_session(&self, token: &Token) -> Option<ClientSession<S>>
    where S: Clone {
        match self.cache.read() {
            Ok(readable_cache) => {
                if let Some(cache_item) = readable_cache.get(token) {
                    return Some(cache_item.session.clone());
                }
            }
            Err(err) => warn!("Unexpected session cache miss: {}", err),
        }

        None
    }

    fn cache_session(&self, token: &Token, session: ClientSession<S>) {
        match self.cache.write() {
            Ok(mut writeable_cache) => {
                match Self::time_now_secs_since_epoch() {
                    Ok(now) => {
                        writeable_cache.insert(
                            token.clone(),
                            CachedSession {
                                evict_after: now + self.ttl_secs,
                                session,
                            },
                        );
                    }
                    Err(err) => warn!(
                        "Unable to cache decrypted session token: {}",
                        err
                    ),
                }
            }
            Err(err) => {
                warn!("Unable to cache decrypted session token: {}", err)
            }
        }
    }

    pub fn encode(
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
                    "Error while serializing session data: {}",
                    err
                ))
            })?;
        let unencrypted_bytes = session_json_str.as_bytes();

        let encrypted_bytes = (self.encrypt_fn)(
            &crypt_state.key,
            unencrypted_bytes,
            &crypt_state.nonce,
        )?;
        let token = Token::from(BASE64_ENGINE.encode(encrypted_bytes));

        self.cache_session(&token, session);
        Ok(token)
    }

    pub fn decode(
        &self,
        token: Token,
        key: &CryptState,
        add_to_cache: bool,
    ) -> Result<ClientSession<S>, ApiAuthError>
    where S: Clone + DeserializeOwned {
        if let Some(session) = self.lookup_session(&token) {
            trace!("Session cache hit for session id {}", &session.user_id);
            return Ok(session);
        } else {
            trace!("Session cache miss, deserializing...");
        }

        let bytes = BASE64_ENGINE.decode(token.as_ref().as_bytes()).map_err(
            |err| {
                debug!("Invalid bearer token: cannot decode: {}", err);
                ApiAuthError::ApiInvalidCredentials(
                    "Invalid bearer token".to_string(),
                )
            },
        )?;

        let unencrypted_bytes = (self.decrypt_fn)(&key.key, &bytes)?;

        let session =
            serde_json::from_slice::<ClientSession<S>>(&unencrypted_bytes)
                .map_err(|err| {
                    debug!(
                        "Invalid bearer token: cannot deserialize: {}",
                        err
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
            self.cache_session(&token, session.clone());
        }

        Ok(session)
    }

    pub fn remove(&self, token: &Token) {
        match self.cache.write() {
            Ok(mut writeable_cache) => {
                writeable_cache.remove(token);
            }
            Err(err) => warn!("Unable to purge cached session: {}", err),
        }
    }

    pub fn size(&self) -> usize {
        match self.cache.read() {
            Ok(readable_cache) => readable_cache.len(),
            Err(err) => {
                warn!("Unable to query session cache size: {}", err);
                0
            }
        }
    }

    pub fn sweep(&self) -> KrillResult<()> {
        let mut cache = self.cache.write().map_err(|err| {
            Error::Custom(format!("Unable to purge session cache: {}", err))
        })?;

        let size_before = cache.len();

        // Only retain cache items that have been cached for less than the
        // maximum time allowed.
        let now = Self::time_now_secs_since_epoch()?;
        cache.retain(|_, v| v.evict_after > now);

        let size_after = cache.len();

        if size_after != size_before {
            debug!(
                "Login session cache purge: size before={}, size after={}",
                size_before, size_after
            );
        }

        Ok(())
    }
}


mod tests {
    #[test]
    fn basic_login_session_cache_test() {
        use super::*;

        let key_bytes: [u8; 32] = [0; 32];
        let key: CryptState = CryptState::from_key_bytes(key_bytes).unwrap();

        fn one_attr_map(k: &str, v: &str) -> HashMap<String, String> {
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert(k.into(), v.into());
            m
        }

        // Create a new cache whose items are elligible for eviction after one
        // second and which does no actual encryption or decryption.
        let mut cache = LoginSessionCache::new();
        cache.ttl_secs = 1;
        cache.encrypt_fn = |_, v, _| Ok(v.to_vec());
        cache.decrypt_fn = |_, v| Ok(v.to_vec());
        let cache = cache;

        // Add an item to the cache and verify that the cache now has 1 item
        let item1_token = cache
            .encode("some id".into(), HashMap::new(), &key, None)
            .unwrap();
        assert_eq!(cache.size(), 1);

        let item1 = cache.decode(item1_token, &key, true).unwrap();
        assert_eq!(item1.user_id.as_ref(), "some id");
        assert_eq!(item1.expires_in, None);
        assert_eq!(item1.secrets, HashMap::new());

        // Wait until after the cached item should have expired but as the
        // cache has not yet been swept the item should still be in
        // the cache
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(cache.size(), 1);

        // Add another item to the cache
        let some_secrets = one_attr_map("some secret key", "some secret val");
        let item2_token = cache
            .encode(
                "other id".into(),
                some_secrets,
                &key,
                Some(Duration::from_secs(10)),
            )
            .unwrap();
        assert_eq!(cache.size(), 2);

        // Sweep the cache and confirm that the expired cache item has been
        // removed but the newest cache item remains.
        cache.sweep().unwrap();
        assert_eq!(cache.size(), 1);

        // Wait until after the remaining cached item should have expired but
        // as the cache has not yet been swept the item should still
        // be present.
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(cache.size(), 1);

        let item2 = cache.decode(item2_token, &key, true).unwrap();
        assert_eq!(item2.user_id.as_ref(), "other id");
        assert_eq!(item2.expires_in, Some(Duration::from_secs(10)));
        assert_eq!(
            item2.secrets,
            one_attr_map("some secret key", "some secret val")
        );

        // Sweep the cache and confirm that cache is now empty.
        cache.sweep().unwrap();
        assert_eq!(cache.size(), 0);
    }
}
