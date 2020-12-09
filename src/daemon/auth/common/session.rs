use std::{collections::HashMap, sync::RwLock, time::{Duration, SystemTime, UNIX_EPOCH}};

use crate::commons::api::Token;
use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;

use super::crypt;

const TAG_SIZE: usize = 16;
const MAX_CACHE_SECS: u64 = 30;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientSession {
    pub start_time: u64,
    pub expires_in: Option<Duration>,
    pub id: String,
    pub attributes: HashMap<String, String>,
    pub secrets: Vec<String>,
}

struct CachedSession {
    pub evict_after: u64,
    pub session: ClientSession,
}

pub struct LoginSessionCache {
    cache: RwLock<HashMap<Token, CachedSession>>,
}

impl Default for LoginSessionCache {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginSessionCache {
    pub fn new() -> Self {
        LoginSessionCache {
            cache: RwLock::new(HashMap::new())
        }
    }

    fn time_now_secs_since_epoch() -> KrillResult<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| KrillError::Custom(
                format!("Unable to determine the current time: {}", err)))?
            .as_secs())
    }

    fn lookup_session(&self, token: &Token) -> Option<ClientSession> {
        match self.cache.read() {
            Ok(readable_cache) => {
                if let Some(cache_item) = readable_cache.get(&token) {
                    return Some(cache_item.session.clone());
                }
            },
            Err(err) => warn!("Unexpected session cache miss: {}", err)
        }

        None
    }

    fn cache_session(&self, token: &Token, session: &ClientSession) {
        match self.cache.write() {
            Ok(mut writeable_cache) => {
                match Self::time_now_secs_since_epoch() {
                    Ok(now) => {
                        writeable_cache.insert(token.clone(), CachedSession {
                            evict_after: now + MAX_CACHE_SECS,
                            session: session.clone(),
                        });
                    },
                    Err(err) => warn!("Unable to cache decrypted session token: {}", err),
                }
            },
            Err(err) => warn!("Unable to cache decrypted session token: {}", err),
        }
    }

    pub fn encode(&self, id: &str, attributes: &HashMap<String, String>, secrets: &[String], key: &[u8], expires_in: Option<Duration>) -> KrillResult<Token> {
        let session = ClientSession {
            start_time: Self::time_now_secs_since_epoch()?,
            expires_in,
            id: id.to_string(),
            attributes: attributes.clone(),
            secrets: secrets.to_vec(),
        };

        debug!("Creating token for session: {:?}", &session);

        let session_json_str = serde_json::to_string(&session)
            .map_err(|err| KrillError::Custom(
                format!("Error while serializing session data: {}",err)))?;
        let unencrypted_bytes = session_json_str.as_bytes();

        let mut tag: [u8; 16] = [0; 16];
        let mut encrypted_bytes = crypt::encrypt(key, unencrypted_bytes, &mut tag)?;
        encrypted_bytes.extend(tag.iter());

        let token = Token::from(base64::encode(&encrypted_bytes));

        self.cache_session(&token, &session);
        Ok(token)
    }

    pub fn decode(&self, token: Token, key: &[u8]) -> KrillResult<ClientSession> {
        if let Some(session) = self.lookup_session(&token) {
            trace!("Session cache hit for session id {}", &session.id);
            return Ok(session);
        } else {
            trace!("Session cache miss, deserializing...");
        }

        let bytes = base64::decode(token.as_ref().as_bytes())
        .map_err(|err| KrillError::Custom(
            format!("Invalid bearer token: {}", err)))?;

        if bytes.len() <= TAG_SIZE {
            return Err(KrillError::Custom("Invalid bearer token: token is too short".to_string()));
        }

        let encrypted_len = bytes.len() - TAG_SIZE;
        let (encrypted_bytes, tag_bytes) = bytes.split_at(encrypted_len);
        let unencrypted_bytes = crypt::decrypt(key, encrypted_bytes, tag_bytes)?;

        let session = serde_json::from_slice::<ClientSession>(&unencrypted_bytes)
            .map_err(|err| KrillError::Custom(
                format!("Unable to deserializing client session: {}", err)))?;

        trace!("Session cache miss, deserialized session id {}", &session.id);

        self.cache_session(&token, &session);

        Ok(session)
    }

    pub fn remove(&self, token: &Token) {
        match self.cache.write() {
            Ok(mut writeable_cache) => { writeable_cache.remove(token); },
            Err(err) => warn!("Unable to purge cached session: {}", err)
        }
    }

    pub fn size(&self) -> usize {
        match self.cache.read() {
            Ok(readable_cache) => readable_cache.len(),
            Err(err) => { warn!("Unable to query session cache size: {}", err); 0 }
        }
    }

    pub fn sweep(&self) -> KrillResult<()> {
        let expired_keys: Vec<_> = {
            let now = Self::time_now_secs_since_epoch()?;
            self.cache.read()
                .map_err(|err| KrillError::Custom(
                    format!("Unable to purge expired sessions: {}", err)))?    
                .iter()
                .filter(|(_, v)| v.evict_after > now)
                .map(|(k, _)| k.clone())
                .collect()
        };

        let mut writeable_cache = self.cache.write()
            .map_err(|err| KrillError::Custom(
                format!("Unable to purge expired sessions: {}", err)))?;

        for k in expired_keys {
            writeable_cache.remove(&k);
        }

        Ok(())
    }
}