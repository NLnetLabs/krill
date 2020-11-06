use std::{collections::HashMap, sync::RwLock, time::{Duration, SystemTime, UNIX_EPOCH}};

use crate::{daemon::auth::common::config::Role, commons::api::Token};
use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;

use super::crypt;

const TAG_SIZE: usize = 16;
const MAX_CACHE_SECS: u64 = 30;

struct CachedSession {
    pub evict_after: u64,
    pub session: ClientSession,
}

lazy_static! {
    static ref SESSION_CACHE: RwLock<HashMap<Token, CachedSession>> = RwLock::new(HashMap::new());
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientSession {
    pub start_time: u64,
    pub expires_in: Option<Duration>,
    pub id: String,
    pub role: Role,
    pub inc_cas: Vec<String>,
    pub exc_cas: Vec<String>,
    pub secrets: Vec<String>,
}

fn time_now_secs_since_epoch() -> KrillResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| KrillError::Custom(
            format!("Unable to determine the current time: {}", err)))?
        .as_secs())
}

fn get_cached_session(token: &Token) -> Option<ClientSession> {
    match SESSION_CACHE.read() {
        Ok(cache) => {
            if let Some(cache_item) = cache.get(&token) {
                return Some(cache_item.session.clone());
            }
        },
        Err(err) => warn!("Unexpected session cache miss: {}", err)
    }

    None
}

fn cache_session(token: &Token, session: &ClientSession) {
    match SESSION_CACHE.write() {
        Ok(mut cache) => {
            match time_now_secs_since_epoch() {
                Ok(now) => {
                    cache.insert(token.clone(), CachedSession {
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

pub fn session_to_token(id: &String, role: &Role, inc_cas: &[String], exc_cas: &[String], secrets: &[String]) -> KrillResult<Token> {
    let session = ClientSession {
        start_time: time_now_secs_since_epoch()?,
        expires_in: Some(Duration::new(3600, 0)),
        id: id.clone(),
        role: role.clone(),
        inc_cas: inc_cas.to_vec(),
        exc_cas: exc_cas.to_vec(),
        secrets: secrets.to_vec(),
    };

    let session_json_str = serde_json::to_string(&session)
        .map_err(|err| KrillError::Custom(
            format!("Error while serializing session data: {}",err)))?;
    let unencrypted_bytes = session_json_str.as_bytes();

    let mut tag: [u8; 16] = [0; 16];
    let mut encrypted_bytes = crypt::encrypt(unencrypted_bytes, &mut tag)?;

    encrypted_bytes.extend(tag.iter());
    let api_token = base64::encode(&encrypted_bytes);

    Ok(Token::from(api_token))
}

pub fn token_to_session(token: Token) -> KrillResult<ClientSession> {
    if let Some(session) = get_cached_session(&token) {
        return Ok(session);
    }

    let bytes = base64::decode(token.as_ref().as_bytes())
    .map_err(|err| KrillError::Custom(
        format!("Invalid bearer token: {}", err)))?;

    if bytes.len() <= TAG_SIZE {
        return Err(KrillError::Custom(format!("Invalid bearer token: token is too short")));
    }

    let encrypted_len = bytes.len() - TAG_SIZE;
    let (encrypted_bytes, tag_bytes) = bytes.split_at(encrypted_len);
    let unencrypted_bytes = crypt::decrypt(encrypted_bytes, tag_bytes)?;

    let session = serde_json::from_slice::<ClientSession>(&unencrypted_bytes)
        .map_err(|err| KrillError::Custom(
            format!("Unable to deserializing client session: {}", err)))?;

    cache_session(&token, &session);
    Ok(session)
}

pub fn forget_cached_session(token: &Token) {
    match SESSION_CACHE.write() {
        Ok(mut cache) => { cache.remove(token); },
        Err(err) => warn!("Unable to purge cached session: {}", err)
    }
}

pub fn get_session_cache_size() -> usize {
    match SESSION_CACHE.read() {
        Ok(cache) => cache.len(),
        Err(err) => { warn!("Unable to query session cache size: {}", err); 0 }
    }
}

pub fn sweep_session_decryption_cache() -> KrillResult<()> {
    let expired_keys: Vec<_> = {
        let now = time_now_secs_since_epoch()?;
        SESSION_CACHE.read()
            .map_err(|err| KrillError::Custom(
                format!("Unable to purge expired sessions: {}", err)))?    
            .iter()
            .filter(|(_, v)| v.evict_after > now)
            .map(|(k, _)| k.clone())
            .collect()
    };

    let mut cache = SESSION_CACHE.write()
        .map_err(|err| KrillError::Custom(
            format!("Unable to purge expired sessions: {}", err)))?;

    for k in expired_keys {
        cache.remove(&k);
    }

    Ok(())
}