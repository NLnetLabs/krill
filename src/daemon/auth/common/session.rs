use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cached::{proc_macro::cached, Cached};

use crate::{daemon::auth::common::config::Role, commons::api::Token};
use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;

use super::crypt;

const TAG_SIZE: usize = 16;

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

pub fn session_to_token(id: &String, role: &Role, inc_cas: &[String], exc_cas: &[String], secrets: &[String]) -> KrillResult<Token> {
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| KrillError::Custom(
            format!("unable to determine the current time: {}", err)))?
        .as_secs();

    let session = ClientSession {
        start_time: start_time,
        expires_in: Some(Duration::new(3600, 0)),
        id: id.clone(),
        role: role.clone(),
        inc_cas: inc_cas.to_vec(),
        exc_cas: exc_cas.to_vec(),
        secrets: secrets.to_vec(),
    };

    let session_json_str = serde_json::to_string(&session)
        .map_err(|err| KrillError::Custom(format!(
            "OpenID Connect: Error while serializing session data: {}",
            err)))?;
    let unencrypted_bytes = session_json_str.as_bytes();

    let mut encrypted_bytes = Vec::with_capacity(unencrypted_bytes.len());
    let tag: [u8; 16] = crypt::encrypt(unencrypted_bytes, &mut encrypted_bytes)?;

    encrypted_bytes.extend(tag.iter());
    let api_token = base64::encode(&encrypted_bytes);

    Ok(Token::from(api_token))
}

#[cached(
    name = "SESSION_CACHE",
    result = true,
    time = 1800
)]
pub fn token_to_session(token: Token) -> KrillResult<ClientSession> {
    let bytes = base64::decode(token.as_ref().as_bytes())
        .map_err(|err| KrillError::Custom(
            format!("OpenID Connect: invalid bearer token: {}", err)))?;

    if bytes.len() <= TAG_SIZE {
        return Err(KrillError::Custom(format!("OpenID Connect: bearer token is too short")));
    }

    let encrypted_len = bytes.len() - TAG_SIZE;
    let (encrypted_bytes, tag_bytes) = bytes.split_at(encrypted_len);
    let mut unencrypted_bytes = Vec::with_capacity(encrypted_len);
    crypt::decrypt(encrypted_bytes, tag_bytes, &mut unencrypted_bytes)?;

    serde_json::from_slice::<ClientSession>(&unencrypted_bytes)
        .map_err(|err| KrillError::Custom(
            format!("OpenID Connect: error while deserializing: {}", err)))
}

pub fn forget_cached_session_token(token: &Token) {
    match SESSION_CACHE.lock() {
        Ok(mut cache) => { cache.cache_remove(token); },
        Err(err) => warn!("OpenID Connect: session cache evict error: {}", err)
    }
}

pub fn get_session_cache_size() -> usize {
    match SESSION_CACHE.lock() {
        Ok(cache) => {
            cache.cache_size()
        },
        Err(err) => {
            warn!("OpenID Connect: session cache size error: {}", err);
            0
        }
    }
}