// This module provides encryption and decryption for the
// ConfigFileAuthProvider and OpenIDConnectAuthProvider login session state
// that they "store" at the client browser. The ChaCha20-Poly1305 AEAD
// algorithm was chosen based on a couple of articles about the current best
// algorithms to use in various situations [1, 2] and for example that it is
// tricky to use random nonces safely with AES-GCM [2], and on the
// availability and quality of NPM libraries and Rust crates available at the
// time of writing for the recommended algorithms.
//
// The encryption uses a two part (sender unique + counter) nonce which was
// based on guidance in section 4 "Security Considerations" of RFC-8439
// "ChaCha20 and Poly1305 for IETF Protocols". The "sender unique" part serves
// both to decrease the chance of nonce-reuse between invocations of Krill and
// the chance of nonce overlap between multiple instances of Krill in a
// cluster.
//
// For much more context see the discussion in Krill issue #382 [4].
//
// 1: https://soatok.blog/2020/07/12/comparison-of-symmetric-encryption-methods/#aes-gcm-vs-chacha20poly1305
// 2: https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html
// 3: https://tools.ietf.org/html/rfc8439#section-4
// 4: https://github.com/NLnetLabs/krill/issues/382

use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use crate::commons::ext_serde;
use crate::commons::KrillResult;
use crate::commons::error::{ApiAuthError, Error};
use crate::commons::storage::{Key, Namespace, Segment};
use crate::config::Config;

const CHACHA20_KEY_BIT_LEN: usize = 256;
const CHACHA20_KEY_BYTE_LEN: usize = CHACHA20_KEY_BIT_LEN / 8;
const CHACHA20_NONCE_BIT_LEN: usize = 96;
const CHACHA20_NONCE_BYTE_LEN: usize = CHACHA20_NONCE_BIT_LEN / 8;
const POLY1305_TAG_BIT_LEN: usize = 128;
const POLY1305_TAG_BYTE_LEN: usize = POLY1305_TAG_BIT_LEN / 8;
const CLEARTEXT_PREFIX_LEN: usize =
    CHACHA20_NONCE_BYTE_LEN + POLY1305_TAG_BYTE_LEN;
const UNUSED_AAD: [u8; 0] = [0; 0];

const CRYPT_STATE_NS: &Namespace = Namespace::make("login_sessions");
const CRYPT_STATE_KEY: &Segment = Segment::make("main_key");

#[derive(Debug, Deserialize, Serialize)]
pub struct NonceState {
    sender_unique: [u8; 4], //   32 bits

    #[serde(
        deserialize_with = "ext_serde::de_atomicu64",
        serialize_with = "ext_serde::ser_atomicu64"
    )]
    counter: AtomicU64, // + 64 bits = 96 bits = CHACHA20_NONCE_BIT_LEN
}

impl NonceState {
    pub fn new() -> KrillResult<NonceState> {
        let mut sender_unique: [u8; 4] = [0; 4];
        openssl::rand::rand_bytes(&mut sender_unique).map_err(|err| {
            Error::Custom(format!(
                "Unable to generate a random sender id: {}",
                &err
            ))
        })?;

        Ok(NonceState {
            sender_unique,
            counter: AtomicU64::new(0),
        })
    }

    fn next(&self) -> [u8; CHACHA20_NONCE_BYTE_LEN] {
        // increment the counter atomically
        let count = self.counter.fetch_add(1, Ordering::SeqCst);

        // combine the fixed sender unique part with the increasing counter
        // part
        let mut nonce: [u8; CHACHA20_NONCE_BYTE_LEN] =
            [0; CHACHA20_NONCE_BYTE_LEN];
        nonce[0..4].copy_from_slice(&self.sender_unique);
        nonce[4..].copy_from_slice(&count.to_ne_bytes());

        nonce
    }
}

#[derive(Deserialize, Serialize)]
pub struct CryptState {
    pub key: [u8; CHACHA20_KEY_BYTE_LEN],
    pub nonce: NonceState,
}

impl CryptState {
    pub fn from_key_bytes(
        key: [u8; CHACHA20_KEY_BYTE_LEN],
    ) -> KrillResult<CryptState> {
        Ok(CryptState {
            key,
            nonce: NonceState::new()?,
        })
    }
}

// Returns nonce + tag + cipher text, or an error.
pub(crate) fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    nonce: &NonceState,
) -> KrillResult<Vec<u8>> {
    // TODO: Do we need to get the cipher each time or could we do this just
    // once?
    let nonce = nonce.next();
    let mut tag: [u8; POLY1305_TAG_BYTE_LEN] = [0; POLY1305_TAG_BYTE_LEN];

    let cipher = openssl::symm::Cipher::chacha20_poly1305();
    let cipher_text = openssl::symm::encrypt_aead(
        cipher,
        key,
        Some(&nonce),
        &UNUSED_AAD,
        plaintext,
        &mut tag,
    )
    .map_err(|err| Error::Custom(format!("Encryption error: {}", &err)))?;

    let mut payload =
        Vec::with_capacity(nonce.len() + tag.len() + cipher_text.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&tag);
    payload.extend(cipher_text);
    Ok(payload)
}

// `payload` should be of the form nonce + tag + cipher text.
// Returns the plain text resulting from decryption, or an error.
pub(crate) fn decrypt(
    key: &[u8], payload: &[u8]
) -> Result<Vec<u8>, ApiAuthError> {
    // TODO: Do we need to get the cipher each time or could we do this just
    // once?
    if payload.len() <= CLEARTEXT_PREFIX_LEN {
        return Err(ApiAuthError::ApiInvalidCredentials(
            "Decryption error: Insufficient data".to_string(),
        ));
    }

    let nonce = &payload[0..CHACHA20_NONCE_BYTE_LEN];
    let tag = &payload[CHACHA20_NONCE_BYTE_LEN..CLEARTEXT_PREFIX_LEN];
    let cipher_text = &payload[CLEARTEXT_PREFIX_LEN..];

    let cipher = openssl::symm::Cipher::chacha20_poly1305();
    openssl::symm::decrypt_aead(
        cipher,
        key,
        Some(nonce),
        &UNUSED_AAD,
        cipher_text,
        tag,
    )
    .map_err(|err| {
        ApiAuthError::ApiInvalidCredentials(
            format!("Decryption error: {}", &err)
        )
    })
}

pub(crate) fn crypt_init(config: &Config) -> KrillResult<CryptState> {
    let store = config.key_value_store(CRYPT_STATE_NS)?;
    let key = Key::new_global(CRYPT_STATE_KEY);

    if let Some(state) = store.get(&key)? {
        Ok(state)
    } else {
        let mut key_bytes = [0; CHACHA20_KEY_BYTE_LEN];
        openssl::rand::rand_bytes(&mut key_bytes).map_err(|err| {
            Error::Custom(format!(
                "Unable to generate symmetric key: {err}"
            ))
        })?;

        let state = CryptState::from_key_bytes(key_bytes)?;
        store.store_new(&key, &state)?;

        Ok(state)
    }
}
