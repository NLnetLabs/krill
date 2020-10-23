// TOOD: use the ring::aead functionality instead of the chacha20_poly1305_aead
// crate, as we already depend on ring.

// See: https://tools.ietf.org/html/rfc7539#section-2.8
//      https://briansmith.org/rustdoc/ring/aead/index.html
//      http://www-cse.ucsd.edu/~mihir/papers/oem.html

use std::io::Write;

use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;

// TODO: use proper values
const AEAD_KEY: [u8; 32]   = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
const AEAD_NONCE: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const AEAD_AAD: [u8; 4]    = [1, 2, 3, 4];

// Encrypts plaintext into ciphertext. Ciphertext should be pre-allocated and be
// the same byte length as plaintext. Returns the tag which will be needed to
// verify the encrypted data during decryption.
pub(crate) fn encrypt<W: Write>(plaintext: &[u8], ciphertext: &mut W) -> KrillResult<[u8; 16]> {
    let tag = chacha20_poly1305_aead::encrypt(&AEAD_KEY, &AEAD_NONCE, &AEAD_AAD, plaintext, ciphertext)
        .map_err(|err| KrillError::Custom(format!("Encryption error: {}", &err)))?;
    
    Ok(tag)
}

// Decrypts ciphertext into plaintext. Plaintext should be pre-allocated and be
// the same byte length as ciphertext. Requires the tag that resulted from
// encryption to verify the data.
pub(crate) fn decrypt<W: Write>(ciphertext: &[u8], tag: &[u8], plaintext: &mut W) -> KrillResult<()> {
    chacha20_poly1305_aead::decrypt(&AEAD_KEY, &AEAD_NONCE, &AEAD_AAD, &ciphertext, &tag, plaintext)
        .map_err(|err| KrillError::Custom(format!("Decryption error: {}", &err)))
}