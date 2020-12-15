// TODO: Fold this into OpenSslSigner?
use std::{fs::File, path::Path, io::Write};

use crate::commons::error::Error;
use crate::commons::KrillResult;

const AES_256_GCM_KEY_BIT_LENGTH: usize = 256;
const AES_256_GCM_KEY_BYTE_LENGTH: usize = AES_256_GCM_KEY_BIT_LENGTH/8;

// TODO: use proper values
// See: https://www.imperialviolet.org/2015/05/16/aeads.html
const IV: [u8; 12]  = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // aka nonce
const AAD: &[u8; 5]  = b"krill";

// Returns the encrypted bytes and also outputs the tag that will be needed
// during decryption to verify the encrypted data during decryption.
pub(crate) fn encrypt(key: &[u8], plaintext: &[u8], mut tag: &mut [u8]) -> KrillResult<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    openssl::symm::encrypt_aead(cipher, &key, Some(&IV), AAD, plaintext, &mut tag)
        .map_err(|err| Error::Custom(format!("Encryption error: {}", &err)))
}

// Requires the tag that resulted from encryption to verify the data.
pub(crate) fn decrypt(key: &[u8], ciphertext: &[u8], tag: &[u8]) -> KrillResult<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    openssl::symm::decrypt_aead(cipher, &key, Some(&IV), AAD, ciphertext, tag)
        .map_err(|err| Error::Custom(format!("Decryption error: {}", &err)))
}

pub(crate) fn load_or_create_key(key_path: &Path) -> KrillResult<Vec<u8>> {
    if key_path.exists() {
        std::fs::read(key_path)
            .map_err(|err| Error::Custom(format!(
                "Unable to load symmetric key: {}", err)))
    } else {
        let mut key_bytes = [0; AES_256_GCM_KEY_BYTE_LENGTH];
        openssl::rand::rand_bytes(&mut key_bytes)
            .map_err(|err| Error::Custom(format!(
                "Unable to generate symmetric key: {}", err)))?;

        let mut f = File::create(key_path)?;
        f.write_all(&key_bytes)?;
        Ok(key_bytes.to_vec())
    }
}