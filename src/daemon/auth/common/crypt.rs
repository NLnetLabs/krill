use crate::commons::error::Error as KrillError;
use crate::commons::KrillResult;

// TODO: use proper values
const KEY: [u8; 32] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
const IV: [u8; 12]  = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const AAD: [u8; 4]  = [1, 2, 3, 4];

// Encrypts plaintext into ciphertext. Ciphertext should be pre-allocated and be
// the same byte length as plaintext. Returns the tag which will be needed to
// verify the encrypted data during decryption.
pub(crate) fn encrypt(plaintext: &[u8], mut tag: &mut [u8]) -> KrillResult<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    openssl::symm::encrypt_aead(cipher, &KEY, Some(&IV), &AAD, plaintext, &mut tag)
        .map_err(|err| KrillError::Custom(format!("Encryption error: {}", &err)))
}

// Decrypts ciphertext into plaintext. Plaintext should be pre-allocated and be
// the same byte length as ciphertext. Requires the tag that resulted from
// encryption to verify the data.
pub(crate) fn decrypt(ciphertext: &[u8], tag: &[u8]) -> KrillResult<Vec<u8>> {
    // chacha20_poly1305_aead::decrypt(&KEY, &IV, &AAD, &ciphertext, &tag, plaintext)
    //     .map_err(|err| KrillError::Custom(format!("Decryption error: {}", &err)))
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    openssl::symm::decrypt_aead(cipher, &KEY, Some(&IV), &AAD, ciphertext, tag)
        .map_err(|err| KrillError::Custom(format!("Decryption error: {}", &err)))
}