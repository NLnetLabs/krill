//! Support for signing things using software keys (through openssl) and
//! storing them unencrypted on disk.
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use bcder::decode;
use bytes::Bytes;
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, PKeyRef, Private};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;
use serde::ser;
use storage::keystore::{self, Info, Key, KeyStore};
use storage::caching_ks::CachingDiskKeyStore;
use rpki::crypto::Signer;
use rpki::crypto::Signature;
use rpki::crypto::PublicKey;
use rpki::crypto::SignatureAlgorithm;
use rpki::crypto::SigningError;
use rpki::crypto::PublicKeyFormat;
use rpki::crypto::signer::KeyError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerKeyId(String);

impl SignerKeyId {
    pub fn new(s: &str) -> Self {
        SignerKeyId(s.to_string())
    }
}

impl AsRef<str> for SignerKeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}


//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
///
/// Keeps the keys in memory (for now).
#[derive(Clone, Debug)]
pub struct OpenSslSigner {
    store: CachingDiskKeyStore
}

impl OpenSslSigner {
    pub fn new(work_dir: &PathBuf) -> Result<Self, SignerError> {
        let meta_data = fs::metadata(&work_dir)?;
        if meta_data.is_dir() {

            let mut keys_dir = PathBuf::from(work_dir);
            keys_dir.push("keys");
            if ! keys_dir.is_dir() {
                fs::create_dir_all(&keys_dir)?;
            }

            Ok(
                OpenSslSigner {
                    store: CachingDiskKeyStore::new(keys_dir)?,
                }
            )
        } else {
            Err(SignerError::InvalidWorkDir(work_dir.clone()))
        }
    }
}

impl OpenSslSigner {
    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(
        pkey: &PKeyRef<Private>,
        data: &D
    ) -> Result<Signature, SignerError>
    {
        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(),
            pkey
        )?;
        signer.update(data.as_ref())?;

        let signature = Signature::new(
            SignatureAlgorithm,
            Bytes::from(signer.sign_to_vec()?));

        Ok(signature)
    }
}

impl Signer for OpenSslSigner {

    type KeyId = SignerKeyId;
    type Error = SignerError;

    fn create_key(
        &mut self,
        algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error> {

        let kp = OpenSslKeyPair::new()?;

        let pk = &kp.subject_public_key_info()?;
        let hex_hash = hex::encode(pk.key_identifier().as_ref());
        let key_id = SignerKeyId(hex_hash);
        let store_key = Key::from_str(key_id.as_ref());
        let info = Info::now("openssl signer", "created key");

        self.store.store(store_key, kp, info)?;

        Ok(key_id)
    }

    fn get_key_info(
        &self,
        key_id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        let store_key = Key::from_str(key_id.as_ref());

        let key_pair_option: Option<Arc<OpenSslKeyPair>> =
            self.store.get(&store_key)
                .map_err(|e| {
                    KeyError::Signer(SignerError::KeyStoreError(e))}
                )?;

        match key_pair_option {
            Some(k) => Ok(k.subject_public_key_info()?),
            None => Err(KeyError::Signer(SignerError::KeyNotFound))
        }
    }

    fn destroy_key(
        &mut self,
        key_id: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {

        let store_key = Key::from_str(key_id.as_ref());
        let info = Info::now("openssl signer", "archived key");

        self.store.archive(&store_key, info).map_err(|e| {
            KeyError::Signer(SignerError::from(e))
        })
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<Signature, SigningError<Self::Error>> {
        let store_key = Key::from_str(key_id.as_ref());
        let key_pair_option: Option<Arc<OpenSslKeyPair>> =
            self.store.get(&store_key)
                .map_err(|e| {
                    KeyError::Signer(SignerError::KeyStoreError(e))}
                )?;

        match key_pair_option {
            None => Err(SigningError::Signer(SignerError::KeyNotFound)),
            Some(k) => {
                Self::sign_with_key(k.pkey.as_ref(), data)
                    .map_err(|e| { SigningError::Signer(e)})
            }
        }
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<(Signature, PublicKey), SignerError> {
        let kp = OpenSslKeyPair::new()?;

        let signature = Self::sign_with_key(
            kp.pkey.as_ref(),
            data
        )?;

        let key = kp.subject_public_key_info()?;

        Ok((signature, key))
    }
}


//------------ OpenSslKeyPair ------------------------------------------------

/// An openssl based RSA key pair
pub struct OpenSslKeyPair {
    pkey: PKey<Private>
}

impl Serialize for OpenSslKeyPair {
    fn serialize<S>(
        &self,
        s: S
    ) -> Result<S::Ok, S::Error> where
        S: Serializer {
        let bytes: Vec<u8> = self.pkey.as_ref().private_key_to_der()
            .map_err(ser::Error::custom)?;

        base64::encode(&bytes).serialize(s)
    }
}

impl<'de> Deserialize<'de> for OpenSslKeyPair {
    fn deserialize<D>(
        d: D
    ) -> Result<OpenSslKeyPair, D::Error> where
        D: Deserializer<'de> {
        match String::deserialize(d) {
            Ok(base64) => {
                let bytes = base64::decode(&base64)
                    .map_err(de::Error::custom)?;

                let pkey = PKey::private_key_from_der(&bytes)
                    .map_err(de::Error::custom)?;

                Ok(
                    OpenSslKeyPair {
                        pkey
                    }
                )
            },
            Err(err) => Err(err)
        }
    }
}

impl OpenSslKeyPair {
    fn new() -> Result<OpenSslKeyPair, SignerError> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(OpenSslKeyPair{ pkey })
    }

    fn subject_public_key_info(&self) -> Result<PublicKey, SignerError> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let mut b = Bytes::from(self.pkey.rsa().unwrap().public_key_to_der()?);
        Ok(PublicKey::decode(&mut b)?)
    }
}


//------------ OpenSslKeyError -----------------------------------------------

#[derive(Debug, Display)]
pub enum SignerError {
    #[display(fmt = "OpenSsl Error: {}", _0)]
    OpenSslError(ErrorStack),

    #[display(fmt = "Could not decode public key info: {}", _0)]
    DecodeError(decode::Error),

    #[display(fmt = "Invalid base path: {:?}", _0)]
    InvalidWorkDir(PathBuf),

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "{}", _0)]
    KeyStoreError(keystore::Error),

    #[display(fmt = "Could not find key")]
    KeyNotFound,
}

impl From<ErrorStack> for SignerError {
    fn from(e: ErrorStack) -> Self {
        SignerError::OpenSslError(e)
    }
}

impl From<decode::Error> for SignerError {
    fn from(e: decode::Error) -> Self {
        SignerError::DecodeError(e)
    }
}

impl From<io::Error> for SignerError {
    fn from(e: io::Error) -> Self {
        SignerError::IoError(e)
    }
}

impl From<keystore::Error> for SignerError {
    fn from(e: keystore::Error) -> Self {
        SignerError::KeyStoreError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::util::test;

    #[test]
    fn should_return_subject_public_key_info() {
        test::test_with_tmp_dir(|d| {
            let mut s = OpenSslSigner::new(&d).unwrap();
            let ki = s.create_key(PublicKeyFormat).unwrap();
            s.get_key_info(&ki).unwrap();
            s.destroy_key(&ki).unwrap();
        })
    }

    #[test]
    fn should_serialize_and_deserialize_key() {

        let key = OpenSslKeyPair::new().unwrap();
        let json = serde_json::to_string(&key).unwrap();
        let key_des: OpenSslKeyPair = serde_json::from_str(json.as_str()).unwrap();
        let json_from_des = serde_json::to_string(&key_des).unwrap();

        // comparing json, because OpenSslKeyPair and its internal friends do
        // not implement Eq and PartialEq.
        assert_eq!(json, json_from_des);
    }
}
