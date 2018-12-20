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
use rpki::signing::KEY_SIZE;
use rpki::signing::PublicKeyAlgorithm;
use rpki::signing::signer::{
    CreateKeyError,
    KeyId,
    KeyUseError,
    OneOffSignature,
    Signature,
    Signer};
use rpki::cert::SubjectPublicKeyInfo;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de;
use serde::ser;
use storage::keystore::{self, Info, Key, KeyStore};
use storage::caching_ks::CachingDiskKeyStore;


//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
///
/// Keeps the keys in memory (for now).
#[derive(Clone, Debug)]
pub struct OpenSslSigner {
    store: CachingDiskKeyStore
}

impl OpenSslSigner {
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
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
            Err(Error::InvalidWorkDir(work_dir.clone()))
        }
    }
}

impl OpenSslSigner {
    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(
        pkey: &PKeyRef<Private>,
        data: &D
    ) -> Result<Signature, KeyUseError>
    {
        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(),
            pkey
        )?;
        signer.update(data.as_ref())?;

        Ok(Signature::new(Bytes::from(signer.sign_to_vec()?)))
    }
}

impl Signer for OpenSslSigner {
    fn create_key(
        &mut self,
        algorithm: &PublicKeyAlgorithm
    ) -> Result<KeyId, CreateKeyError> {

        if *algorithm != PublicKeyAlgorithm::RsaEncryption {
            return Err(CreateKeyError::UnsupportedAlgorithm)
        }

        let kp = OpenSslKeyPair::new()?;

        let key_id = KeyId::from_spki(&kp.subject_public_key_info()?);
        let key = Key::from_key_id(&key_id);
        let info = Info::now("openssl signer", "created key");

        self.store.store(key, kp, info)?;

        Ok(key_id)
    }

    fn get_key_info(&self, id: &KeyId)
                    -> Result<SubjectPublicKeyInfo, KeyUseError>
    {

        let key_pair_option: Option<Arc<OpenSslKeyPair>> =
            self.store.get(&Key::from_key_id(id))?;


        match key_pair_option {
            Some(k) => Ok(k.subject_public_key_info()?),
            None => Err(KeyUseError::KeyNotFound)
        }
    }

    fn destroy_key(&mut self, id: &KeyId) -> Result<(), KeyUseError> {

        let key = Key::from_key_id(id);
        let info = Info::now("openssl signer", "archived key");

        self.store.archive(&key, info).map_err(|e| {KeyUseError::from(e)})
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        id: &KeyId,
        data: &D
    ) -> Result<Signature, KeyUseError> {
        let key = Key::from_key_id(id);
        let key_pair_option: Option<Arc<OpenSslKeyPair>> =
            self.store.get(&key)?;

        match key_pair_option {
            None => Err(KeyUseError::KeyNotFound),
            Some(k) => {
                match self.get_key_info(id)?.algorithm() {
                    PublicKeyAlgorithm::RsaEncryption => {
                        Self::sign_with_key(k.pkey.as_ref(), data)
                    }
                }
            }
        }
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D
    ) -> Result<OneOffSignature, KeyUseError> {
        let kp = OpenSslKeyPair::new()?;

        let signature = Self::sign_with_key(
            kp.pkey.as_ref(),
            data
        )?;

        let key = kp.subject_public_key_info()?;

        Ok(OneOffSignature::new(key, signature))
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
    fn new() -> Result<OpenSslKeyPair, Error> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(KEY_SIZE)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(OpenSslKeyPair{ pkey })
    }

    fn subject_public_key_info(&self) -> Result<SubjectPublicKeyInfo, Error> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let mut b = Bytes::from(self.pkey.rsa().unwrap().public_key_to_der()?);
        Ok(SubjectPublicKeyInfo::decode(&mut b)?)
    }
}


//------------ OpenSslKeyError -----------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {

    #[fail(display = "OpenSsl Error: {}", _0)]
    OpenSslError(ErrorStack),

    #[fail(display = "Could not decode public key info: {}", _0)]
    DecodeError(decode::Error),

    #[fail(display = "Invalid base path: {:?}", _0)]
    InvalidWorkDir(PathBuf),

    #[fail(display = "{}", _0)]
    IoError(io::Error),

    #[fail(display = "{}", _0)]
    KeyStoreError(keystore::Error),
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Error::OpenSslError(e)
    }
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Error::DecodeError(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;
    use test;

    #[test]
    fn should_return_subject_public_key_info() {
        test::test_with_tmp_dir(|d| {
            let mut s = OpenSslSigner::new(&d).unwrap();
            let ki = s.create_key(&PublicKeyAlgorithm::RsaEncryption).unwrap();
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
