//! Support for signing things using software keys (through openssl) and
//! storing them unencrypted on disk.
use std::{
    fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use bytes::Bytes;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

use openssl::{
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
};

use rpki::repository::crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError, signer::{KeyError, Sign, SignWithKey}};

use crate::{
    commons::{crypto::signers::error::SignerError, error::KrillIoError},
    constants::KEYS_DIR,
};

#[cfg(feature = "hsm")]
use std::sync::RwLock;

#[cfg(feature = "hsm")]
use crate::commons::{api::Handle, crypto::dispatch::signerinfo::SignerMapper};

//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
#[derive(Debug)]
pub struct OpenSslSigner {
    keys_dir: Arc<Path>,

    #[cfg(feature = "hsm")]
    name: String,

    #[cfg(feature = "hsm")]
    handle: RwLock<Option<Handle>>,

    #[cfg(feature = "hsm")]
    info: Option<String>,

    #[cfg(feature = "hsm")]
    mapper: Option<Arc<SignerMapper>>,
}

#[cfg(not(feature = "hsm"))]
impl OpenSslSigner {
    pub fn build(work_dir: &Path) -> Result<Self, SignerError> {
        let keys_dir = Self::init_keys_dir(work_dir)?;
        Ok(OpenSslSigner {
            keys_dir: keys_dir.into(),
        })
    }
}

#[cfg(feature = "hsm")]
impl OpenSslSigner {
    /// The OpenSslSigner can be used with or without a SignerMapper. Without a SignerMapper a caller that needs to
    /// dispatch requests to the Signer that owns a given KeyIdentifier will be unable to do so as the SignerMapper
    /// only knows about keys created by the OpenSslSigner if the OpenSslSigner registers the new keys in the mapper.
    pub fn build(work_dir: &Path, name: &str, mapper: Option<Arc<SignerMapper>>) -> Result<Self, SignerError> {
        let keys_dir = Self::init_keys_dir(work_dir)?;

        let s = OpenSslSigner {
            name: name.to_string(),
            info: Some(format!(
                "OpenSSL Soft Signer [version: {}, keys dir: {}]",
                openssl::version::version(),
                keys_dir.as_path().display()
            )),
            handle: RwLock::new(None), // will be set later
            mapper: mapper.clone(),
            keys_dir: keys_dir.into(),
        };

        Ok(s)
    }

    #[cfg(feature = "hsm")]
    pub fn get_name(&self) -> &str {
        &self.name
    }

    #[cfg(feature = "hsm")]
    pub fn set_handle(&self, handle: Handle) {
        let mut writable_handle = self.handle.write().unwrap();
        if writable_handle.is_some() {
            panic!("Cannot set signer handle as handle is already set");
        }
        *writable_handle = Some(handle);
    }

    #[cfg(feature = "hsm")]
    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        use std::str::FromStr;

        let key_id = KeyIdentifier::from_str(signer_private_key_id).map_err(|_| SignerError::KeyNotFound)?;
        let key_pair = self.load_key(&key_id)?;
        let signature = Self::sign_with_key_internal(key_pair.pkey.as_ref(), challenge)?;
        Ok(signature)
    }

    #[cfg(feature = "hsm")]
    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        // For the OpenSslSigner we use the KeyIdentifier as the internal key id so the two are the same.
        let key_id = self.build_key()?;
        let internal_key_id = key_id.to_string();
        let key_pair = self.load_key(&key_id)?;
        let public_key = key_pair.subject_public_key_info()?;
        Ok((public_key, internal_key_id))
    }

    #[cfg(feature = "hsm")]
    pub fn get_info(&self) -> Option<String> {
        self.info.clone()
    }
}

impl OpenSslSigner {
    pub fn supports_random(&self) -> bool {
        true
    }
}

impl OpenSslSigner {
    fn init_keys_dir(work_dir: &Path) -> Result<PathBuf, SignerError> {
        let meta_data = fs::metadata(&work_dir).map_err(|e| {
            KrillIoError::new(
                format!("Could not get metadata from '{}'", work_dir.to_string_lossy()),
                e,
            )
        })?;
        if meta_data.is_dir() {
            let mut keys_dir = work_dir.to_path_buf();
            keys_dir.push(KEYS_DIR);
            if !keys_dir.is_dir() {
                fs::create_dir_all(&keys_dir).map_err(|e| {
                    KrillIoError::new(
                        format!(
                            "Could not create dir(s) '{}' for key storage",
                            keys_dir.to_string_lossy()
                        ),
                        e,
                    )
                })?;
            }
            Ok(keys_dir)
        } else {
            Err(SignerError::InvalidWorkDir(work_dir.to_path_buf()))
        }
    }

    fn build_key(&self) -> Result<KeyIdentifier, SignerError> {
        let kp = OpenSslKeyPair::build()?;

        let pk = &kp.subject_public_key_info()?;
        let key_id = pk.key_identifier();

        let path = self.key_path(&key_id);
        let json = serde_json::to_string(&kp)?;

        let mut f = File::create(&path)
            .map_err(|e| KrillIoError::new(format!("Could not create key file '{}'", path.to_string_lossy()), e))?;
        f.write_all(json.as_ref())
            .map_err(|e| KrillIoError::new(format!("Could write to key file '{}'", path.to_string_lossy()), e))?;

        Ok(key_id)
    }

    fn sign_with_key_internal<D: AsRef<[u8]> + ?Sized>(pkey: &PKeyRef<Private>, data: &D) -> Result<Signature, SignerError> {
        let mut signer = ::openssl::sign::Signer::new(MessageDigest::sha256(), pkey)?;
        signer.update(data.as_ref())?;

        let signature = Signature::new(SignatureAlgorithm::default(), Bytes::from(signer.sign_to_vec()?));

        Ok(signature)
    }

    pub async fn sign_with_key<What: SignWithKey>(
        &self, key_id: &KeyIdentifier, what: What
    ) -> Result<<What::Sign as Sign>::Final, SignerError> {
        let key_pair = self.load_key(key_id)?;
        let info = key_pair.subject_public_key_info()?;
        let what = what.set_key(&info).map_err(|err| SignerError::Other(err.to_string()))?;
        let signature = Self::sign_with_key_internal(key_pair.pkey.as_ref(), what.signed_data())?;
        Ok(what.sign(signature))
    }

    fn load_key(&self, id: &KeyIdentifier) -> Result<OpenSslKeyPair, SignerError> {
        let path = self.key_path(id);
        if path.exists() {
            let f = File::open(&path)
                .map_err(|e| KrillIoError::new(format!("Could not read key file '{}'", path.to_string_lossy()), e))?;
            let kp: OpenSslKeyPair = serde_json::from_reader(f)?;
            Ok(kp)
        } else {
            Err(SignerError::KeyNotFound)
        }
    }

    fn key_path(&self, key_id: &KeyIdentifier) -> PathBuf {
        let mut path = self.keys_dir.to_path_buf();
        path.push(&key_id.to_string());
        path
    }

    #[cfg(not(feature = "hsm"))]
    fn remember_key_id(&self, _key_id: &KeyIdentifier) -> Result<(), SignerError> {
        Ok(())
    }

    #[cfg(feature = "hsm")]
    fn remember_key_id(&self, key_id: &KeyIdentifier) -> Result<(), SignerError> {
        // When testing the OpenSSlSigner in isolation there is no need for a mapper as we don't need to determine
        // which signer to use for a particular KeyIdentifier as there is only one signer, and the OpenSslSigner
        // doesn't need a mapper to map from KeyIdentifier to internal key id as the internal key id IS the
        // KeyIdentifier.
        if let Some(mapper) = &self.mapper {
            let readable_handle = self.handle.read().unwrap();
            let signer_handle = readable_handle.as_ref().ok_or(SignerError::Other(
                "Failed to record signer key: Signer handle not set".to_string(),
            ))?;
            mapper
                .add_key(signer_handle, key_id, &format!("{}", key_id))
                .map_err(|err| SignerError::Other(format!("Failed to record signer key: {}", err)))
        } else {
            Ok(())
        }
    }
}

impl Signer for OpenSslSigner {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&self, _algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let key_id = self.build_key()?;
        self.remember_key_id(&key_id)?;
        Ok(key_id)
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let key_pair = self.load_key(key_id)?;
        Ok(key_pair.subject_public_key_info()?)
    }

    fn destroy_key(&self, key_id: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        let path = self.key_path(key_id);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                SignerError::IoError(KrillIoError::new(
                    format!("Could not remove key file '{}'", path.to_string_lossy()),
                    e,
                ))
            })?;
        }
        Ok(())
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        let key_pair = self.load_key(key_id)?;
        Self::sign_with_key_internal(key_pair.pkey.as_ref(), data).map_err(SigningError::Signer)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        let kp = OpenSslKeyPair::build()?;

        let signature = Self::sign_with_key_internal(kp.pkey.as_ref(), data)?;

        let key = kp.subject_public_key_info()?;

        Ok((signature, key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        openssl::rand::rand_bytes(target).map_err(SignerError::OpenSslError)
    }
}

//------------ OpenSslKeyPair ------------------------------------------------

/// An openssl based RSA key pair
pub struct OpenSslKeyPair {
    pkey: PKey<Private>,
}

impl Serialize for OpenSslKeyPair {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = self.pkey.as_ref().private_key_to_der().map_err(ser::Error::custom)?;

        base64::encode(&bytes).serialize(s)
    }
}

impl<'de> Deserialize<'de> for OpenSslKeyPair {
    fn deserialize<D>(d: D) -> Result<OpenSslKeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(d) {
            Ok(base64) => {
                let bytes = base64::decode(&base64).map_err(de::Error::custom)?;

                let pkey = PKey::private_key_from_der(&bytes).map_err(de::Error::custom)?;

                Ok(OpenSslKeyPair { pkey })
            }
            Err(err) => Err(err),
        }
    }
}

impl OpenSslKeyPair {
    fn build() -> Result<OpenSslKeyPair, SignerError> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(OpenSslKeyPair { pkey })
    }

    fn subject_public_key_info(&self) -> Result<PublicKey, SignerError> {
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let mut b = Bytes::from(self.pkey.rsa().unwrap().public_key_to_der()?);
        PublicKey::decode(&mut b).map_err(|_| SignerError::DecodeError)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use crate::test;

    use super::*;

    #[test]
    fn should_return_subject_public_key_info() {
        test::test_under_tmp(|d| {
            #[cfg(not(feature = "hsm"))]
            let s = OpenSslSigner::build(&d).unwrap();

            #[cfg(feature = "hsm")]
            let s = OpenSslSigner::build(&d, "dummy", None).unwrap();

            let ki = s.create_key(PublicKeyFormat::Rsa).unwrap();
            s.get_key_info(&ki).unwrap();
            s.destroy_key(&ki).unwrap();
        })
    }

    #[test]
    fn should_serialize_and_deserialize_key() {
        let key = OpenSslKeyPair::build().unwrap();
        let json = serde_json::to_string(&key).unwrap();
        let key_des: OpenSslKeyPair = serde_json::from_str(json.as_str()).unwrap();
        let json_from_des = serde_json::to_string(&key_des).unwrap();

        // comparing json, because OpenSslKeyPair and its internal friends do
        // not implement Eq and PartialEq.
        assert_eq!(json, json_from_des);
    }
}
