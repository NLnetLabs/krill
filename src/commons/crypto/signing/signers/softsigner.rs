//! Support for signing things using software keys (through openssl) and
//! storing them unencrypted on disk.
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
};
use rpki::crypto::{
    signer::{KeyError, SigningAlgorithm},
    KeyIdentifier, PublicKey, PublicKeyFormat, RpkiSignature, RpkiSignatureAlgorithm, Signature, SignatureAlgorithm,
    SigningError,
};
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::{
    commons::{
        crypto::{dispatch::signerinfo::SignerMapper, signers::error::SignerError, SignerHandle},
        eventsourcing::{Key, KeyValueStore, Segment, SegmentExt},
    },
    constants::KEYS_NS,
};

//------------ OpenSslSigner -------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Hash, PartialEq, Eq)]
pub struct OpenSslSignerConfig {
    #[serde(default)]
    pub keys_storage_uri: Option<Url>,
}

impl OpenSslSignerConfig {
    pub fn new(storage_uri: Url) -> Self {
        Self {
            keys_storage_uri: Some(storage_uri),
        }
    }
}

/// An openssl based signer.
#[derive(Debug)]
pub struct OpenSslSigner {
    keys_store: KeyValueStore,

    name: String,

    handle: RwLock<Option<SignerHandle>>,

    info: Option<String>,

    mapper: Option<Arc<SignerMapper>>,
}

impl OpenSslSigner {
    /// The OpenSslSigner can be used with or without a SignerMapper. Without a SignerMapper a caller that needs to
    /// dispatch requests to the Signer that owns a given KeyIdentifier will be unable to do so as the SignerMapper
    /// only knows about keys created by the OpenSslSigner if the OpenSslSigner registers the new keys in the mapper.
    pub fn build(storage_uri: &Url, name: &str, mapper: Option<Arc<SignerMapper>>) -> Result<Self, SignerError> {
        let keys_store = Self::init_keys_store(storage_uri)?;

        let s = OpenSslSigner {
            name: name.to_string(),
            info: Some(format!(
                "OpenSSL Soft Signer [version: {}, keys store: {}]",
                openssl::version::version(),
                storage_uri,
            )),
            handle: RwLock::new(None), // will be set later
            mapper,
            keys_store,
        };

        Ok(s)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_handle(&self, handle: SignerHandle) {
        let mut writable_handle = self.handle.write().unwrap();
        if writable_handle.is_some() {
            panic!("Cannot set signer handle as handle is already set");
        }
        *writable_handle = Some(handle);
    }

    pub fn get_info(&self) -> Option<String> {
        self.info.clone()
    }

    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        // For the OpenSslSigner we use the KeyIdentifier as the internal key id so the two are the same.
        let key_id = self.build_key()?;
        let internal_key_id = key_id.to_string();
        let key_pair = self.load_key(&key_id)?;
        let public_key = key_pair.subject_public_key_info()?;
        Ok((public_key, internal_key_id))
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<RpkiSignature, SignerError> {
        let key_id = KeyIdentifier::from_str(signer_private_key_id).map_err(|_| SignerError::KeyNotFound)?;
        let key_pair = self.load_key(&key_id)?;
        let signature = Self::sign_with_key(key_pair.pkey.as_ref(), RpkiSignatureAlgorithm::default(), challenge)?;
        Ok(signature)
    }
}

impl OpenSslSigner {
    fn init_keys_store(storage_uri: &Url) -> Result<KeyValueStore, SignerError> {
        let store = KeyValueStore::create(storage_uri, KEYS_NS)
            .map_err(|_| SignerError::InvalidStorage(storage_uri.clone()))?;
        Ok(store)
    }

    fn build_key(&self) -> Result<KeyIdentifier, SignerError> {
        let kp = OpenSslKeyPair::build()?;
        self.store_key(kp)
    }

    fn store_key(&self, kp: OpenSslKeyPair) -> Result<KeyIdentifier, SignerError> {
        let pk = &kp.subject_public_key_info()?;
        let key_id = pk.key_identifier();

        // TODO encrypt key before storing
        let json = serde_json::to_value(&kp)?;
        match self
            .keys_store
            .store(&Key::new_global(Segment::parse_lossy(&key_id.to_string())), &json) // key_id should always be a valid Segment
        {
            Ok(_) => Ok(key_id),
            Err(err) => Err(SignerError::Other(format!("Failed to store key: {}:", err))),
        }
    }

    fn sign_with_key<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        pkey: &PKeyRef<Private>,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SignerError> {
        let signing_algorithm = algorithm.signing_algorithm();
        if !matches!(signing_algorithm, SigningAlgorithm::RsaSha256) {
            return Err(SignerError::UnsupportedSigningAlg(signing_algorithm));
        }

        let mut signer = ::openssl::sign::Signer::new(MessageDigest::sha256(), pkey)?;
        signer.update(data.as_ref())?;

        let signature = Signature::new(algorithm, Bytes::from(signer.sign_to_vec()?));

        Ok(signature)
    }

    fn load_key(&self, key_id: &KeyIdentifier) -> Result<OpenSslKeyPair, SignerError> {
        // TODO decrypt key after read
        match self
            .keys_store
            .get(&Key::new_global(Segment::parse_lossy(&key_id.to_string()))) // key_id should always be a valid Segment
        {
            Ok(Some(kp)) => Ok(kp),
            Ok(None) => Err(SignerError::KeyNotFound),
            Err(err) => Err(SignerError::Other(format!("Failed to get key: {}", err))),
        }
    }

    fn remember_key_id(&self, key_id: &KeyIdentifier) -> Result<(), SignerError> {
        // When testing the OpenSSlSigner in isolation there is no need for a mapper as we don't need to determine
        // which signer to use for a particular KeyIdentifier as there is only one signer, and the OpenSslSigner
        // doesn't need a mapper to map from KeyIdentifier to internal key id as the internal key id IS the
        // KeyIdentifier.
        if let Some(mapper) = &self.mapper {
            let readable_handle = self.handle.read().unwrap();
            let signer_handle = readable_handle.as_ref().ok_or_else(|| {
                SignerError::Other("OpenSSL: Failed to record signer key: Signer handle not set".to_string())
            })?;
            mapper
                .add_key(signer_handle, key_id, &format!("{}", key_id))
                .map_err(|err| SignerError::Other(format!("Failed to record signer key: {}", err)))
        } else {
            Ok(())
        }
    }
}

// Implement the functions defined by the `Signer` trait because `SignerProvider` expects to invoke them, but as the
// dispatching is not trait based we don't actually have to implement the `Signer` trait.
impl OpenSslSigner {
    pub fn create_key(&self, _algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        let key_id = self.build_key()?;
        self.remember_key_id(&key_id)?;

        Ok(key_id)
    }

    /// Import an existing RSA key pair from the PEM encoded private key
    pub fn import_key(&self, pem: &str) -> Result<KeyIdentifier, SignerError> {
        let kp = OpenSslKeyPair::from_pem(pem)?;
        let key_id = self.store_key(kp)?;
        self.remember_key_id(&key_id)?;

        Ok(key_id)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<SignerError>> {
        let key_pair = self.load_key(key_id)?;
        Ok(key_pair.subject_public_key_info()?)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        self.keys_store
            .drop_key(&Key::new_global(Segment::parse_lossy(&key_id.to_string()))) // key_id should always be a valid Segment
            .map_err(|_| KeyError::Signer(SignerError::KeyNotFound))
    }

    pub fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SigningError<SignerError>> {
        let key_pair = self.load_key(key_id)?;
        Self::sign_with_key(key_pair.pkey.as_ref(), algorithm, data).map_err(SigningError::Signer)
    }

    pub fn sign_one_off<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: Alg,
        data: &D,
    ) -> Result<(Signature<Alg>, PublicKey), SignerError> {
        let kp = OpenSslKeyPair::build()?;
        let signature = Self::sign_with_key(kp.pkey.as_ref(), algorithm, data)?;
        let key = kp.subject_public_key_info()?;

        Ok((signature, key))
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

        base64::encode(bytes).serialize(s)
    }
}

impl<'de> Deserialize<'de> for OpenSslKeyPair {
    fn deserialize<D>(d: D) -> Result<OpenSslKeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(d) {
            Ok(base64) => Self::from_base64(&base64).map_err(de::Error::custom),
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
        let rsa = self.pkey.rsa().map_err(SignerError::other)?;
        let bytes = Bytes::from(rsa.public_key_to_der().map_err(SignerError::other)?);

        PublicKey::decode(bytes).map_err(SignerError::other)
    }

    /// Can be used to import an existing RSA key pair from
    /// the pem encoded private key.
    pub fn from_pem(pem: &str) -> Result<OpenSslKeyPair, SignerError> {
        PKey::private_key_from_pem(pem.as_bytes())
            .map(|pkey| OpenSslKeyPair { pkey })
            .map_err(|e| SignerError::Other(format!("Invalid private key: {}", e)))
    }

    fn from_base64(base64: &str) -> Result<OpenSslKeyPair, SignerError> {
        let bytes = base64::decode(base64).map_err(|_| SignerError::other("Cannot parse private key base64"))?;

        PKey::private_key_from_der(&bytes)
            .map(|pkey| OpenSslKeyPair { pkey })
            .map_err(|e| SignerError::Other(format!("Invalid private key: {}", e)))
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use crate::test;

    use super::*;

    #[test]
    fn should_return_subject_public_key_info() {
        test::test_in_memory(|storage_uri| {
            let s = OpenSslSigner::build(storage_uri, "dummy", None).unwrap();
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

    #[test]
    fn import_existing_pkcs1_openssl_key() {
        test::test_in_memory(|storage_uri| {
            // The following key was generated using OpenSSL on the command line
            let pem = include_str!("../../../../../test-resources/ta/example-pkcs1.pem");
            let signer = OpenSslSigner::build(storage_uri, "dummy", None).unwrap();

            let ki = signer.import_key(pem).unwrap();
            signer.get_key_info(&ki).unwrap();
            signer.destroy_key(&ki).unwrap();
        })
    }

    #[test]
    fn import_existing_pkcs8_openssl_key() {
        test::test_in_memory(|storage_uri| {
            // The following key was generated using OpenSSL on the command line
            let pem = include_str!("../../../../../test-resources/ta/example-pkcs8.pem");
            let signer = OpenSslSigner::build(storage_uri, "dummy", None).unwrap();

            let ki = signer.import_key(pem).unwrap();
            signer.get_key_info(&ki).unwrap();
            signer.destroy_key(&ki).unwrap();
        })
    }
}
