//! Support for signing things using software keys (through openssl) and
//! storing them unencrypted on disk.
use std::{fs, io};
use std::path::PathBuf;
use bytes::Bytes;
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, PKeyRef, Private};
use rpki::crypto::{
    Signature,
    SignatureAlgorithm,
    Signer,
    SigningError,
    PublicKey,
    PublicKeyFormat
};
use rpki::crypto::signer::KeyError;
use serde::{de, ser};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::Write;


//------------ SignerKeyId ---------------------------------------------------

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

impl Serialize for SignerKeyId {
    fn serialize<S>(
        &self,
        serializer: S
    ) -> Result<S::Ok, S::Error> where S: Serializer {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignerKeyId {
    fn deserialize<D>(
        deserializer: D
    ) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        Ok(SignerKeyId::new(&s))
    }
}


//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
///
/// Keeps the keys in memory (for now).
#[derive(Clone, Debug)]
pub struct OpenSslSigner {
    keys_dir: PathBuf
}

impl OpenSslSigner {
    pub fn build(work_dir: &PathBuf) -> Result<Self, SignerError> {
        let meta_data = fs::metadata(&work_dir)?;
        if meta_data.is_dir() {

            let mut keys_dir = PathBuf::from(work_dir);
            keys_dir.push("keys");
            if ! keys_dir.is_dir() {
                fs::create_dir_all(&keys_dir)?;
            }

            Ok(OpenSslSigner { keys_dir } )
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

    fn load_key(&self, id: &SignerKeyId) -> Result<OpenSslKeyPair, SignerError> {
        let path = self.key_path(id);
        if path.exists() {
            let f = File::open(path)?;
            let kp: OpenSslKeyPair = serde_json::from_reader(f)?;
            Ok(kp)
        } else {
            Err(SignerError::KeyNotFound)
        }

    }

    fn key_path(&self, key_id: &SignerKeyId) -> PathBuf {
        let mut path = self.keys_dir.clone();
        path.push(key_id.as_ref());
        path
    }
}

impl Signer for OpenSslSigner {

    type KeyId = SignerKeyId;
    type Error = SignerError;

    fn create_key(
        &mut self,
        _algorithm: PublicKeyFormat
    ) -> Result<Self::KeyId, Self::Error> {
        let kp = OpenSslKeyPair::build()?;

        let pk = &kp.subject_public_key_info()?;
        let hex_hash = hex::encode(pk.key_identifier().as_ref());
        let key_id = SignerKeyId(hex_hash);

        let path = self.key_path(&key_id);
        let json = serde_json::to_string(&kp)?;

        let mut f = File::create(path)?;
        f.write_all(json.as_ref())?;

        Ok(key_id)
    }

    fn get_key_info(
        &self,
        key_id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        let key_pair = self.load_key(key_id)?;
        Ok(key_pair.subject_public_key_info()?)
    }

    fn destroy_key(
        &mut self,
        key_id: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {
        let path = self.key_path(key_id);
        if path.exists() {
            fs::remove_file(path).map_err(SignerError::IoError)?;
        }
        Ok(())
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<Signature, SigningError<Self::Error>> {
        let key_pair = self.load_key(key_id)?;
        Self::sign_with_key(key_pair.pkey.as_ref(), data)
            .map_err(|e| { SigningError::Signer(e)})
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<(Signature, PublicKey), SignerError> {
        let kp = OpenSslKeyPair::build()?;

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
    fn build() -> Result<OpenSslKeyPair, SignerError> {
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
        Ok(PublicKey::decode(&mut b).map_err(|_| SignerError::DecodeError)?)
    }
}


//------------ OpenSslKeyError -----------------------------------------------

#[derive(Debug, Display)]
pub enum SignerError {
    #[display(fmt = "OpenSsl Error: {}", _0)]
    OpenSslError(ErrorStack),

    #[display(fmt = "Could not decode public key info: {}", _0)]
    JsonError(serde_json::Error),

    #[display(fmt = "Invalid base path: {:?}", _0)]
    InvalidWorkDir(PathBuf),

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "Could not find key")]
    KeyNotFound,

    #[display(fmt = "Could not decode key")]
    DecodeError,
}

impl From<ErrorStack> for SignerError {
    fn from(e: ErrorStack) -> Self {
        SignerError::OpenSslError(e)
    }
}

impl From<serde_json::Error> for SignerError {
    fn from(e: serde_json::Error) -> Self {
        SignerError::JsonError(e)
    }
}

impl From<io::Error> for SignerError {
    fn from(e: io::Error) -> Self {
        SignerError::IoError(e)
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
            let mut s = OpenSslSigner::build(&d).unwrap();
            let ki = s.create_key(PublicKeyFormat).unwrap();
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
