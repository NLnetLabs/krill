//! Support for signing things using software keys (through openssl) and
//! storing them unencrypted on disk.
use std::{fs::File, ops::Deref};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs, io};

use bytes::Bytes;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use pkcs11::{Ctx, types::*};
use serde::{de, ser};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::crypto::signer::KeyError;
use rpki::crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError};

//------------ OpenSslSigner -------------------------------------------------

/// An openssl based signer.
#[derive(Clone, Debug)]
pub struct OpenSslSigner {
    keys_dir: Arc<Path>,
}

impl OpenSslSigner {
    pub fn build(work_dir: &Path) -> Result<Self, SignerError> {
        let meta_data = fs::metadata(&work_dir)?;
        if meta_data.is_dir() {
            let mut keys_dir = work_dir.to_path_buf();
            keys_dir.push("keys");
            if !keys_dir.is_dir() {
                fs::create_dir_all(&keys_dir)?;
            }

            Ok(OpenSslSigner {
                keys_dir: keys_dir.into(),
            })
        } else {
            Err(SignerError::InvalidWorkDir(work_dir.to_path_buf()))
        }
    }
}

impl OpenSslSigner {
    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(pkey: &PKeyRef<Private>, data: &D) -> Result<Signature, SignerError> {
        let mut signer = ::openssl::sign::Signer::new(MessageDigest::sha256(), pkey)?;
        signer.update(data.as_ref())?;

        let signature = Signature::new(SignatureAlgorithm::default(), Bytes::from(signer.sign_to_vec()?));

        Ok(signature)
    }

    fn load_key(&self, id: &KeyIdentifier) -> Result<OpenSslKeyPair, SignerError> {
        let path = self.key_path(id);
        if path.exists() {
            let f = File::open(path)?;
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
}

impl Signer for OpenSslSigner {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&mut self, _algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let kp = OpenSslKeyPair::build()?;

        let pk = &kp.subject_public_key_info()?;
        let key_id = pk.key_identifier();

        let path = self.key_path(&key_id);
        let json = serde_json::to_string(&kp)?;

        let mut f = File::create(path)?;
        f.write_all(json.as_ref())?;

        Ok(key_id)
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let key_pair = self.load_key(key_id)?;
        Ok(key_pair.subject_public_key_info()?)
    }

    fn destroy_key(&mut self, key_id: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
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
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        let key_pair = self.load_key(key_id)?;
        Self::sign_with_key(key_pair.pkey.as_ref(), data).map_err(SigningError::Signer)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        let kp = OpenSslKeyPair::build()?;

        let signature = Self::sign_with_key(kp.pkey.as_ref(), data)?;

        let key = kp.subject_public_key_info()?;

        Ok((signature, key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
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

//------------ OpenSslKeyError -----------------------------------------------

#[derive(Debug)]
pub enum SignerError {
    OpenSslError(ErrorStack),
    JsonError(serde_json::Error),
    InvalidWorkDir(PathBuf),
    IoError(io::Error),
    KeyNotFound,
    DecodeError,
    Pkcs11Error(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignerError::OpenSslError(e) => write!(f, "OpenSsl Error: {}", e),
            SignerError::JsonError(e) => write!(f, "Could not decode public key info: {}", e),
            SignerError::InvalidWorkDir(path) => write!(f, "Invalid base path: {}", path.to_string_lossy()),
            SignerError::IoError(e) => e.fmt(f),
            SignerError::KeyNotFound => write!(f, "Could not find key"),
            SignerError::DecodeError => write!(f, "Could not decode key"),
            SignerError::Pkcs11Error(e) => write!(f, "PKCS#11 error: {}", e),
        }
    }
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

//------------ Pkcs11Signer --------------------------------------------------

#[derive(Clone, Debug)]
struct Pkcs11Ctx {
    ctx: Arc<Ctx>
}

impl Pkcs11Ctx {
    pub fn new(lib_path: &Path) -> Result<Self, SignerError> {
        let mut ctx = Ctx::new(lib_path)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to create context: {}", err)))?;

        // TODO: are these arg values okay?
        let mut args = CK_C_INITIALIZE_ARGS::new();
        args.CreateMutex = None;
        args.DestroyMutex = None;
        args.LockMutex = None;
        args.UnlockMutex = None;
        args.flags = CKF_OS_LOCKING_OK;
        ctx.initialize(Some(args))
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to initialize: {}", err)))?;

        let ctx = Arc::new(ctx);

        Ok(Pkcs11Ctx { ctx })
    }
}

impl Deref for Pkcs11Ctx {
    type Target = Ctx;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl Drop for Pkcs11Ctx {
    fn drop(&mut self) {
        trace!("Finalizing PKCS#11 connection..");
        if let Some(ctx) = Arc::get_mut(&mut self.ctx) {
            if let Err(err) = ctx.finalize() {
                warn!("Failed to finalize PKCS#11 application: {}", err);
            }
        } else {
            warn!("Failed to finalize PKCS#11 application: Unable to get mutable access to the context");
        }
    }
}

#[derive(Clone, Debug)]
struct Pkcs11Session {
    ctx: Pkcs11Ctx,
    handle: CK_SESSION_HANDLE
}

impl Pkcs11Session {
    pub fn new(ctx: Pkcs11Ctx, slot_id: CK_SLOT_ID) -> Result<Self, SignerError> {
        let handle = ctx.open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to open session: {}", err)))?;
        Ok(Self { ctx, handle })
    }
}

impl Deref for Pkcs11Session {
    type Target = CK_SESSION_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        trace!("Finalizing PKCS#11 connection..");
        if let Err(err) = self.ctx.close_session(self.handle) {
            warn!("Failed to close PKCS#11 session: {}", err);
        }
    }
}

/// A PKCS#11 based signer.
#[derive(Clone, Debug)]
pub struct Pkcs11Signer {
    ctx: Pkcs11Ctx,
    login_session: Pkcs11Session,
    slot_id: CK_SLOT_ID,
}

impl Pkcs11Signer {
    pub fn build(lib_path: &Path, pin: &str, slot_id: u64) -> Result<Self, SignerError> {
        let ctx = Pkcs11Ctx::new(lib_path)?;
        let slot_id: CK_SLOT_ID = slot_id;
        let login_session = Pkcs11Session::new(ctx.clone(), slot_id)?;

        ctx.login(*login_session, CKU_USER, Some(pin))
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to login: {}", err)))?;
    
        Ok(Pkcs11Signer { ctx, login_session, slot_id })
    }

    fn open_session(&self) -> Result<Pkcs11Session, SignerError> {
        Pkcs11Session::new(self.ctx.clone(), self.slot_id)
    }
}

impl Signer for Pkcs11Signer {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    // Currently results in PKCS#11: CKR_USER_NOT_LOGGED_IN (0x101)
    fn create_key(&mut self, _algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

        let mut key_id: [u8; 4] = [0; 4];
        openssl::rand::rand_bytes(&mut key_id).map_err(SignerError::OpenSslError)?;
        // let key_id = libc::rand::random::<[u8; 4]>();
        let mech = CK_MECHANISM {
            mechanism: pkcs11::types::CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut priv_template: Vec<CK_ATTRIBUTE> = Vec::new();
        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();

        priv_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_SIGN).with_bool(&pkcs11::types::CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(&key_id));
        priv_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_TOKEN).with_bool(&pkcs11::types::CK_TRUE));
    
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_VERIFY).with_bool(&pkcs11::types::CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ID).with_bytes(&key_id));
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_PUBLIC_EXPONENT).with_bytes(&PUBLIC_EXPONENT));
        pub_template.push(CK_ATTRIBUTE::new(pkcs11::types::CKA_MODULUS_BITS).with_ck_ulong(&1024));
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_TOKEN).with_bool(&pkcs11::types::CK_TRUE));
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_PRIVATE).with_bool(&pkcs11::types::CK_FALSE));
        pub_template
            .push(CK_ATTRIBUTE::new(pkcs11::types::CKA_ENCRYPT).with_bool(&pkcs11::types::CK_TRUE));

        let param = [CKM_RSA_PKCS];
        let mut allowed_mechanisms_attr = CK_ATTRIBUTE::new(CKA_ALLOWED_MECHANISMS);
        allowed_mechanisms_attr.ulValueLen = ::std::mem::size_of::<CK_MECHANISM_TYPE>() as u64; // is as safe here?
        allowed_mechanisms_attr.pValue = &param as *const CK_MECHANISM_TYPE as CK_VOID_PTR;

        pub_template.push(allowed_mechanisms_attr);
        priv_template.push(allowed_mechanisms_attr);

        let session = self.open_session()?;
        self.ctx.generate_key_pair(*session, &mech, &pub_template, &priv_template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to create key: {}", err)))?;

        // let mut b = Bytes::from(self.pkey.rsa().unwrap().public_key_to_der()?);
        // PublicKey::decode(&mut b).map_err(|_| SignerError::DecodeError)

        // Ok(key_id)
        Err(SignerError::Pkcs11Error("get_key_info: not implemented".to_string()))
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        Err(KeyError::Signer(SignerError::Pkcs11Error("get_key_info: not implemented".to_string())))
    }

    fn destroy_key(&mut self, key_id: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        Err(KeyError::Signer(SignerError::Pkcs11Error("destroy_key: not implemented".to_string())))
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        Err(SigningError::Signer(SignerError::Pkcs11Error("sign: not implemented".to_string())))
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        Err(SignerError::Pkcs11Error("sign_one_off: not implemented".to_string()))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        Err(SignerError::Pkcs11Error("rand: not implemented".to_string()))
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
            let mut s = OpenSslSigner::build(&d).unwrap();
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
