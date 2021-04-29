//! Support for signing things using software keys (through openssl) and
//! storing them unencrypted on disk.
use std::{fs::File, io::Read, ops::Deref, sync::atomic::{AtomicU8, Ordering}};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs, io};

use bcder::guide::encode;
use bytes::Bytes;
use once_cell::sync::OnceCell;
use openssl::{error::ErrorStack, sign};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use pkcs11::{Ctx, types::*};
use serde::{de, ser};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rpki::crypto::signer::KeyError;
use rpki::crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError};

use crate::constants::test_mode_enabled;

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

static ONE_CTX: OnceCell<Arc<Ctx>> = OnceCell::new();
static CTX_REF_COUNT: AtomicU8 = AtomicU8::new(0);

#[derive(Debug)]
struct Pkcs11Ctx {
    ctx: Arc<Ctx>
}

impl Pkcs11Ctx {
    pub fn new(lib_path: &Path) -> Result<Self, SignerError> {
        let ctx = ONE_CTX.get_or_try_init(|| -> Result<Arc<Ctx>, SignerError> {
            info!("PKCS#11: Initializing");

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
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to initialize context: {}", err)))?;

            Ok(Arc::new(ctx))
        })?;

        Ok(Pkcs11Ctx { ctx: ctx.clone() })
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
        if CTX_REF_COUNT.fetch_sub(1, Ordering::SeqCst) == 1 {
            trace!("PKCS#11: Finalizing context..");
            if let Some(ctx) = Arc::get_mut(&mut self.ctx) {
                if let Err(err) = ctx.finalize() {
                    warn!("PKCS#11: Failed to finalize context: {}", err);
                }
            } else {
                warn!("PKCS#11: Failed to finalize context: Internal error: Could not acquire mutable reference");
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Pkcs11Session {
    ctx: Arc<Pkcs11Ctx>,
    handle: CK_SESSION_HANDLE,
    logged_in: bool,
}

impl Pkcs11Session {
    pub fn new(ctx: Arc<Pkcs11Ctx>, slot_id: CK_SLOT_ID) -> Result<Self, SignerError> {
        // PKCS#11 v2.21: "For legacy reasons, the CKF_SERIAL_SESSION bit must always be set"
        let handle = ctx.open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to open PKCS#11 session: {}", err)))?;
        Ok(Self { ctx, handle, logged_in: false })
    }

    fn login(&mut self, user: CK_USER_TYPE, pin: Option<&str>) -> Result<(), SignerError> {
        info!("PKCS#11: Logging in");
        self.ctx.login(self.handle, user, pin)
            .or_else(|err| {
                if matches!(err, pkcs11::errors::Error::Pkcs11(CKR_USER_ALREADY_LOGGED_IN)) && test_mode_enabled() {
                    warn!("PKCS#11: Ignoring error CKR_USER_ALREADY_LOGGED_IN because test mode is enabled");
                    return Ok(());
                }
                Err(err)
            })
            .map_err(|err| SignerError::Pkcs11Error(format!("Login failed: {}", err)))?;
        self.logged_in = true;
        Ok(())
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
        trace!("PKCS#11: Auto-closing session");
        if self.logged_in {
            debug!("PKCS#11: Session being closed is a login session, logging out");
            if let Err(err) = self.ctx.logout(self.handle) {
                warn!("PKCS#11: Logout failed: {}", err);
            }
            self.logged_in = false;
        }
        if let Err(err) = self.ctx.close_session(self.handle) {
            warn!("PKCS#11: Close session failed: {}", err);
        }
    }
}

/// A PKCS#11 based signer.
#[derive(Clone, Debug)]
pub struct Pkcs11Signer {
    ctx: Arc<Pkcs11Ctx>,
    login_session: Pkcs11Session,
    slot_id: CK_SLOT_ID,
}

impl Pkcs11Signer {
    pub fn build(lib_path: &Path, pin: &str, slot_id: u64) -> Result<Self, SignerError> {
        let ctx = Arc::new(Pkcs11Ctx::new(lib_path)?);
        let slot_id: CK_SLOT_ID = slot_id;
        let mut login_session = Pkcs11Session::new(ctx.clone(), slot_id)?;

        login_session.login(CKU_USER, Some(pin))?;

        Ok(Pkcs11Signer { ctx, login_session, slot_id })
    }

    fn open_session(&self) -> Result<Pkcs11Session, SignerError> {
        Pkcs11Session::new(self.ctx.clone(), self.slot_id)
    }

    fn get_public_key_from_handle(&self, pub_handle: u64) -> Result<PublicKey, SignerError> {
        let session = self.open_session()?;

        // Modern strategy for acquiring the SPKI:
        // =======================================
        // PKCS#11 2.40+ supports a public key attribute called CKA_PUBLIC_KEY_INFO which yields a byte array of the DER
        // encoded SubjectPublicKeyInfo so this is ideal. However, tokens that implement older PKCS#11 standard versions
        // don't support it, and even in compatible implementations the attribute is allowed to be empty (and in testing
        // with SoftHSMv2 it is empty for example). So, first, try to get this attribute and use it:

        // TODO: Factor out initial attribute length lookup and actual attribute value fetch to helper function
        // TODO: Add trace and debug level logging to indicate when the HSM is being queried and which logic path is
        // being followed.

        // Construct it from the modulus and exponent of the public key. These are available via CKA_ key attributes,
        // but again these might be empty. If we can't get the exponent we can assume that it is the value we requested
        // that it should be. There's no way we can work around not being able to get the modulus however.

        trace!("PKCS#11: Generating SubjectPublicKeyInfo using RSA modulus and public exponent key attributes");

        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT));
        let (_, res_vec) = self.ctx.get_attribute_value(*session, pub_handle, &mut pub_template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to get modulus and/or public exponent lengths: {}", err)))?;

        let mut modulus = Vec::with_capacity(res_vec[0].ulValueLen as usize);
        let mut public_exp = Vec::with_capacity(res_vec[1].ulValueLen as usize);
        modulus.resize(res_vec[0].ulValueLen as usize, 0);
        public_exp.resize(res_vec[1].ulValueLen as usize, 0);
        pub_template.clear();
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS).with_bytes(modulus.as_mut_slice()));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(public_exp.as_mut_slice()));
        let (_, res_vec) = self.ctx.get_attribute_value(*session, pub_handle, &mut pub_template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to get modulus and/or public exponent value: {}", err)))?;

        // TODO: use the input exponent value from the top of this function if we got a zero length exponent attribute
        // value back from the PKCS#11 interface.

        // TODO: work out how to encode the fetched values as a DER format SPKI for passing to PublicKey::decode().

        // From: https://tools.ietf.org/html/rfc5280#section-4.1 Internet X.509 Public Key Infrastructure
        //       Certificate and Certificate Revocation List (CRL) ProfileBasic Certificate Fields
        //
        //     SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //         algorithm              AlgorithmIdentifier,
        //         subjectPublicKey       BIT STRING  }
        //
        //     AlgorithmIdentifier   ::=  SEQUENCE  {
        //         algorithm              OBJECT IDENTIFIER,
        //         parameters             ANY DEFINED BY algorithm OPTIONAL  }
        // 
        // The subjectPublicKey bit string is a DER encoding of the following ASN.1 definition:
        //
        //     RSAPublicKey          ::= SEQUENCE {
        //         modulus               INTEGER, -- n
        //         publicExponent        INTEGER -- e
        //     }
        //
        // We have the algorithm (aka PublicKeyFormat struct), modulus and publicExponent values but we have no way
        // to construct a PublicKey struct (aka SubjectPublicKeyInfo) from them. One way to do this is to transform
        // the PKCS#11 "Big Integer" modulus and publicExponent byte array values into a DER encoded ASN.1 sequence
        // hierarchy as described above, and use PublicKey::decode() to then create the PublicKey struct instance
        // that we need.
        //
        // From the PKCS#11 2.20 spec:
        //
        //   "Big integer a string of CK_BYTEs representing an unsigned integer of arbitrary size, most-significant
        //    byte first (e.g., the integer 32768 is represented as the 2-byte string 0x80 0x00)"
        //
        // We need to encode this as an ASN.1 INTEGER.

        let algorithm = PublicKeyFormat::Rsa;

        use crate::bcder::encode::PrimitiveContent; // for .encode()
        let modulus = bcder::Unsigned::from_slice(modulus);
        let public_exp = bcder::Unsigned::from_slice(public_exp);

        let rsa_public_key = bcder::encode::sequence(( modulus.encode(), public_exp.encode() ));

        use crate::bcder::encode::Values; // for .write_encoded()
        let mut rsa_public_key_bytes: Vec<u8> = Vec::new();
        rsa_public_key.write_encoded(bcder::Mode::Der, &mut rsa_public_key_bytes)
            .map_err(|err| SignerError::Pkcs11Error(
                format!("Failed to create DER encoded RSAPublicKey from constituent parts: {}", err)))?;

        let subject_public_key = bcder::BitString::new(0, bytes::Bytes::from(rsa_public_key_bytes));

        let subject_public_key_info = bcder::encode::sequence(( algorithm.encode(), subject_public_key.encode() ));

        let mut subject_public_key_info_source: Vec<u8> = Vec::new();
        subject_public_key_info.write_encoded(bcder::Mode::Der, &mut subject_public_key_info_source)
            .map_err(|err| SignerError::Pkcs11Error(
                format!("Failed to create DER encoded SubjectPublicKeyInfo from constituent parts: {}", err)))?;

        let public_key = PublicKey::decode(subject_public_key_info_source.as_slice())
            .map_err(|err| SignerError::Pkcs11Error(
                format!("Failed to create public key from the DER encoded SubjectPublicKeyInfo: {}", err)))?;

        Ok(public_key)
    }

    fn find_key(&self, key_id: &KeyIdentifier, key_class: CK_OBJECT_CLASS) -> Result<CK_OBJECT_HANDLE, KeyError<SignerError>> {
        let session = self.open_session()?;

        let human_key_class = match key_class {
            CKO_PUBLIC_KEY => "public key",
            CKO_PRIVATE_KEY => "private key",
            _ => "key"
        };
        
        trace!("PKCS#11: Finding key handle for {} with ID {}", &human_key_class, &key_id);

        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        template.push(CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&key_class));
        template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_id.as_slice()));

        self.ctx.find_objects_init(*session, &template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to initialize find for {} with id {}: {}", &human_key_class, &key_id, err)))?;

        let max_object_count = 2;
        let res = self.ctx.find_objects(*session, max_object_count)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to perform find for {} with id {}: {}", &human_key_class, &key_id, err)));
        let res = match res {
            Err(err) => {
                self.ctx.find_objects_final(*session)
                    .map_err(|err2| KeyError::Signer(SignerError::Pkcs11Error(format!("Failed to finalize find for {} with id {}: {} (after find failed with error: {}", &human_key_class, &key_id, err2, err))))?;
                Err(KeyError::Signer(err))
            }
            Ok(results) => match results.len() {
                0 => Err(KeyError::KeyNotFound),
                1 => Ok(results[0]),
                _ => Err(KeyError::Signer(SignerError::Pkcs11Error(format!("More than one {} found with id {}", &human_key_class, &key_id))))
            }
        };

        if let Err(err) = self.ctx.find_objects_final(*session)
            .map_err(|err| KeyError::Signer(SignerError::Pkcs11Error(
                format!("Failed to finalize find for {} with id {}: {}", &human_key_class, &key_id, err)))) {
            warn!("PKCS#11: {}", err);
        }

        res
    }

    fn build_key(&self, algorithm: PublicKeyFormat) -> Result<(PublicKey, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), SignerError> {
        // https://tools.ietf.org/html/rfc6485#section-3: Asymmetric Key Pair Formats
        //   "The RSA key pairs used to compute the signatures MUST have a 2048-bit
        //    modulus and a public exponent (e) of 65,537."

        if !matches!(algorithm, PublicKeyFormat::Rsa) {
            return Err(SignerError::Pkcs11Error(
                format!("Algorithm {:?} not supported while creating key", &algorithm)));
        }

        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
        pub_template.push(CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(&2048));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(&[0x01, 0x00, 0x01]));
        pub_template.push(CK_ATTRIBUTE::new(CKA_LABEL).with_string("Krill"));

        let mut priv_template: Vec<CK_ATTRIBUTE> = Vec::new();
        priv_template.push(CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_LABEL).with_string("Krill"));

        let param = [CKM_SHA256_RSA_PKCS];
        let mut allowed_mechanisms_attr = CK_ATTRIBUTE::new(CKA_ALLOWED_MECHANISMS);
        allowed_mechanisms_attr.ulValueLen = ::std::mem::size_of::<CK_MECHANISM_TYPE>() as u64; // TODO: is 'as' safe?
        allowed_mechanisms_attr.pValue = &param as *const CK_MECHANISM_TYPE as CK_VOID_PTR;

        pub_template.push(allowed_mechanisms_attr);
        priv_template.push(allowed_mechanisms_attr);

        trace!("PKCS#11: Generating key pair with templates: public key={:?}, private key={:?}",
            &pub_template, &priv_template);

        let session = self.open_session()?;
        let (pub_handle, priv_handle) = self.ctx.generate_key_pair(*session, &mech, &pub_template, &priv_template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to create key: {}", err)))?;

        // TODO: if we encounter an error from this point on should we delete the keys that we just created?
            
        let public_key = self.get_public_key_from_handle(pub_handle)?;
        let key_identifier = public_key.key_identifier();
        
        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_identifier.as_slice()));
        self.ctx.set_attribute_value(*session, pub_handle, &template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to set attributes on public key: {}", err)))?;
        self.ctx.set_attribute_value(*session, priv_handle, &template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to set attributes on private key: {}", err)))?;

        debug!("PKCS#11: Generated key pair with ID {}", key_identifier);

        Ok((public_key, pub_handle, priv_handle))
    }

    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(
        &self,
        priv_handle: CK_OBJECT_HANDLE,
        algorithm: SignatureAlgorithm,
        data: &D
    ) -> Result<Signature, SignerError> {
        debug!("PKCS#11: Signing");

        if algorithm.public_key_format() != PublicKeyFormat::Rsa {
            return Err(SignerError::Pkcs11Error(
                format!("Algorithm public key format not supported for signing: {:?}", algorithm.public_key_format())));
        }

        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let session = self.open_session()?;
        self.ctx.sign_init(*session, &mech, priv_handle)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to initialize sign: {}", err)))?;

        let signed = self.ctx.sign(*session, data.as_ref())
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to sign: {}", err)))?;

            
        let sig = Signature::new(SignatureAlgorithm::default(), Bytes::from(signed));

        // temporarily for testing purposes log some data we can use to verify that signing is working correctly:
        //   (plus we also log the key identifier in the caller fn sign())
        // error!("XIMON: data to sign: {}", hex::encode(data));
        // error!("XIMON: signed data : {}", hex::encode(&signed));
        // error!("XIMON: signature   : {}", hex::encode(sig.value()));
        // with these values we can copy paste the hex data into files and use this command to convert it back to
        // binary:
        //   $ xxd -r -p <input hex file> <output binary file>
        // then we can export the public key from SoftHSMv2 with this command:
        //   $ pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -p <USER_PIN> --read-object --type pubkey \
        //       --id <SIGNING KEY ID> -o /tmp/key.pub
        // then we can verify that the data was signed correctly with this command:
        //   $ openssl dgst -verify /tmp/key.pub -keyform DER -sha256 -signature /tmp/sig.bin -binary /tmp/in.bin
        //     Verified OK

        Ok(sig)
    }
}

impl Signer for Pkcs11Signer {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    // TODO: extend the fn signature to accept a context string, e.g. CA name, to label the key with?
    fn create_key(&mut self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let (key, _, _) = self.build_key(algorithm)?;
        Ok(key.key_identifier())
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let pub_handle = self.find_key(key_id, CKO_PUBLIC_KEY)?;
        self.get_public_key_from_handle(pub_handle).map_err(|err| KeyError::Signer(err))
    }

    fn destroy_key(&mut self, key_id: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        debug!("PKCS#11: Deleting key pair with ID {}", &key_id);
        
        let session = self.open_session()?;

        if let Ok(pub_handle) = self.find_key(key_id, CKO_PUBLIC_KEY) {
            self.ctx.destroy_object(*session, pub_handle)
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to delete public key: {}", err)))?;
        }

        if let Ok(priv_handle) = self.find_key(key_id, CKO_PRIVATE_KEY) {
            self.ctx.destroy_object(*session, priv_handle)
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to delete private key: {}", err)))?;
        }

        Ok(())
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        let priv_handle = self.find_key(key_id, CKO_PRIVATE_KEY)
            .map_err(|err| match err {
                KeyError::KeyNotFound => SigningError::KeyNotFound,
                KeyError::Signer(err) => SigningError::Signer(err),
            })?;

        error!("XIMON: sign with key id: {}", &key_id);

        self.sign_with_key(priv_handle, algorithm, data)
            .map_err(|err| SigningError::Signer(err))
    }
 
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        let (key, _, priv_handle) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature = self.sign_with_key(priv_handle, algorithm, data.as_ref())?;

        Ok((signature, key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        let session = self.open_session()?;
        let random_value = self.ctx.generate_random(*session, target.len() as CK_ULONG)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to generate random value: {}", err)))?;
        target.copy_from_slice(random_value.as_slice());
        Ok(())
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
