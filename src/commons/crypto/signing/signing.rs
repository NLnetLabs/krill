//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
#[cfg(feature = "hsm")]
use std::{collections::HashMap, fs::OpenOptions, path::{PathBuf}, str::FromStr};
use std::path::Path;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::convert::TryFrom;
use std::ops::DerefMut;
#[cfg(feature = "hsm")]
use std::fs::File;
#[cfg(feature = "hsm")]
use std::io::{prelude::*, BufReader};

use bytes::Bytes;

use rpki::repository::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::repository::crl::{Crl, CrlEntry, TbsCertList};
use rpki::repository::crypto::{DigestAlgorithm, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer};
use rpki::repository::csr::Csr;
use rpki::repository::manifest::{FileAndHash, Manifest, ManifestContent};
use rpki::repository::roa::{Roa, RoaBuilder};
use rpki::repository::sigobj::SignedObjectBuilder;
use rpki::repository::x509::{Name, Serial, Time, Validity};
use rpki::repository::rta;
use rpki::uri;

use crate::{commons::api::{IssuedCert, RcvdCert, ReplacedObject, RepoInfo, RequestResourceLimit, ResourceSet}, daemon::config::Config};
#[cfg(feature = "hsm")]
use crate::daemon::config::SignerType;
#[cfg(feature = "hsm")]
use crate::commons::crypto::signing::{Pkcs11Signer, KmipSigner};
use crate::commons::crypto::{self, CryptoResult};
use crate::commons::error::Error;
use crate::commons::util::AllowedUri;
use crate::commons::KrillResult;
use crate::daemon::ca::CertifiedKey;

use super::{SignerError, ConfigSignerOpenSsl, OpenSslSigner};

const OPENSSL_DEFAULT_SIGNER_NAME: &str = "OpenSSL";

//------------ KeyMeta -------------------------------------------------------


#[cfg(not(feature = "hsm"))]
#[derive(Debug, Clone)]
pub struct KeyMap { }

#[cfg(not(feature = "hsm"))]
impl KeyMap {
    pub fn persistent(_data_dir: &Path) -> KrillResult<Self> {
        Ok(Self { })
    }

    pub fn in_memory() -> KrillResult<Self> {
        Ok(Self { })
    }

    pub fn add_key(&self, _signer_name: &str, _key_id: KeyIdentifier, _key_handle: &[u8]) {
        // NOOP
    }

    pub fn get_key(&self, _signer_name: &str, key_id: &KeyIdentifier) -> Result<Vec<u8>, SignerError> {
        // When the HSM feature is disabled we only have the OpenSSL signer which uses the KeyIdentifier as the key id
        Ok(key_id.as_slice().to_vec())
    }

    pub fn get_signer_name_for_key(&self, _key_id: &KeyIdentifier) -> CryptoResult<String> {
        // When the HSM feature is disabled we only have the OpenSSL signer.
        Ok(OPENSSL_DEFAULT_SIGNER_NAME.to_string())
    }
}

#[cfg(feature = "hsm")]
type SignerName = String;

#[cfg(feature = "hsm")]
#[derive(Debug, Clone)]
struct KeyInfo{ key_handle: Vec<u8>, signer_name: SignerName }

#[cfg(feature = "hsm")]
#[derive(Debug, Clone)]
pub struct KeyMap {
    db_path: Option<PathBuf>,

    keys: Arc<RwLock<HashMap<KeyIdentifier, KeyInfo>>>,
}

#[cfg(feature = "hsm")]
impl KeyMap {
    pub fn persistent(data_dir: &Path) -> KrillResult<Self> {
        let db_path = data_dir.join("keys/map.db");
        debug!("Opening key map database at '{}'", &db_path.display());
        Self::init(Some(db_path))
    }

    pub fn in_memory() -> KrillResult<Self> {
        Self::init(None)
    }

    fn init(db_path: Option<PathBuf>) -> KrillResult<Self> {
        trace!("Initializing signer mappings");

        let mut keys = HashMap::new();

        if let Some(ref db_path) = db_path {
            trace!("Opening signer mapping database '{}'", db_path.display());

            if let Ok(file) = File::open(db_path) {
                let reader = BufReader::new(file);

                for line in reader.lines() {
                    // PoC line format: <signer_name><comma><hex key_identifer><comma><hex key handle>
                    // TODO: Prefix the line with a time date field for when the key was created.
                    let line = line.map_err(|err| Error::SignerError(
                        format!("Failed to read line from database file: {}", err)))?;
                    trace!("Read signer mapping database line: {}", &line);

                    let mut fields_iter = line.split(',');
                    let signer_name = fields_iter.next();
                    let hex_key_id = fields_iter.next();
                    let hex_key_handle = fields_iter.next();

                    if let (Some(signer_name), Some(hex_key_id), Some(hex_key_handle)) = (signer_name, hex_key_id, hex_key_handle) {
                        let signer_name = signer_name.to_string();
                        let key_id = KeyIdentifier::from_str(hex_key_id)
                            .map_err(|err| Error::SignerError(
                                format!("Failed to parse hex key identifier from database file: {}", err)))?;
                        let key_handle = hex::decode(hex_key_handle)
                            .map_err(|err| Error::SignerError(
                                format!("Failed to parse hex key handle from database file: {}", err)))?;
        
                        // TODO: Use an index into a vector of signer names instead of cloning the signer name for each
                        // record.
                        let key_info = KeyInfo { key_handle, signer_name: signer_name.clone() };
                        if keys.insert(key_id.clone(), key_info).is_some() {
                            return Err(Error::SignerError("Duplicate key while restoring keys lookup table".to_string()));
                        }
                    } else {
                        return Err(Error::SignerError("Failed to parse database file line".to_string()));
                    }
                }
            }
        }

        let keys = Arc::new(RwLock::new(keys));
    
        Ok(Self { db_path, keys })
    }

    fn add_and_flush(
        &self,
        signer_name: String,
        key_id: KeyIdentifier,
        key_handle: &[u8]
    )-> Result<(), SignerError> {
        let hex_key_id = hex::encode_upper(key_id.as_slice());
        let hex_key_handle = hex::encode_upper(&key_handle);
        let key_handle = key_handle.to_vec();
        let key_info = KeyInfo { key_handle, signer_name: signer_name.clone() };

        let mut keys = self.keys.write()
            .map_err(|err| SignerError::KeyMapError(format!("Failed to lock keys map for writing: {}", err)))?;

        if keys.insert(key_id.clone(), key_info).is_some() {
            return Err(SignerError::KeyMapError("Duplicate key while inserting into keys lookup table".to_string()));
        }

        if let Some(db_path) = &self.db_path {
            // Determine the parent directory of the where we will create the key map database file
            let parent_dir = db_path
                .parent()
                .ok_or(SignerError::KeyMapError(
                    format!("Failed ot open key map database '{}': Path has no parent!", db_path.display())))?;

            // Create the parent directory if not existing
            std::fs::create_dir_all(parent_dir)
                .map_err(|err| SignerError::KeyMapError(
                    format!("Failed to open key map database '{}': Cannot create parent directory: {}", db_path.display(), err)))?;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(db_path)
                .map_err(|err| SignerError::KeyMapError(
                    format!("Failed to open key map database '{}': {}", db_path.display(), err)))?;

            write!(file, "{},{},{}\n", signer_name, hex_key_id, hex_key_handle)
                .map_err(|err| SignerError::KeyMapError(
                    format!("Failed to append to key map database '{}': {}", db_path.display(), err)))?;
        }

        Ok(())
    }

    pub fn add_key(&self, signer_name: &str, key_id: KeyIdentifier, key_handle: &[u8]) {
        trace!("Add key {} for signer {}", &key_id, signer_name);

        if let Err(err) = self.add_and_flush(signer_name.to_string(), key_id.clone(), key_handle) {
            // Abort Krill because if we cannot write the key mapping record completely to disk we will never be
            // able to sign with this key or show in the history which signer this key was used with.
            panic!("Failed to add key {} to key map: {}", key_id, err);
        }
    }

    pub fn get_key(&self, _signer_name: &str, key_id: &KeyIdentifier) -> Result<Vec<u8>, SignerError> {
        // Note: We don't currently support multiple signers with the same KeyIdentifier
        trace!("Get key {} for signer {}", key_id, _signer_name);
        self.keys
            .read()
            .map_err(|err| SignerError::KeyMapError(
                format!("Failed to get key handle for key id '{}': Failed to lock keys map for reading: {}", key_id, err)))?
            .get(key_id)
            .ok_or(SignerError::KeyNotFound)
            .map(|v| v.key_handle.clone())
    }

    pub fn get_signer_name_for_key(&self, key_id: &KeyIdentifier) -> CryptoResult<String> {
        trace!("Get signer name for key {}", &key_id);
        self.keys
            .read()
            .map_err(|err| crate::commons::crypto::error::Error::SignerError(
                format!("Failed to get signer name for key id '{}': Failed to lock keys map for reading: {}", key_id, err)))?
            .get(key_id)
            .ok_or(crate::commons::crypto::error::Error::KeyNotFound)
            .map(|v| v.signer_name.clone())
    }
}

//------------ Signer --------------------------------------------------------

#[derive(Debug)]
pub enum SignerImpl {
    OpenSsl(OpenSslSigner),
    #[cfg(feature = "hsm")]
    Pkcs11(Pkcs11Signer),
    #[cfg(feature = "hsm")]
    Kmip(KmipSigner)
}

// This is an enum in preparation of other supported signer types
#[derive(Clone, Debug)]
pub struct KrillSigner {
    // use a blocking lock to avoid having to be async, for signing operations
    // this should be fine.
    signers: Vec<Arc<RwLock<SignerImpl>>>,
    default_signer_idx: usize,
    keyroll_signer_idx: usize,
    key_lookup: Arc<KeyMap>,
    signer_names: Vec<String>,
}

impl KrillSigner {
    pub fn build(config: Arc<Config>) -> KrillResult<Self> {
        let key_lookup = Arc::new(KeyMap::persistent(&config.data_dir)?);
        let mut signers = Vec::new();
        let mut signer_names = Vec::new();

        #[allow(unused_mut)] // because without the HSM feature this is only set here
        let mut default_signer_idx: Option<usize> = None;
        #[allow(unused_mut)] // because without the HSM feature this is only set here
        let mut keyroll_signer_idx: Option<usize> = None;

        #[cfg(feature = "hsm")]
        if let Some(config_signers) = &config.signers {
            for (idx, signer) in config_signers.iter().enumerate() {
                let signer_name = &signer.name;

                signer_names.push(signer_name.clone());

                signers.push(match &signer.signer_conf {
                    SignerType::OpenSsl(signer_conf) => {
                        info!("Initializing OpenSSL signer '{}'", signer_name);
                        SignerImpl::OpenSsl(OpenSslSigner::build(signer_name, &signer_conf, &config.data_dir, key_lookup.clone())?)
                    }
                    SignerType::Pkcs11(signer_conf) => {
                        info!("Initializing PKCS#11 signer '{}'", signer_name);
                        SignerImpl::Pkcs11(Pkcs11Signer::build(signer_name, &signer_conf, key_lookup.clone())?)
                    }
                    SignerType::Kmip(signer_conf) => {
                        info!("Initializing KMIP signer '{}'", signer_name);
                        SignerImpl::Kmip(KmipSigner::build(signer_name, &signer_conf, key_lookup.clone())?)
                    }
                });

                if signer.default {
                    if default_signer_idx.is_some() {
                        return Err(Error::ConfigError("Only one signer can be set as the default signer".to_string()));
                    } else {
                        default_signer_idx = Some(idx);
                    }
                }

                if signer.keyroll {
                    if keyroll_signer_idx.is_some() {
                        return Err(Error::ConfigError("Only one signer can be set as the keyroll signer".to_string()));
                    } else {
                        keyroll_signer_idx = Some(idx);
                    }
                }                

                info!("Initialized signer '{}'", signer_name);
            }
        }

        if signers.is_empty() {
            let signer_config = ConfigSignerOpenSsl::default();
            signer_names.push(OPENSSL_DEFAULT_SIGNER_NAME.to_string());
            signers.push(SignerImpl::OpenSsl(OpenSslSigner::build(
                OPENSSL_DEFAULT_SIGNER_NAME, &signer_config, &config.data_dir, key_lookup.clone())?));
        }

        let default_signer_idx = default_signer_idx.unwrap_or(0);
        let keyroll_signer_idx = keyroll_signer_idx.unwrap_or(0);

        #[cfg(feature = "hsm")]
        info!("Using '{}' as the default signer", &signer_names[default_signer_idx]);

        let signers: Vec<_> = signers.into_iter().map(|s| Arc::new(RwLock::new(s))).collect();

        Ok(KrillSigner { signers, default_signer_idx, keyroll_signer_idx, key_lookup, signer_names })
    }

    pub fn test(data_dir: &Path) -> KrillResult<Self> {
        let key_lookup = Arc::new(KeyMap::in_memory()?);
        let signer_config = ConfigSignerOpenSsl::default();
        let signer = SignerImpl::OpenSsl(OpenSslSigner::build(
            OPENSSL_DEFAULT_SIGNER_NAME, &signer_config, &data_dir, key_lookup.clone())?);
        let signers = vec![Arc::new(RwLock::new(signer))];
        let signer_names = vec![OPENSSL_DEFAULT_SIGNER_NAME.to_string()];
        let default_signer_idx = 0;
        let keyroll_signer_idx = 0;
        Ok(KrillSigner { signers, default_signer_idx, keyroll_signer_idx, key_lookup, signer_names })
    }

    /// Returns the default signer
    fn signer(&self) -> Arc<RwLock<SignerImpl>> {
        self.signers[self.default_signer_idx].clone()
    }

    fn keyroll_signer(&self) -> Arc<RwLock<SignerImpl>> {
        self.signers[self.keyroll_signer_idx].clone()
    }

    #[cfg(feature = "hsm")]
    fn signer_for_key(&self, key_id: &KeyIdentifier) -> CryptoResult<Arc<RwLock<SignerImpl>>> {
        // lookup the key by key_id to get the signer id
        let signer_name = self.key_lookup.get_signer_name_for_key(key_id)?;
        let signer_idx = self.signer_names.iter().position(|item| item == &signer_name);
        if let Some(idx) = signer_idx {
            Ok(self.signers[idx].clone())
        } else {
            Err(crypto::Error::signer(format!("Unknown signer '{}'", signer_name)))
        }
    }

    #[cfg(feature = "hsm")]
    pub fn signer_name_for_key(&self, key_id: &KeyIdentifier) -> Option<String> {
        self.key_lookup.get_signer_name_for_key(key_id).ok()
    }

    #[cfg(not(feature = "hsm"))]
    fn signer_for_key(&self, _key_id: &KeyIdentifier) -> CryptoResult<Arc<RwLock<SignerImpl>>> {
        // There's only the OpenSsl signer when not using the HSM feature
        Ok(self.signers[0].clone())
    }

    #[cfg(not(feature = "hsm"))]
    pub fn signer_name_for_key(&self, _key_id: &KeyIdentifier) -> Option<String> {
        // There's only the OpenSsl signer when not using the HSM feature
        Some(self.signer_names[0].clone())
    }

    pub fn signer_key_for_key(&self, key_id: &KeyIdentifier) -> Option<String> {
        let signer_name = self.signer_name_for_key(key_id)?;
        Some(hex::encode_upper(self.key_lookup.get_key(&signer_name, key_id).ok()?))
    }
}

impl KrillSigner {
    pub fn create_key(&self) -> CryptoResult<KeyIdentifier> {
        match self.signer().write().unwrap().deref_mut() {
            SignerImpl::OpenSsl(signer) => signer.create_key(PublicKeyFormat::Rsa),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => signer.create_key(PublicKeyFormat::Rsa),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => signer.create_key(PublicKeyFormat::Rsa),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn create_key_for_key_roll(&self) -> CryptoResult<KeyIdentifier> {
        match self.keyroll_signer().write().unwrap().deref_mut() {
            SignerImpl::OpenSsl(signer) => signer.create_key(PublicKeyFormat::Rsa),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => signer.create_key(PublicKeyFormat::Rsa),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => signer.create_key(PublicKeyFormat::Rsa),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        match self.signer_for_key(key_id)?.write().unwrap().deref_mut() {
            SignerImpl::OpenSsl(signer) => signer.destroy_key(key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => signer.destroy_key(key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => signer.destroy_key(key_id),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> CryptoResult<PublicKey> {
        match self.signer_for_key(key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => signer.get_key_info(key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => signer.get_key_info(key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => signer.get_key_info(key_id),
        }
        .map_err(crypto::Error::key_error)
    }

    pub fn random_serial(&self) -> CryptoResult<Serial> {
        match self.signer().read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => Serial::random(signer),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => Serial::random(signer),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => Serial::random(signer),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(&self, key_id: &KeyIdentifier, data: &D) -> CryptoResult<Signature> {
        match self.signer_for_key(key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => signer.sign(key_id, SignatureAlgorithm::default(), data),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => signer.sign(key_id, SignatureAlgorithm::default(), data),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => signer.sign(key_id, SignatureAlgorithm::default(), data),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> CryptoResult<(Signature, PublicKey)> {
        match self.signer().read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => signer.sign_one_off(SignatureAlgorithm::default(), data),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => signer.sign_one_off(SignatureAlgorithm::default(), data),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => signer.sign_one_off(SignatureAlgorithm::default(), data),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn sign_csr(&self, base_repo: &RepoInfo, name_space: &str, key_id: &KeyIdentifier) -> CryptoResult<Csr> {
        let locked_signer = self.signer_for_key(key_id)?;
        let signer = locked_signer.read().unwrap();

        fn do_sign<S>(signer: &S, base_repo: &RepoInfo, name_space: &str, key_id: &KeyIdentifier) -> CryptoResult<Csr>
        where
            S: Signer<KeyId = KeyIdentifier>
        {
            let pub_key = signer.get_key_info(key_id).map_err(crypto::Error::key_error)?;
            let ca_repository = &base_repo.ca_repository(name_space).join(&[]).unwrap();
            let rpki_manifest = &base_repo.rpki_manifest(name_space, &pub_key.key_identifier());
            let rpki_notify = Some(base_repo.rpki_notify());

            let enc = Csr::construct(signer, key_id, ca_repository, rpki_manifest, rpki_notify.as_ref())
                .map_err(crypto::Error::signing)?;

            Ok(Csr::decode(enc.as_slice())?)
        }

        match signer.deref() {
            SignerImpl::OpenSsl(signer) => do_sign(signer, base_repo, name_space, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => do_sign(signer, base_repo, name_space, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => do_sign(signer, base_repo, name_space, key_id),
        }
    }

    pub fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        match self.signer_for_key(key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => tbs.into_cert(signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => tbs.into_cert(signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => tbs.into_cert(signer, key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
        match self.signer_for_key(key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => tbs.into_crl(signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => tbs.into_crl(signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => tbs.into_crl(signer, key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_manifest(
        &self,
        content: ManifestContent,
        builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Manifest> {
        match self.signer_for_key(key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => content.into_manifest(builder, signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => content.into_manifest(builder, signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => content.into_manifest(builder, signer, key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_roa(
        &self,
        roa_builder: RoaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Roa> {
        match self.signer_for_key(key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => roa_builder.finalize(object_builder, signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => roa_builder.finalize(object_builder, signer, key_id),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => roa_builder.finalize(object_builder, signer, key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        let key_id = ee.subject_key_identifier();
        rta_builder.push_cert(ee);
        match self.signer_for_key(&key_id)?.read().unwrap().deref() {
            SignerImpl::OpenSsl(signer) => rta_builder.sign(signer, &key_id, None, None),
            #[cfg(feature = "hsm")]
            SignerImpl::Pkcs11(signer) => rta_builder.sign(signer, &key_id, None, None),
            #[cfg(feature = "hsm")]
            SignerImpl::Kmip(signer) => rta_builder.sign(signer, &key_id, None, None),
        }
        .map_err(crypto::Error::signing)
    }
}

// //------------ Signer --------------------------------------------------------
//
// pub trait Signer: crypto::Signer<KeyId = KeyIdentifier> + Clone + Sized + Sync + Send + 'static {}
// impl<T: crypto::Signer<KeyId = KeyIdentifier> + Clone + Sized + Sync + Send + 'static> Signer for T {}

//------------ CsrInfo -------------------------------------------------------

pub type CaRepository = uri::Rsync;
pub type RpkiManifest = uri::Rsync;
pub type RpkiNotify = uri::Https;

pub struct CsrInfo {
    ca_repository: CaRepository,
    rpki_manifest: RpkiManifest,
    rpki_notify: Option<RpkiNotify>,
    key: PublicKey,
}

impl CsrInfo {
    pub fn new(
        ca_repository: CaRepository,
        rpki_manifest: RpkiManifest,
        rpki_notify: Option<RpkiNotify>,
        key: PublicKey,
    ) -> Self {
        CsrInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
            key,
        }
    }

    pub fn global_uris(&self) -> bool {
        self.ca_repository.seems_global_uri()
            && self.rpki_manifest.seems_global_uri()
            && self
                .rpki_notify
                .as_ref()
                .map(|uri| uri.seems_global_uri())
                .unwrap_or_else(|| true)
    }

    pub fn unpack(self) -> (CaRepository, RpkiManifest, Option<RpkiNotify>, PublicKey) {
        (self.ca_repository, self.rpki_manifest, self.rpki_notify, self.key)
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.key.key_identifier()
    }
}

impl TryFrom<&Csr> for CsrInfo {
    type Error = Error;

    fn try_from(csr: &Csr) -> KrillResult<CsrInfo> {
        csr.validate().map_err(|_| Error::invalid_csr("invalid signature"))?;
        let ca_repository = csr
            .ca_repository()
            .cloned()
            .ok_or_else(|| Error::invalid_csr("missing ca repository"))?;
        let rpki_manifest = csr
            .rpki_manifest()
            .cloned()
            .ok_or_else(|| Error::invalid_csr("missing rpki manifest"))?;
        let rpki_notify = csr.rpki_notify().cloned();
        let key = csr.public_key().clone();
        Ok(CsrInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
            key,
        })
    }
}

impl From<&Cert> for CsrInfo {
    fn from(issued: &Cert) -> Self {
        let ca_repository = issued.ca_repository().cloned().unwrap();
        let rpki_manifest = issued.rpki_manifest().cloned().unwrap();
        let rpki_notify = issued.rpki_notify().cloned();
        let key = issued.subject_public_key_info().clone();
        CsrInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
            key,
        }
    }
}

//------------ CaSignSupport -------------------------------------------------

/// Support signing by CAs
pub struct SignSupport;

impl SignSupport {
    /// Create an IssuedCert
    pub fn make_issued_cert(
        csr: CsrInfo,
        resources: &ResourceSet,
        limit: RequestResourceLimit,
        replaces: Option<ReplacedObject>,
        signing_key: &CertifiedKey,
        weeks: i64,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCert> {
        let signing_cert = signing_key.incoming_cert();
        let resources = resources.apply_limit(&limit)?;
        if !signing_cert.resources().contains(&resources) {
            return Err(Error::MissingResources);
        }

        let validity = Self::sign_validity_weeks(weeks);
        let request = CertRequest::Ca(csr, validity);

        let tbs = Self::make_tbs_cert(&resources, signing_cert, request, signer)?;
        let cert = signer.sign_cert(tbs, &signing_key.key_id())?;

        let cert_uri = signing_cert.uri_for_object(&cert);

        Ok(IssuedCert::new(cert_uri, limit, resources, cert, replaces))
    }

    /// Create an EE certificate for use in ResourceTaggedAttestations.
    /// Note that for RPKI signed objects such as ROAs and Manifests, the
    /// EE certificate is created by the rpki.rs library instead.
    pub fn make_rta_ee_cert(
        resources: &ResourceSet,
        signing_key: &CertifiedKey,
        validity: Validity,
        pub_key: PublicKey,
        signer: &KrillSigner,
    ) -> KrillResult<Cert> {
        let signing_cert = signing_key.incoming_cert();
        let request = CertRequest::Ee(pub_key, validity);
        let tbs = Self::make_tbs_cert(resources, signing_cert, request, signer)?;

        let cert = signer.sign_cert(tbs, &signing_key.key_id())?;
        Ok(cert)
    }

    fn make_tbs_cert(
        resources: &ResourceSet,
        signing_cert: &RcvdCert,
        request: CertRequest,
        signer: &KrillSigner,
    ) -> KrillResult<TbsCert> {
        let serial = signer.random_serial()?;
        let issuer = signing_cert.cert().subject().clone();

        let validity = match &request {
            CertRequest::Ca(_, validity) => *validity,
            CertRequest::Ee(_, validity) => *validity,
        };

        let pub_key = match &request {
            CertRequest::Ca(info, _) => info.key.clone(),
            CertRequest::Ee(key, _) => key.clone(),
        };

        let subject = Some(Name::from_pub_key(&pub_key));

        let key_usage = match &request {
            CertRequest::Ca(_, _) => KeyUsage::Ca,
            CertRequest::Ee(_, _) => KeyUsage::Ee,
        };

        let overclaim = Overclaim::Refuse;

        let mut cert = TbsCert::new(serial, issuer, validity, subject, pub_key, key_usage, overclaim);

        let asns = resources.to_as_resources();
        if asns.is_inherited() || !asns.to_blocks().unwrap().is_empty() {
            cert.set_as_resources(asns);
        }

        let ipv4 = resources.to_ip_resources_v4();
        if ipv4.is_inherited() || !ipv4.to_blocks().unwrap().is_empty() {
            cert.set_v4_resources(ipv4);
        }

        let ipv6 = resources.to_ip_resources_v6();
        if ipv6.is_inherited() || !ipv6.to_blocks().unwrap().is_empty() {
            cert.set_v6_resources(ipv6);
        }

        cert.set_authority_key_identifier(Some(signing_cert.cert().subject_key_identifier()));
        cert.set_ca_issuer(Some(signing_cert.uri().clone()));
        cert.set_crl_uri(Some(signing_cert.crl_uri()));

        match request {
            CertRequest::Ca(csr, _) => {
                let (ca_repository, rpki_manifest, rpki_notify, _pub_key) = csr.unpack();
                cert.set_basic_ca(Some(true));
                cert.set_ca_repository(Some(ca_repository));
                cert.set_rpki_manifest(Some(rpki_manifest));
                cert.set_rpki_notify(rpki_notify);
            }
            CertRequest::Ee(_, _) => {
                // cert.set_signed_object() ??
            }
        }

        Ok(cert)
    }

    /// Returns a validity period from 5 minutes ago (in case of NTP mess-up), to
    /// X weeks from now.
    pub fn sign_validity_weeks(weeks: i64) -> Validity {
        let from = Time::five_minutes_ago();
        let until = Time::now() + chrono::Duration::weeks(weeks);
        Validity::new(from, until)
    }

    pub fn sign_validity_days(days: i64) -> Validity {
        let from = Time::five_minutes_ago();
        let until = Time::now() + chrono::Duration::days(days);
        Validity::new(from, until)
    }
}

#[allow(clippy::large_enum_variant)]
enum CertRequest {
    Ca(CsrInfo, Validity),
    Ee(PublicKey, Validity),
}

trait ManifestEntry {
    fn mft_bytes(&self) -> Bytes;
    fn mft_hash(&self) -> Bytes {
        let digest = DigestAlgorithm::default().digest(self.mft_bytes().as_ref());
        Bytes::copy_from_slice(digest.as_ref())
    }
    fn mft_entry(&self, name: &str) -> FileAndHash<Bytes, Bytes> {
        FileAndHash::new(Bytes::copy_from_slice(name.as_bytes()), self.mft_hash())
    }
}

impl ManifestEntry for Crl {
    fn mft_bytes(&self) -> Bytes {
        self.to_captured().into_bytes()
    }
}

#[cfg(feature = "hsm")]
#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use rpki::repository::crypto::KeyIdentifier;

    use crate::commons::crypto::SignerError;

    use super::KeyMap;

    const TEST_SIGNER_NAME: &str = "TestSigner";

    fn make_key_id(n: u8) -> KeyIdentifier {
        let mut dummy_key_id_bytes: [u8; 20] = [0; 20];
        dummy_key_id_bytes[19] = n;
        KeyIdentifier::try_from(&dummy_key_id_bytes[..]).unwrap()
    }    

    #[test]
    fn lookup_add_key_should_succeed() {
        let lookup = KeyMap::in_memory().unwrap();
        lookup.add_key(TEST_SIGNER_NAME, make_key_id(1), &[]);
    }

    #[test]
    #[should_panic]
    fn lookup_add_dup_key_should_fail() {
        let lookup = KeyMap::in_memory().unwrap();
        let key_id = make_key_id(1);
        lookup.add_key(TEST_SIGNER_NAME, key_id.clone(), &[]);
        lookup.add_key(TEST_SIGNER_NAME, key_id.clone(), &[]);
    }

    #[test]
    fn lookup_get_key_should_succeed() {
        let lookup = KeyMap::in_memory().unwrap();
        let key_id = make_key_id(1);
        let handle = [1, 2, 3];
        lookup.add_key(TEST_SIGNER_NAME, key_id.clone(), &handle);
        assert_eq!(handle, lookup.get_key(TEST_SIGNER_NAME, &key_id).unwrap().as_slice());
    }

    #[test]
    fn lookup_get_nonexisting_key_should_fail() {
        let lookup = KeyMap::in_memory().unwrap();
        let key_id = make_key_id(1);
        assert!(matches!(lookup.get_key(TEST_SIGNER_NAME, &key_id), Err(SignerError::KeyNotFound)));
    }
}