use std::{path::Path, sync::Arc};

use rpki::repository::{
    aspa::{Aspa, AspaBuilder},
    cert::TbsCert,
    crl::{CrlEntry, TbsCertList},
    crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer},
    manifest::ManifestContent,
    roa::RoaBuilder,
    rta,
    sigobj::SignedObjectBuilder,
    x509::Serial,
    Cert, Crl, Csr, Manifest, Roa,
};

use crate::{
    commons::{
        api::RepoInfo,
        crypto::{self, dispatch::signerrouter::SignerRouter, CryptoResult},
        KrillResult,
    },
    daemon::config::Config,
};

#[cfg(feature = "hsm")]
use crate::daemon::config::{SignerConfig, SignerType};

#[derive(Debug)]
pub struct KrillSignerConfig {
    #[cfg(feature = "hsm")]
    pub signer_configs: Vec<SignerConfig>,
}

impl Default for KrillSignerConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "hsm")]
            signer_configs: vec![SignerConfig::default()],
        }
    }
}

#[cfg(feature = "hsm")]
impl KrillSignerConfig {
    pub fn single_signer(name: Option<String>, signer_type: SignerType) -> Self {
        KrillSignerConfig {
            signer_configs: vec![SignerConfig::new(name, signer_type)],
        }
    }
}

impl From<Arc<Config>> for KrillSignerConfig {
    #[cfg(not(feature = "hsm"))]
    fn from(_: Arc<Config>) -> Self {
        KrillSignerConfig::default()
    }

    #[cfg(feature = "hsm")]
    fn from(config: Arc<Config>) -> Self {
        KrillSignerConfig {
            signer_configs: config.signers.clone(),
        }
    }
}

/// High level signing interface between Krill and the [SignerRouter].
///
/// KrillSigner:
///   - Delegates Signer management and dispatch to [SignerRouter].
///   - Maps Result<SignerError> to KrillResult.
///   - Directs signers to use the RPKI standard key format (RSA).
///   - Directs signers to use the RPKI standard signature algorithm (RSA PKCS #1 v1.5 with SHA-256).
///   - Offers additional high level functions compared to the [Signer] trait.
///
/// We delegate to [SignerRouter] because our interface differs to that of the [Signer] trait and because the code is
/// easier to read if we separate out responsibilities.
///
/// We need dispatch to the correct [Signer] to be done by a Struct that implements the [Signer] trait itself because
/// otherwise functions elsewhere in Krill that take a [Signer] trait as input will not invoke the correct [Signer].
///
/// We _could_ implement the [Signer] trait in [KrillSigner] but then we would implement two almost identical but
/// subtly different interfaces in the same struct AND implement management of signers and dispatch to the correct
/// signer all in one place, and that quickly becomes harder to read, understand and maintain.
#[derive(Debug)]
pub struct KrillSigner {
    router: SignerRouter,
}

impl KrillSigner {
    #[cfg(not(feature = "hsm"))]
    pub fn build(work_dir: &Path, _: KrillSignerConfig) -> KrillResult<Self> {
        let router = SignerRouter::build(work_dir)?;
        Ok(KrillSigner { router })
    }

    #[cfg(feature = "hsm")]
    pub fn build(work_dir: &Path, config: KrillSignerConfig) -> KrillResult<Self> {
        let router = SignerRouter::build(work_dir, &config.signer_configs)?;
        Ok(KrillSigner { router })
    }

    pub fn create_key(&self) -> CryptoResult<KeyIdentifier> {
        self.router
            .create_key(PublicKeyFormat::Rsa)
            .map_err(crypto::Error::signer)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        self.router.destroy_key(key_id).map_err(crypto::Error::key_error)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> CryptoResult<PublicKey> {
        self.router.get_key_info(key_id).map_err(crypto::Error::key_error)
    }

    pub fn random_serial(&self) -> CryptoResult<Serial> {
        Serial::random(&self.router).map_err(crypto::Error::signer)
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(&self, key_id: &KeyIdentifier, data: &D) -> CryptoResult<Signature> {
        self.router
            .sign(key_id, SignatureAlgorithm::default(), data)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> CryptoResult<(Signature, PublicKey)> {
        self.router
            .sign_one_off(SignatureAlgorithm::default(), data)
            .map_err(crypto::Error::signer)
    }

    pub fn sign_csr(&self, base_repo: &RepoInfo, name_space: &str, key: &KeyIdentifier) -> CryptoResult<Csr> {
        let pub_key = self.router.get_key_info(key).map_err(crypto::Error::key_error)?;
        let enc = Csr::construct(
            &self.router,
            key,
            &base_repo.ca_repository(name_space).join(&[]).unwrap(), // force trailing slash
            &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(crypto::Error::signing)?;
        Ok(Csr::decode(enc.as_slice())?)
    }

    pub fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        tbs.into_cert(&self.router, key_id).map_err(crypto::Error::signing)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
        tbs.into_crl(&self.router, key_id).map_err(crypto::Error::signing)
    }

    pub fn sign_manifest(
        &self,
        content: ManifestContent,
        builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Manifest> {
        content
            .into_manifest(builder, &self.router, key_id)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_roa(
        &self,
        roa_builder: RoaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Roa> {
        roa_builder
            .finalize(object_builder, &self.router, key_id)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_aspa(
        &self,
        aspa_builder: AspaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Aspa> {
        aspa_builder
            .finalize(object_builder, &self.router, key_id)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        let key = ee.subject_key_identifier();
        rta_builder.push_cert(ee);
        rta_builder
            .sign(&self.router, &key, None, None)
            .map_err(crypto::Error::signing)
    }
}
