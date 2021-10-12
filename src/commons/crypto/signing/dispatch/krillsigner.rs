use std::path::Path;

use rpki::repository::{
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

use crate::commons::{
    api::RepoInfo,
    crypto::{self, dispatch::signerrouter::SignerRouter, CryptoResult},
    KrillResult,
};

//------------ KrillSigner ---------------------------------------------------

/// High level signing interface between Krill and the Signer backends.
///
/// KrillSigner:
///   - Is configured via the Krill configuration file.
///   - Maps Result<SignerError> to KrillResult.
///   - Directs signers to use the RPKI standard key format (RSA).
///   - Directs signers to use the RPKI standard signature algorithm (RSA PKCS #1 v1.5 with SHA-256).
///   - Offers a higher level interface than the Signer trait.
#[derive(Clone, Debug)]
pub struct KrillSigner {
    router: SignerRouter,
}

impl KrillSigner {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        Ok(KrillSigner {
            router: SignerRouter::build(work_dir)?,
        })
    }

    pub fn create_key(&self) -> CryptoResult<KeyIdentifier> {
        self.router
            .create_key_minimally_locking(PublicKeyFormat::Rsa)
            .map_err(crypto::Error::signer)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        self.router
            .destroy_key_minimally_locking(key_id)
            .map_err(crypto::Error::key_error)
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

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        let key = ee.subject_key_identifier();
        rta_builder.push_cert(ee);
        rta_builder
            .sign(&self.router, &key, None, None)
            .map_err(crypto::Error::signing)
    }
}
