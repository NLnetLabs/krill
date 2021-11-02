//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::{
    ops::Deref,
    sync::{Arc, RwLock},
    {convert::TryFrom, path::Path},
};

use bcder::Captured;
use bytes::Bytes;

use rpki::{
    repository::{
        aspa::{Aspa, AspaBuilder},
        cert::{Cert, KeyUsage, Overclaim, TbsCert},
        crl::{Crl, CrlEntry, TbsCertList},
        crypto::{DigestAlgorithm, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer},
        csr::Csr,
        manifest::{FileAndHash, Manifest, ManifestContent},
        roa::{Roa, RoaBuilder},
        rta,
        sigobj::SignedObjectBuilder,
        x509::{Name, Serial, Time, Validity},
    },
    uri,
};

#[cfg(feature = "hsm")]
use crate::commons::util::dummysigner::DummySigner;

use crate::{
    commons::{
        api::{IssuedCert, RcvdCert, ReplacedObject, RepoInfo, RequestResourceLimit, ResourceSet},
        crypto::{self, CryptoResult},
        error::Error,
        util::{softsigner::OpenSslSigner, AllowedUri},
        KrillResult,
    },
    daemon::ca::CertifiedKey,
};

//------------ Signer --------------------------------------------------------

#[derive(Clone, Debug)]
enum SignerProvider {
    OpenSsl(OpenSslSigner),

    #[cfg(feature = "hsm")]
    #[allow(dead_code)]
    Dummy(DummySigner),
}

impl SignerProvider {
    pub fn create_key(&mut self) -> CryptoResult<KeyIdentifier> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.create_key(PublicKeyFormat::Rsa),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => signer.create_key(PublicKeyFormat::Rsa),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn destroy_key(&mut self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.destroy_key(key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => signer.destroy_key(key_id),
        }
        .map_err(crypto::Error::key_error)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> CryptoResult<PublicKey> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_key_info(key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => signer.get_key_info(key_id),
        }
        .map_err(crypto::Error::key_error)
    }

    pub fn random_serial(&self) -> CryptoResult<Serial> {
        match self {
            SignerProvider::OpenSsl(signer) => Serial::random(signer.deref()),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => Serial::random(signer.deref()),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        sig_alg: SignatureAlgorithm,
        data: &D,
    ) -> CryptoResult<Signature> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign(key_id, sig_alg, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => signer.sign(key_id, sig_alg, data),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        sig_alg: SignatureAlgorithm,
        data: &D,
    ) -> CryptoResult<(Signature, PublicKey)> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_one_off(sig_alg, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => signer.sign_one_off(sig_alg, data),
        }
        .map_err(crypto::Error::signer)
    }

    pub fn sign_csr(&self, base_repo: &RepoInfo, name_space: &str, key: &KeyIdentifier) -> CryptoResult<Csr> {
        fn func<T>(signer: &T, base_repo: &RepoInfo, name_space: &str, key: &KeyIdentifier) -> CryptoResult<Captured>
        where
            T: Signer<KeyId = KeyIdentifier>,
        {
            let pub_key = signer.get_key_info(key).map_err(crypto::Error::key_error)?;
            Csr::construct(
                signer.deref(),
                key,
                &base_repo.ca_repository(name_space).join(&[]).unwrap(), // force trailing slash
                &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
                Some(&base_repo.rpki_notify()),
            )
            .map_err(crypto::Error::signing)
        }

        let enc = match self {
            SignerProvider::OpenSsl(signer) => func(signer.deref(), base_repo, name_space, key),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => func(signer.deref(), base_repo, name_space, key),
        }?;

        Ok(Csr::decode(enc.as_slice())?)
    }

    pub fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        match self {
            SignerProvider::OpenSsl(signer) => tbs.into_cert(signer.deref(), key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => tbs.into_cert(signer.deref(), key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
        match self {
            SignerProvider::OpenSsl(signer) => tbs.into_crl(signer.deref(), key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => tbs.into_crl(signer.deref(), key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_manifest(
        &self,
        content: ManifestContent,
        builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Manifest> {
        match self {
            SignerProvider::OpenSsl(signer) => content.into_manifest(builder, signer.deref(), key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => content.into_manifest(builder, signer.deref(), key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_roa(
        &self,
        roa_builder: RoaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Roa> {
        match self {
            SignerProvider::OpenSsl(signer) => roa_builder.finalize(object_builder, signer.deref(), key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => roa_builder.finalize(object_builder, signer.deref(), key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_aspa(
        &self,
        aspa_builder: AspaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Aspa> {
        match self {
            SignerProvider::OpenSsl(signer) => aspa_builder.finalize(object_builder, signer.deref(), key_id),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => aspa_builder.finalize(object_builder, signer.deref(), key_id),
        }
        .map_err(crypto::Error::signing)
    }

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        let key = ee.subject_key_identifier();
        rta_builder.push_cert(ee);

        match self {
            SignerProvider::OpenSsl(signer) => rta_builder.sign(signer.deref(), &key, None, None),
            #[cfg(feature = "hsm")]
            SignerProvider::Dummy(signer) => rta_builder.sign(signer.deref(), &key, None, None),
        }
        .map_err(crypto::Error::signing)
    }
}

#[derive(Clone, Debug)]
pub struct KrillSigner {
    // KrillSigner chooses which signer to use when. The noise of handling the enum based dispatch is handled by the
    // SignerProvider type defined above, patterned after the existing AuthProvider enum based approach.
    //
    // Use Arc references so that we can use refer to the same signer instance more than once if that signer should be
    // used for multiple purposes, e.g. as both general_signer and one_off_signer in this case.
    //
    // Use an RwLock because the Signer trait from the rpki-rs crate uses &mut self for create_key() and destroy_key()
    // operations. In future we might move the responsibility for locking into the signer so that it can lock only what
    // actually needs to be locked raet

    // The general signer is used for all signing operations except one off signing.
    general_signer: Arc<RwLock<SignerProvider>>,

    // As the security of a HSM isn't needed for one off keys, and HSMs are slow, by default this should be an instance
    // of OpenSslSigner. However, if users think the perceived extra security is warranted let them use a different
    // Signer for one off keys if that's what they want.
    one_off_signer: Arc<RwLock<SignerProvider>>,
}

impl KrillSigner {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        // The types of signer to initialize, the details needed to initialize them and the intended purpose for each
        // signer (e.g. signer for past keys, currently used signer, signer to use for a key roll, etc.) should come
        // from the configuration file. KrillSigner should combine that input its own rules, e.g. to dispatch a signing
        // request to the correct signer we will need to determine which signer possesses the signing key, and the
        // signer to use to create a new key depends on whether the key is one-off or not and whether or not it is
        // being created for a key roll. For now the capability for different signers for different purposes exists but
        // is not yet used.

        let openssl_signer = OpenSslSigner::build(work_dir)?;
        let openssl_signer = Arc::new(RwLock::new(SignerProvider::OpenSsl(openssl_signer)));
        let general_signer = openssl_signer.clone();
        let one_off_signer = openssl_signer;
        Ok(KrillSigner {
            general_signer,
            one_off_signer,
        })
    }

    pub fn create_key(&self) -> CryptoResult<KeyIdentifier> {
        self.general_signer.write().unwrap().create_key()
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        self.general_signer.write().unwrap().destroy_key(key_id)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> CryptoResult<PublicKey> {
        self.general_signer.read().unwrap().get_key_info(key_id)
    }

    pub fn random_serial(&self) -> CryptoResult<Serial> {
        self.general_signer.read().unwrap().random_serial()
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(&self, key_id: &KeyIdentifier, data: &D) -> CryptoResult<Signature> {
        self.general_signer
            .read()
            .unwrap()
            .sign(key_id, SignatureAlgorithm::default(), data)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> CryptoResult<(Signature, PublicKey)> {
        self.one_off_signer
            .read()
            .unwrap()
            .sign_one_off(SignatureAlgorithm::default(), data)
    }

    pub fn sign_csr(&self, base_repo: &RepoInfo, name_space: &str, key: &KeyIdentifier) -> CryptoResult<Csr> {
        self.general_signer.read().unwrap().sign_csr(base_repo, name_space, key)
    }

    pub fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        self.general_signer.read().unwrap().sign_cert(tbs, key_id)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
        self.general_signer.read().unwrap().sign_crl(tbs, key_id)
    }

    pub fn sign_manifest(
        &self,
        content: ManifestContent,
        builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Manifest> {
        self.general_signer
            .read()
            .unwrap()
            .sign_manifest(content, builder, key_id)
    }

    pub fn sign_roa(
        &self,
        roa_builder: RoaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Roa> {
        self.general_signer
            .read()
            .unwrap()
            .sign_roa(roa_builder, object_builder, key_id)
    }

    pub fn sign_aspa(
        &self,
        aspa_builder: AspaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Aspa> {
        self.general_signer
            .read()
            .unwrap()
            .sign_aspa(aspa_builder, object_builder, key_id)
    }

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        self.general_signer.read().unwrap().sign_rta(rta_builder, ee)
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
        let cert = signer.sign_cert(tbs, signing_key.key_id())?;

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

        let cert = signer.sign_cert(tbs, signing_key.key_id())?;
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
