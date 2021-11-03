//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::{
    sync::{Arc, RwLock},
    {convert::TryFrom, path::Path},
};

use bytes::Bytes;

use rpki::{
    repository::{
        aspa::{Aspa, AspaBuilder},
        cert::{Cert, KeyUsage, Overclaim, TbsCert},
        crl::{Crl, CrlEntry, TbsCertList},
        crypto::{
            signer::KeyError, DigestAlgorithm, KeyIdentifier, PublicKey, PublicKeyFormat, Signature,
            SignatureAlgorithm, Signer, SigningError,
        },
        csr::Csr,
        manifest::{FileAndHash, Manifest, ManifestContent},
        roa::{Roa, RoaBuilder},
        rta,
        sigobj::SignedObjectBuilder,
        x509::{Name, Serial, Time, Validity},
    },
    uri,
};

use crate::{
    commons::{
        api::{IssuedCert, RcvdCert, ReplacedObject, RepoInfo, RequestResourceLimit, ResourceSet},
        crypto::{
            self,
            signers::{error::SignerError, softsigner::OpenSslSigner},
            CryptoResult,
        },
        error::Error,
        util::AllowedUri,
        KrillResult,
    },
    daemon::ca::CertifiedKey,
};

#[cfg(feature = "hsm")]
use crate::commons::crypto::signers::kmip::KmipSigner;

//------------ SignerProvider ------------------------------------------------

/// Dispatchers Signer requests to a particular implementation of the Signer trait.
///
/// Named and modelled after the similar AuthProvider concept that already exists in Krill.
#[allow(dead_code)] // Needed as we currently only ever construct one variant
#[derive(Clone, Debug)]
enum SignerProvider {
    OpenSsl(OpenSslSigner),

    #[cfg(feature = "hsm")]
    Kmip(KmipSigner),
}

impl SignerProvider {
    pub fn supports_random(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(signer) => signer.supports_random(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.supports_random(),
        }
    }
}

impl Signer for SignerProvider {
    type KeyId = KeyIdentifier;

    type Error = SignerError;

    fn create_key(&self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.create_key(algorithm),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.create_key(algorithm),
        }
    }

    fn get_key_info(&self, key: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_key_info(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_key_info(key),
        }
    }

    fn destroy_key(&self, key: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.destroy_key(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.destroy_key(key),
        }
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign(key, algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign(key, algorithm, data),
        }
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_one_off(algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign_one_off(algorithm, data),
        }
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.rand(target),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.rand(target),
        }
    }
}

//------------ SignerRouter --------------------------------------------------

/// Manages multiple Signers and decides which Signer should handle which request.
#[derive(Clone, Debug)]
struct SignerRouter {
    // The general signer is used for all signing operations except one-off signing.
    general_signer: Arc<RwLock<SignerProvider>>,

    // As the security of a HSM isn't needed for one-off keys, and HSMs are slow, by default this should be an instance
    // of OpenSslSigner. However, if users think the perceived extra security is warranted let them use a different
    // Signer for one-off keys if that's what they want.
    one_off_signer: Arc<RwLock<SignerProvider>>,

    // The signer to use when a configured signer doesn't support generation of random numbers.
    rand_fallback_signer: Arc<RwLock<SignerProvider>>,
}

impl SignerRouter {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        // The types of signer to initialize, the details needed to initialize them and the intended purpose for each
        // signer (e.g. signer for past keys, currently used signer, signer to use for a key roll, etc.) should come
        // from the configuration file. SignerRouter combines that input with its own rules, e.g. to dispatch a signing
        // request to the correct signer we will need to determine which signer possesses the signing key, and the
        // signer to use to create a new key depends on whether the key is one-off or not and whether or not it is
        // being created for a key roll. For now the capability for different signers for different purposes exists but
        // is not yet used.

        // TODO: Once it becomes possible to configure how an HSM is used by Krill we need to decide what the
        // defaults should be and what should be configurable or not concerning HSM usage, and to document why, if
        // permitted, it is acceptable to use local keys, signing & random number genration instead of the more
        // secure HSM based alternatives (if available).

        // We always need an OpenSSL signer, either for keys created by a previous instance of Krill, or as a fallback
        // random number generator for HSMs that don't support random number generation, or for creating one-off short
        // lived signing keys.
        let openssl_signer = Arc::new(RwLock::new(SignerProvider::OpenSsl(OpenSslSigner::build(work_dir)?)));

        #[cfg(not(feature = "hsm"))]
        {
            // For backward compatibility with currently released Krill, use OpenSSL for everything.
            Ok(SignerRouter {
                general_signer: openssl_signer.clone(),
                one_off_signer: openssl_signer.clone(),
                rand_fallback_signer: openssl_signer,
            })
        }

        #[cfg(all(feature = "hsm", not(feature = "hsm-tests")))]
        {
            // Currently the behaviour is the same with the hsm-tests feature enabled or disabled. This is because with
            // it disabled the Krill 'functional' test fails with error 'Krill failed to start: Signing issue: Could
            // not find key'. Implementing the mapping of keys to signers is beyond the scope of the current task and
            // so this has for now been commented out.
            compile_error!("The 'hsm' feature can only be used in combination with the 'hsm-tests' feature at present");
            unreachable!();
            // // When the HSM feature is activated but we are not in test mode:
            // //   - Use the HSM for key creation, signing, deletion, except for one-off keys.
            // //   - Use the HSM for random number generation, if supported, else use the OpenSSL signer.
            // //   - Use the OpenSSL signer for one-off keys.
            // let kmip_signer = Arc::new(RwLock::new(SignerProvider::Kmip(KmipSigner::build()?)));

            // Ok(SignerRouter {
            //     general_signer: kmip_signer.clone(),
            //     one_off_signer: openssl_signer.clone(),
            //     rand_fallback_signer: openssl_signer,
            // })
        }

        #[cfg(all(feature = "hsm", feature = "hsm-tests"))]
        {
            // When the HSM feature is activated AND test mode is activated:
            //   - Use the HSM for as much as possible to depend on it as broadly as possible in the Krill test suite..
            //   - Fallback to OpenSSL for random number generation if the HSM doesn't support it.
            let kmip_signer = Arc::new(RwLock::new(SignerProvider::Kmip(KmipSigner::build()?)));

            Ok(SignerRouter {
                general_signer: kmip_signer.clone(),
                one_off_signer: kmip_signer.clone(),
                rand_fallback_signer: openssl_signer,
            })
        }
    }
}

impl Signer for SignerRouter {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        self.general_signer.write().unwrap().create_key(algorithm)
    }

    fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<Self::Error>> {
        self.general_signer.read().unwrap().get_key_info(key_id)
    }

    fn destroy_key(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<Self::Error>> {
        self.general_signer.write().unwrap().destroy_key(key_id)
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        self.general_signer.read().unwrap().sign(key_id, algorithm, data)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        self.one_off_signer.read().unwrap().sign_one_off(algorithm, data)
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        let signer = self.general_signer.read().unwrap();
        if signer.supports_random() {
            signer.rand(target)
        } else {
            self.rand_fallback_signer.read().unwrap().rand(target)
        }
    }
}

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
