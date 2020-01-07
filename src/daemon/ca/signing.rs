//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::convert::TryFrom;

use bytes::Bytes;

use rpki::cert::{Cert, KeyUsage, Overclaim, TbsCert};
use rpki::crl::Crl;
use rpki::crypto::{self, DigestAlgorithm, KeyIdentifier, PublicKey};
use rpki::csr::Csr;
use rpki::manifest::FileAndHash;
use rpki::uri;
use rpki::x509::{Name, Serial, Time, Validity};

use crate::commons::api::{IssuedCert, ReplacedObject, RequestResourceLimit, ResourceSet};
use crate::daemon::ca::{self, CertifiedKey};

//------------ Signer --------------------------------------------------------

pub trait Signer:
    crypto::Signer<KeyId = KeyIdentifier> + Clone + Sized + Sync + Send + 'static
{
}
impl<T: crypto::Signer<KeyId = KeyIdentifier> + Clone + Sized + Sync + Send + 'static> Signer
    for T
{
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

    pub fn contains_localhost(&self) -> bool {
        let ca_uri = self.ca_repository.to_string().to_ascii_lowercase();
        let mft_uri = self.rpki_manifest.to_string().to_ascii_lowercase();
        let rrdp_uri = self
            .rpki_notify
            .as_ref()
            .map(|uri| uri.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        ca_uri.starts_with("rsync://localhost")
            || ca_uri.starts_with("rsync://127.")
            || mft_uri.starts_with("rsync://localhost")
            || mft_uri.starts_with("rsync://127.")
            || rrdp_uri.starts_with("https://localhost")
            || rrdp_uri.starts_with("https://127.")
    }

    pub fn unpack(self) -> (CaRepository, RpkiManifest, Option<RpkiNotify>, PublicKey) {
        (
            self.ca_repository,
            self.rpki_manifest,
            self.rpki_notify,
            self.key,
        )
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.key.key_identifier()
    }
}

impl TryFrom<&Csr> for CsrInfo {
    type Error = ca::Error;

    fn try_from(csr: &Csr) -> ca::Result<CsrInfo> {
        csr.validate()
            .map_err(|_| ca::Error::invalid_csr("invalid signature"))?;
        let ca_repository = csr
            .ca_repository()
            .cloned()
            .ok_or_else(|| ca::Error::invalid_csr("missing ca repository"))?;
        let rpki_manifest = csr
            .rpki_manifest()
            .cloned()
            .ok_or_else(|| ca::Error::invalid_csr("missing rpki manifest"))?;
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
    pub fn make_issued_cert<S: Signer>(
        csr: CsrInfo,
        resources: &ResourceSet,
        limit: RequestResourceLimit,
        replaces: Option<ReplacedObject>,
        signing_key: &CertifiedKey,
        signer: &S,
    ) -> ca::Result<IssuedCert> {
        let (ca_repository, rpki_manifest, rpki_notify, pub_key) = csr.unpack();

        let signing_cert = signing_key.incoming_cert();

        let resources = resources
            .apply_limit(&limit)
            .map_err(|_| ca::Error::MissingResources)?;

        if !signing_cert.resources().contains(&resources) {
            return Err(ca::Error::MissingResources);
        }

        let serial = { Serial::random(signer).map_err(ca::Error::signer)? };
        let issuer = signing_cert.cert().subject().clone();

        let validity = Validity::new(Time::five_minutes_ago(), Time::next_year());

        let subject = Some(Name::from_pub_key(&pub_key));

        let key_usage = KeyUsage::Ca;
        let overclaim = Overclaim::Refuse;

        let mut cert = TbsCert::new(
            serial, issuer, validity, subject, pub_key, key_usage, overclaim,
        );
        cert.set_basic_ca(Some(true));

        cert.set_ca_issuer(Some(signing_cert.uri().clone()));
        cert.set_crl_uri(Some(signing_cert.crl_uri()));
        cert.set_ca_repository(Some(ca_repository));
        cert.set_rpki_manifest(Some(rpki_manifest));
        cert.set_rpki_notify(rpki_notify);

        let asns = resources.to_as_resources();
        if asns.is_inherited() || !asns.as_blocks().unwrap().is_empty() {
            cert.set_as_resources(Some(asns));
        }

        let ipv4 = resources.to_ip_resources_v4();
        if ipv4.is_inherited() || !ipv4.as_blocks().unwrap().is_empty() {
            cert.set_v4_resources(Some(ipv4));
        }

        let ipv6 = resources.to_ip_resources_v6();
        if ipv6.is_inherited() || !ipv6.as_blocks().unwrap().is_empty() {
            cert.set_v6_resources(Some(ipv6));
        }

        cert.set_authority_key_identifier(Some(signing_cert.cert().subject_key_identifier()));

        let cert = cert
            .into_cert(signer, &signing_key.key_id())
            .map_err(ca::Error::signer)?;
        let cert_uri = signing_cert.uri_for_object(&cert);

        Ok(IssuedCert::new(
            cert_uri,
            limit,
            resources.clone(),
            cert,
            replaces,
        ))
    }

    /// Returns a validity period from 5 minutes ago (in case of NTP mess-up), to
    /// one year from now.
    pub fn sign_validity_year() -> Validity {
        let just_now = Time::five_minutes_ago();
        let one_year = Time::next_year();
        Validity::new(just_now, one_year)
    }
}

trait ManifestEntry {
    fn mft_bytes(&self) -> Bytes;
    fn mft_hash(&self) -> Bytes {
        Bytes::from(
            DigestAlgorithm::default()
                .digest(self.mft_bytes().as_ref())
                .as_ref(),
        )
    }
    fn mft_entry(&self, name: &str) -> FileAndHash<Bytes, Bytes> {
        FileAndHash::new(Bytes::from(name), self.mft_hash())
    }
}

impl ManifestEntry for Crl {
    fn mft_bytes(&self) -> Bytes {
        self.to_captured().into_bytes()
    }
}
