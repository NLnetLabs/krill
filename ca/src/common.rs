//! Common objects for TAs and CAs
use std::sync::Arc;

use bytes::Bytes;

use rpki::crl::{Crl, TbsCertList, CrlEntry};
use rpki::manifest::{Manifest, ManifestContent, FileAndHash};
use rpki::cert::Cert;
use rpki::crypto::{DigestAlgorithm, SigningError};
use rpki::crypto::signer::KeyError;
use rpki::sigobj::SignedObjectBuilder;
use rpki::uri;
use rpki::x509::{Serial, Time, KeyIdentifier, Validity};

use krill_commons::api::ca::RepoInfo;

use crate::trustanchor::CaSigner;

/// This type contains information about the signing certificate:
/// The key id, the actual certificate and its publication point
/// for use in AIA.
pub struct SigningCertificate<'a, S: CaSigner> {
    key: &'a S::KeyId,
    cert: &'a Cert,
    uri: &'a uri::Rsync
}

impl<'a, S: CaSigner> SigningCertificate<'a, S> {
    pub fn new(
        key: &'a S::KeyId,
        cert: &'a Cert,
        uri: &'a uri::Rsync
    ) -> Self {
        SigningCertificate {
            key,
            cert,
            uri
        }
    }
}


trait ManifestEntry {
    fn mft_bytes(&self) -> Bytes;
    fn mft_hash(&self) -> Bytes {
        Bytes::from(
            DigestAlgorithm::default().digest(
                self.mft_bytes().as_ref()).as_ref()
        )
    }
    fn mft_entry(&self, name: &str) -> FileAndHash<Bytes, Bytes> {
        FileAndHash::new(
            Bytes::from(name),
            self.mft_hash()
        )
    }
}

impl ManifestEntry for Crl {
    fn mft_bytes(&self) -> Bytes {
        self.to_captured().into_bytes()
    }
}

//------------ PublicationDelta ----------------------------------------------

/// This type describes a set up of objects published for a CA key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicationDelta {
    crl: Crl,
    mft: Manifest
}

impl PublicationDelta {
    pub fn publish<S: CaSigner>(
        signer: Arc<S>,
        signing_cert: SigningCertificate<S>,
        current_set: Option<&CurrentObjectSet>,
        repo_info: &RepoInfo
    ) -> Result<Self, PublicationError<S>> {
        if let Some(_set) = current_set {
            unimplemented!()
        }
        let pub_key = signer.get_key_info(signing_cert.key)
            .map_err(PublicationError::KeyError)?;

        let number = Serial::from(1_u128);

        let now = Time::now();
        let tomorrow = Time::tomorrow();
        let next_week = Time::next_week();

        let crl: Crl = {
            let mut crl = TbsCertList::new(
                Default::default(),
                pub_key.to_subject_name(),
                now,
                tomorrow,
                Vec::<CrlEntry>::new(),
                KeyIdentifier::from_public_key(&pub_key),
                number
            );

            crl.into_crl(signer.as_ref(), signing_cert.key)
                .map_err(PublicationError::SigningError)?
        };

        let crl_uri = repo_info.crl_uri(&pub_key);
        let crl_name = repo_info.crl_name(&pub_key);

        let mft: Manifest = {
            let mft_content = ManifestContent::new(
                number,
                now,
                tomorrow,
                DigestAlgorithm::default(),
                [ crl.mft_entry(&crl_name) ].iter()
            );

            mft_content.into_manifest(
                SignedObjectBuilder::new(
                    Serial::random(signer.as_ref()).map_err(PublicationError::SignerError)?,
                    Validity::new(now, next_week),
                    crl_uri,
                    signing_cert.uri.clone(),
                    repo_info.rpki_manifest(&pub_key)
                ),
                signer.as_ref(),
                signing_cert.key,
                signing_cert.cert
            ).map_err(PublicationError::SigningError)?
        };

        Ok(PublicationDelta { crl, mft })
    }
}

impl PartialEq for PublicationDelta {
    fn eq(&self, other: &PublicationDelta) -> bool {
        self.crl.mft_bytes() == other.crl.mft_bytes() &&
        self.mft.to_captured().into_bytes() == other.mft.to_captured().into_bytes()
    }
}

impl Eq for PublicationDelta {}

//------------ PublicationError ----------------------------------------------

#[derive(Debug, Display)]
pub enum PublicationError<S: CaSigner> {
    #[display(fmt = "{}", _0)]
    SignerError(S::Error),

    #[display(fmt = "{}", _0)]
    KeyError(KeyError<S::Error>),

    #[display(fmt = "{}", _0)]
    SigningError(SigningError<S::Error>),
}


//------------ CurrentObjectSet ----------------------------------------------

/// This type describes the complete current set of objects for CA key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentObjectSet {
    crl: Crl,
    mft: Manifest
}

impl CurrentObjectSet {
    pub fn apply_delta(&mut self, delta: PublicationDelta) {
        self.crl = delta.crl;
        self.mft = delta.mft;
    }
}

impl From<PublicationDelta> for CurrentObjectSet {
    fn from(delta: PublicationDelta) -> Self {
        CurrentObjectSet {
            crl: delta.crl,
            mft: delta.mft
        }
    }
}

impl PartialEq for CurrentObjectSet {
    fn eq(&self, other: &CurrentObjectSet) -> bool {
        self.crl.mft_bytes() == other.crl.mft_bytes() &&
        self.mft.to_captured().into_bytes() == other.mft.to_captured().into_bytes()
    }
}

impl Eq for CurrentObjectSet {}
