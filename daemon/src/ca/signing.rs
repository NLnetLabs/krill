//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use bytes::Bytes;

use rpki::crl::{Crl, TbsCertList};
use rpki::crypto::signer::KeyError;
use rpki::crypto::{self, DigestAlgorithm, KeyIdentifier, SigningError};
use rpki::manifest::{FileAndHash, Manifest, ManifestContent};
use rpki::sigobj::SignedObjectBuilder;
use rpki::uri;
use rpki::x509::{Serial, Time, Validity};

use krill_commons::api::ca::{
    AddedObject, CertifiedKey, CurrentObject, ObjectsDelta, PublicationDelta, RepoInfo, Revocation,
    RevocationsDelta, UpdatedObject,
};

//------------ Signer --------------------------------------------------------

pub trait Signer:
    crypto::Signer<KeyId = KeyIdentifier> + Clone + Sized + Sync + Send + 'static
{
}
impl<T: crypto::Signer<KeyId = KeyIdentifier> + Clone + Sized + Sync + Send + 'static> Signer
    for T
{
}

//------------ CertSiaInfo ---------------------------------------------------

pub type CaRepository = uri::Rsync;
pub type RpkiManifest = uri::Rsync;
pub type RpkiNotify = uri::Https;

pub struct CertSiaInfo {
    ca_repository: CaRepository,
    rpki_manifest: RpkiManifest,
    rpki_notify: Option<RpkiNotify>,
}

impl CertSiaInfo {
    pub fn new(
        ca_repository: CaRepository,
        rpki_manifest: RpkiManifest,
        rpki_notify: Option<RpkiNotify>,
    ) -> Self {
        CertSiaInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
        }
    }

    pub fn unpack(self) -> (CaRepository, RpkiManifest, Option<RpkiNotify>) {
        (self.ca_repository, self.rpki_manifest, self.rpki_notify)
    }
}

//------------ CaSignSupport -------------------------------------------------

/// Support signing by CAs
pub struct SignSupport;

impl SignSupport {
    /// Publish for the given Key and repository.
    ///
    /// Any updates for existing objects will result in Update, rather
    /// than Publish elements for the PublicationDelta, and the previous
    /// instances will be revoked.
    pub fn publish<S: Signer>(
        ca_key: &CertifiedKey,
        repo_info: &RepoInfo,
        name_space: &str,
        mut objects_delta: ObjectsDelta,
        new_revocations: Vec<Revocation>,
        signer: &S,
    ) -> Result<PublicationDelta, SignError<S>> {
        let aia = ca_key.incoming_cert().uri();
        let key_id = ca_key.key_id();

        let pub_key = signer.get_key_info(key_id).map_err(SignError::KeyError)?;

        let aki = KeyIdentifier::from_public_key(&pub_key);

        let current_set = ca_key.current_set();

        let number = current_set.number() + 1;
        let serial_number = Serial::from(number);

        let now = Time::now();
        let tomorrow = Time::tomorrow();
        let next_week = Time::next_week();

        let mut revocations = current_set.revocations().clone();
        let mut revocations_delta = RevocationsDelta::default();

        for revocation in new_revocations.into_iter() {
            revocations.add(revocation);
            revocations_delta.add(revocation);
        }

        for expired in revocations.purge() {
            revocations_delta.drop(expired);
        }

        let mut current_objects = current_set.objects().clone();

        let mft_name = RepoInfo::mft_name(&pub_key.key_identifier());
        let mft_uri = repo_info.resolve(name_space, &mft_name);
        let old_mft = current_set.objects().object_for(&mft_name);

        // TODO Process other objects, re-issue, revoke, add/remove
        // TODO for now only publish MFT and CRL, revoking old MFTs only
        if let Some(mft) = old_mft {
            let revocation = Revocation::from(mft);
            revocations.add(revocation);
            revocations_delta.add(revocation);
        }

        let crl_name = RepoInfo::crl_name(&pub_key.key_identifier());
        let crl_uri = repo_info.resolve(name_space, &crl_name);

        let crl: Crl = {
            let crl = TbsCertList::new(
                Default::default(),
                pub_key.to_subject_name(),
                now,
                tomorrow,
                revocations.to_crl_entries(),
                aki,
                serial_number,
            );

            crl.into_crl(signer, key_id)
                .map_err(SignError::SigningError)?
        };

        match current_objects.insert(crl_name.clone(), CurrentObject::from(&crl)) {
            None => {
                let added = AddedObject::new(crl_name, CurrentObject::from(&crl));
                objects_delta.add(added);
            }
            Some(old_crl) => {
                let hash = old_crl.content().to_encoded_hash();
                let updated = UpdatedObject::new(crl_name, CurrentObject::from(&crl), hash);
                objects_delta.update(updated);
            }
        }

        let mft: Manifest = {
            let mft_content = ManifestContent::new(
                serial_number,
                now,
                tomorrow,
                DigestAlgorithm::default(),
                current_objects.mft_entries().iter(),
            );

            mft_content
                .into_manifest(
                    SignedObjectBuilder::new(
                        Serial::random(signer).map_err(SignError::SignerError)?,
                        Validity::new(now, next_week),
                        crl_uri,
                        aia.clone(),
                        mft_uri.clone(),
                    ),
                    signer,
                    key_id,
                )
                .map_err(SignError::SigningError)?
        };

        match old_mft {
            None => {
                let added = AddedObject::new(mft_name, CurrentObject::from(&mft));
                objects_delta.add(added);
            }
            Some(old_mft) => {
                let hash = old_mft.content().to_encoded_hash();
                let updated = UpdatedObject::new(mft_name, CurrentObject::from(&mft), hash);
                objects_delta.update(updated);
            }
        }

        Ok(PublicationDelta::new(
            now,
            tomorrow,
            number,
            revocations_delta,
            objects_delta,
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

//------------ SignError -----------------------------------------------------

#[derive(Debug, Display)]
pub enum SignError<S: Signer> {
    #[display(fmt = "{}", _0)]
    SignerError(S::Error),

    #[display(fmt = "{}", _0)]
    KeyError(KeyError<S::Error>),

    #[display(fmt = "{}", _0)]
    SigningError(SigningError<S::Error>),
}
