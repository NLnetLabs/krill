//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::sync::Arc;

use bytes::Bytes;

use rpki::crl::{Crl, TbsCertList};
use rpki::manifest::{Manifest, ManifestContent, FileAndHash};
use rpki::crypto::{DigestAlgorithm, SigningError};
use rpki::crypto::signer::KeyError;
use rpki::sigobj::SignedObjectBuilder;
use rpki::x509::{Serial, Time, KeyIdentifier, Validity};

use krill_commons::api::ca::{
    AddedObject,
    CaKey,
    CurrentObject,
    ObjectsDelta,
    PublicationDelta,
    RepoInfo,
    Revocation,
    RevocationsDelta,
    UpdatedObject,
};

use crate::trustanchor::CaSigner;


pub struct CaSignSupport;

impl CaSignSupport {

    pub fn publish<S: CaSigner>(
        signer: Arc<S>,
        ca_key: &CaKey,
        repo_info: &RepoInfo,
        name_space: &str
    ) -> Result<PublicationDelta, CaSignError<S>> {

        let aia = ca_key.incoming_cert().uri();
        let signing_cert = ca_key.incoming_cert().cert();
        let key_id = ca_key.key_id();

        let pub_key = signer.get_key_info(key_id).map_err(CaSignError::KeyError)?;

        let aki = KeyIdentifier::from_public_key(&pub_key);

        let current_set = ca_key.current_set();

        let number = current_set.number() + 1;
        let serial_number = Serial::from(number);

        let now = Time::now();
        let tomorrow = Time::tomorrow();
        let next_week = Time::next_week();

        let mut revocations = current_set.revocations().clone();
        let mut revocations_delta = RevocationsDelta::default();

        let mut current_objects = current_set.objects().clone();
        let mut objects_delta = ObjectsDelta::new(repo_info.signed_object(name_space));

        for expired in revocations.purge() {
            revocations_delta.drop(expired);
        }

        let mft_name = RepoInfo::mft_name(&pub_key);
        let mft_uri = repo_info.resolve(name_space, &mft_name);
        let old_mft = current_set.objects().object_for(&mft_name);

        // TODO Process other objects, re-issue, revoke, add/remove
        // TODO for now only publish MFT and CRL, revoking old MFTs only
        if let Some(mft) = old_mft {
            let revocation = Revocation::from(mft);
            revocations.add(revocation.clone());
            revocations_delta.add(revocation);
        }

        let crl_name = RepoInfo::crl_name(&pub_key);
        let crl_uri = repo_info.resolve(name_space, &crl_name);

        let crl: Crl = {
            let mut crl = TbsCertList::new(
                Default::default(),
                pub_key.to_subject_name(),
                now,
                tomorrow,
                revocations.to_crl_entries(),
                aki,
                serial_number
            );

            crl.into_crl(signer.as_ref(), key_id).map_err(CaSignError::SigningError)?
        };

        match current_objects.insert(crl_name.clone(), CurrentObject::from(&crl)) {
            None => {
                let added = AddedObject::new(crl_name, CurrentObject::from(&crl));
                objects_delta.add(added);
            },
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
                current_objects.mft_entries().iter()
            );

            mft_content.into_manifest(
                SignedObjectBuilder::new(
                    Serial::random(signer.as_ref()).map_err(CaSignError::SignerError)?,
                    Validity::new(now, next_week),
                    crl_uri,
                    aia.clone(),
                    mft_uri.clone()
                ),
                signer.as_ref(),
                key_id,
                signing_cert
            ).map_err(CaSignError::SigningError)?
        };

        match old_mft {
            None => {
                let added = AddedObject::new(mft_name, CurrentObject::from(&mft));
                objects_delta.add(added);
            },
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
            objects_delta
        ))
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


//------------ CaSignError ---------------------------------------------------

#[derive(Debug, Display)]
pub enum CaSignError<S: CaSigner> {
    #[display(fmt = "{}", _0)]
    SignerError(S::Error),

    #[display(fmt = "{}", _0)]
    KeyError(KeyError<S::Error>),

    #[display(fmt = "{}", _0)]
    SigningError(SigningError<S::Error>),
}
