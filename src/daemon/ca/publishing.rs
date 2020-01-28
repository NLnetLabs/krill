//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::collections::HashMap;

use bytes::Bytes;

use rpki::crl::{Crl, TbsCertList};
use rpki::crypto::{DigestAlgorithm, KeyIdentifier};
use rpki::manifest::{FileAndHash, Manifest, ManifestContent};
use rpki::sigobj::SignedObjectBuilder;
use rpki::x509::{Serial, Time, Validity};

use crate::commons::api::{
    AddedObject, CurrentObject, HexEncodedHash, IssuedCert, ObjectName, ObjectsDelta, RcvdCert,
    RepoInfo, Revocation, Revocations, RevocationsDelta, UpdatedObject, WithdrawnObject,
};
use crate::commons::KrillResult;
use crate::daemon::ca::{self, RoaInfo, RouteAuthorization, Signer};

//------------ AddedOrUpdated ----------------------------------------------

pub enum AddedOrUpdated {
    Added(AddedObject),
    Updated(UpdatedObject),
}

//------------ ManifestInfo ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManifestInfo {
    name: ObjectName,
    current: CurrentObject,
    next_update: Time,
    old: Option<HexEncodedHash>,
}

impl ManifestInfo {
    pub fn new(mft: &Manifest, old: Option<HexEncodedHash>) -> Self {
        let name = ObjectName::from(mft);
        let current = CurrentObject::from(mft);
        let next_update = mft.next_update();
        ManifestInfo {
            name,
            current,
            next_update,
            old,
        }
    }

    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    pub fn current(&self) -> &CurrentObject {
        &self.current
    }

    pub fn next_update(&self) -> Time {
        self.next_update
    }

    pub fn added_or_updated(&self) -> AddedOrUpdated {
        let name = self.name.clone();
        let object = self.current.clone();
        match self.old.clone() {
            None => AddedOrUpdated::Added(AddedObject::new(name, object)),
            Some(old) => AddedOrUpdated::Updated(UpdatedObject::new(name, object, old)),
        }
    }

    pub fn withdraw(&self) -> WithdrawnObject {
        let name = self.name.clone();
        let hash = self.current.to_hex_hash();
        WithdrawnObject::new(name, hash)
    }
}

//------------ CrlInfo -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrlInfo {
    name: ObjectName, // can be derived from CRL, but keeping in mem saves cpu
    current: CurrentObject,
    old: Option<HexEncodedHash>,
}

impl CrlInfo {
    pub fn new(crl: &Crl, old: Option<HexEncodedHash>) -> Self {
        let name = ObjectName::from(crl);
        let current = CurrentObject::from(crl);
        CrlInfo { name, current, old }
    }

    pub fn name(&self) -> &ObjectName {
        &self.name
    }

    pub fn current(&self) -> &CurrentObject {
        &self.current
    }

    pub fn added_or_updated(&self) -> AddedOrUpdated {
        let name = self.name.clone();
        let object = self.current.clone();
        match self.old.clone() {
            None => AddedOrUpdated::Added(AddedObject::new(name, object)),
            Some(old) => AddedOrUpdated::Updated(UpdatedObject::new(name, object, old)),
        }
    }

    pub fn withdraw(&self) -> WithdrawnObject {
        let name = self.name.clone();
        let hash = self.current.to_hex_hash();
        WithdrawnObject::new(name, hash)
    }
}

//------------ PublicationDelta ----------------------------------------------

/// This type describes a set up of objects published for a CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSetDelta {
    number: u64,
    revocations_delta: RevocationsDelta,
    manifest_info: ManifestInfo,
    crl_info: CrlInfo,
    objects_delta: ObjectsDelta,
}

impl CurrentObjectSetDelta {
    pub fn new(
        number: u64,
        revocations_delta: RevocationsDelta,
        manifest_info: ManifestInfo,
        crl_info: CrlInfo,
        objects_delta: ObjectsDelta,
    ) -> Self {
        CurrentObjectSetDelta {
            number,
            revocations_delta,
            manifest_info,
            crl_info,
            objects_delta,
        }
    }

    pub fn objects(&self) -> &ObjectsDelta {
        &self.objects_delta
    }
}

//------------ CurrentObjectSet ----------------------------------------------

/// This type describes the complete current set of objects for CA key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentObjectSet {
    number: u64,
    revocations: Revocations,
    manifest_info: ManifestInfo,
    crl_info: CrlInfo,
}

impl CurrentObjectSet {
    pub fn create<S: Signer>(
        signing_cert: &RcvdCert,
        repo_info: &RepoInfo,
        name_space: &str,
        signer: &S,
    ) -> KrillResult<Self> {
        let number = 1;
        let revocations = Revocations::default();
        let (crl_info, _) = CrlBuilder::build(
            revocations.clone(),
            vec![],
            number,
            None,
            signing_cert,
            signer,
        )?;

        let manifest_info = ManifestBuilder::with_crl_only(&crl_info).build(
            signing_cert,
            repo_info,
            name_space,
            number,
            None,
            signer,
        )?;

        Ok(CurrentObjectSet {
            number,
            revocations,
            manifest_info,
            crl_info,
        })
    }
}

impl CurrentObjectSet {
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn revocations(&self) -> &Revocations {
        &self.revocations
    }

    pub fn manifest_info(&self) -> &ManifestInfo {
        &self.manifest_info
    }

    pub fn crl_info(&self) -> &CrlInfo {
        &self.crl_info
    }

    pub fn next_update(&self) -> Time {
        self.manifest_info().next_update()
    }

    pub fn apply_delta(&mut self, delta: CurrentObjectSetDelta) {
        self.number = delta.number;
        self.revocations.apply_delta(delta.revocations_delta);
        self.manifest_info = delta.manifest_info;
        self.crl_info = delta.crl_info;
    }
}

//------------ CrlBuilder --------------------------------------------------

pub struct CrlBuilder {}

impl CrlBuilder {
    pub fn build<S: Signer>(
        mut revocations: Revocations,
        new_revocations: Vec<Revocation>,
        number: u64,
        old: Option<HexEncodedHash>,
        signing_cert: &RcvdCert,
        signer: &S,
    ) -> KrillResult<(CrlInfo, RevocationsDelta)> {
        let signing_key = signing_cert.cert().subject_public_key_info();

        let aki = KeyIdentifier::from_public_key(signing_key);

        let mut revocations_delta = RevocationsDelta::default();
        for revocation in new_revocations.into_iter() {
            revocations.add(revocation);
            revocations_delta.add(revocation);
        }

        for expired in revocations.purge() {
            revocations_delta.drop(expired);
        }

        let just_now = Time::five_minutes_ago();
        let tomorrow = Time::tomorrow();
        let serial_number = Serial::from(number);

        let mut crl = TbsCertList::new(
            Default::default(),
            signing_key.to_subject_name(),
            just_now,
            tomorrow,
            revocations.to_crl_entries(),
            aki,
            serial_number,
        );
        crl.set_issuer(signing_cert.cert().subject().clone());

        let crl = crl.into_crl(signer, &aki).map_err(ca::Error::signer)?;

        let crl_info = CrlInfo::new(&crl, old);

        Ok((crl_info, revocations_delta))
    }
}

pub struct ManifestBuilder {
    entries: HashMap<Bytes, Bytes>,
}

impl ManifestBuilder {
    pub fn with_crl_only(crl_info: &CrlInfo) -> Self {
        let mut entries: HashMap<Bytes, Bytes> = HashMap::new();

        entries.insert(
            crl_info.name.clone().into(),
            Self::mft_hash(&crl_info.current().content().to_bytes()),
        );

        ManifestBuilder { entries }
    }

    pub fn new<'a>(
        crl_info: &CrlInfo,
        issued: impl Iterator<Item = &'a IssuedCert>,
        roas: impl Iterator<Item = (&'a RouteAuthorization, &'a RoaInfo)>,
        delta: &ObjectsDelta,
    ) -> Self {
        let mut entries: HashMap<Bytes, Bytes> = HashMap::new();

        // Add the *new* CRL
        entries.insert(
            crl_info.name.clone().into(),
            Self::mft_hash(&crl_info.current().content().to_bytes()),
        );

        // Add all *current* issued certs
        for issued in issued {
            let cert = issued.cert();
            let name = ObjectName::from(cert);
            let hash = Self::mft_hash(cert.to_captured().as_slice());

            entries.insert(name.into(), hash);
        }

        // Add all *current* ROAs
        for (_auth, roa_info) in roas {
            let name = roa_info.name().clone();
            let hash = Self::mft_hash(&roa_info.object().content().to_bytes());

            entries.insert(name.into(), hash);
        }

        // Add all *new* objects
        for added in delta.added() {
            let name = added.name().clone();
            let hash = Self::mft_hash(added.object().content().to_bytes().as_ref());

            entries.insert(name.into(), hash);
        }

        // Add all *updated* objects, note that this may (should) update any ROAs that
        // existed under the same name, but that are now updated (issued under a new key,
        // or validation time).
        for updated in delta.updated() {
            let name = updated.name().clone();
            let hash = Self::mft_hash(updated.object().content().to_bytes().as_ref());

            entries.insert(name.into(), hash);
        }

        // Remove any *withdrawn* objects if present; i.e. removed certs or ROAs.
        for withdraw in delta.withdrawn() {
            let name: Bytes = withdraw.name().clone().into();
            entries.remove(&name);
        }

        ManifestBuilder { entries }
    }

    pub fn build<S: Signer>(
        self,
        signing_cert: &RcvdCert,
        repo_info: &RepoInfo,
        name_space: &str,
        number: u64,
        old: Option<HexEncodedHash>,
        signer: &S,
    ) -> KrillResult<ManifestInfo> {
        let signing_key = signing_cert.cert().subject_public_key_info();

        let signing_ki = signing_key.key_identifier();

        let crl_uri = repo_info.crl_distribution_point(name_space, &signing_ki);
        let mft_uri = repo_info.rpki_manifest(name_space, &signing_ki);

        let aia = signing_cert.uri();
        let aki = KeyIdentifier::from_public_key(signing_key);
        let serial_number = Serial::from(number);

        let just_now = Time::five_minutes_ago();
        let now = Time::now();
        let tomorrow = Time::tomorrow();
        let next_week = Time::next_week();

        let entries = self.entries.iter().map(|(k, v)| FileAndHash::new(k, v));

        let manifest: Manifest = {
            let mft_content = ManifestContent::new(
                serial_number,
                just_now,
                tomorrow,
                DigestAlgorithm::default(),
                entries,
            );
            let mut object_builder = SignedObjectBuilder::new(
                Serial::random(signer).map_err(ca::Error::signer)?,
                Validity::new(just_now, next_week),
                crl_uri,
                aia.clone(),
                mft_uri,
            );
            object_builder.set_issuer(Some(signing_cert.cert().subject().clone()));
            object_builder.set_signing_time(Some(now));

            mft_content
                .into_manifest(object_builder, signer, &aki)
                .map_err(ca::Error::signer)?
        };

        Ok(ManifestInfo::new(&manifest, old))
    }

    fn mft_hash(bytes: &[u8]) -> Bytes {
        Bytes::from(DigestAlgorithm::default().digest(bytes).as_ref())
    }
}
