//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::collections::HashMap;

use bytes::Bytes;

use rpki::crl::{Crl, TbsCertList};
use rpki::crypto::{DigestAlgorithm, KeyIdentifier, PublicKey};
use rpki::manifest::{FileAndHash, Manifest, ManifestContent};
use rpki::sigobj::SignedObjectBuilder;
use rpki::x509::{Serial, Time, Validity};

use crate::commons::api::{
    AddedObject, CurrentObject, HexEncodedHash, IssuedCert, ObjectName, ObjectsDelta, RcvdCert,
    Revocation, Revocations, RevocationsDelta, RouteAuthorization, UpdatedObject, WithdrawnObject,
};

use crate::daemon::ca::{self, RoaInfo, Signer};

//------------ AddedOrUpdated ----------------------------------------------

pub enum AddedOrUpdated {
    Added(AddedObject),
    Updated(UpdatedObject),
}

//------------ ManifestInfo ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestInfo {
    name: ObjectName,
    manifest: Manifest,
    old: Option<HexEncodedHash>,
}

impl ManifestInfo {
    pub fn added_or_updated(&self) -> AddedOrUpdated {
        let name = self.name.clone();
        let object = CurrentObject::from(&self.manifest);
        match self.old.clone() {
            None => AddedOrUpdated::Added(AddedObject::new(name, object)),
            Some(old) => AddedOrUpdated::Updated(UpdatedObject::new(name, object, old)),
        }
    }

    pub fn withdraw(&self) -> WithdrawnObject {
        let name = self.name.clone();
        let hash = HexEncodedHash::from(&self.manifest);
        WithdrawnObject::new(name, hash)
    }
}

impl PartialEq for ManifestInfo {
    fn eq(&self, other: &Self) -> bool {
        self.manifest.to_captured().as_slice() == other.manifest.to_captured().as_slice()
            && self.old == other.old
    }
}

impl Eq for ManifestInfo {}

//------------ CrlInfo -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrlInfo {
    name: ObjectName, // can be derived from CRL, but keeping in mem saves cpu
    crl: Crl,
    old: Option<HexEncodedHash>,
}

impl CrlInfo {
    pub fn added_or_updated(&self) -> AddedOrUpdated {
        let name = self.name.clone();
        let object = CurrentObject::from(&self.crl);
        match self.old.clone() {
            None => AddedOrUpdated::Added(AddedObject::new(name, object)),
            Some(old) => AddedOrUpdated::Updated(UpdatedObject::new(name, object, old)),
        }
    }

    pub fn withdraw(&self) -> WithdrawnObject {
        let name = self.name.clone();
        let hash = HexEncodedHash::from(&self.crl);
        WithdrawnObject::new(name, hash)
    }
}

impl PartialEq for CrlInfo {
    fn eq(&self, other: &Self) -> bool {
        self.crl.to_captured().as_slice() == other.crl.to_captured().as_slice()
            && self.old == other.old
    }
}

impl Eq for CrlInfo {}

//------------ PublicationDelta ----------------------------------------------

/// This type describes a set up of objects published for a CA key.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
        signing_key: &PublicKey,
        signing_cert: &RcvdCert,
        signer: &S,
    ) -> ca::Result<Self> {
        let number = 1;
        let revocations = Revocations::default();
        let (crl_info, _) = CrlBuilder::build(
            revocations.clone(),
            vec![],
            number,
            None,
            signing_key,
            signer,
        )?;

        let manifest_info = ManifestBuilder::with_crl_only(&crl_info).build(
            signing_key,
            signing_cert,
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

    pub fn manifest(&self) -> &Manifest {
        &self.manifest_info.manifest
    }

    pub fn crl_info(&self) -> &CrlInfo {
        &self.crl_info
    }

    pub fn crl(&self) -> &Crl {
        &self.crl_info.crl
    }

    pub fn next_update(&self) -> Time {
        self.manifest().next_update()
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
        signing_key: &PublicKey,
        signer: &S,
    ) -> ca::Result<(CrlInfo, RevocationsDelta)> {
        let aki = KeyIdentifier::from_public_key(signing_key);
        let name = ObjectName::new(&aki, "crl");

        let mut revocations_delta = RevocationsDelta::default();
        for revocation in new_revocations.into_iter() {
            revocations.add(revocation);
            revocations_delta.add(revocation);
        }

        for expired in revocations.purge() {
            revocations_delta.drop(expired);
        }

        let now = Time::five_minutes_ago();
        let tomorrow = Time::tomorrow();
        let serial_number = Serial::from(number);

        let crl = TbsCertList::new(
            Default::default(),
            signing_key.to_subject_name(),
            now,
            tomorrow,
            revocations.to_crl_entries(),
            aki,
            serial_number,
        );

        let crl = crl.into_crl(signer, &aki).map_err(ca::Error::signer)?;

        Ok((CrlInfo { name, crl, old }, revocations_delta))
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
            Self::mft_hash(crl_info.crl.to_captured().as_slice()),
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

        entries.insert(
            crl_info.name.clone().into(),
            Self::mft_hash(crl_info.crl.to_captured().as_slice()),
        );

        for issued in issued {
            let cert = issued.cert();
            let name = ObjectName::from(cert);
            let hash = Self::mft_hash(cert.to_captured().as_slice());

            entries.insert(name.into(), hash);
        }

        for (auth, roa_info) in roas {
            let roa = roa_info.roa();
            let name = ObjectName::from(auth);
            let hash = Self::mft_hash(roa.to_captured().as_slice());

            entries.insert(name.into(), hash);
        }

        for added in delta.added() {
            let name = added.name().clone();
            let hash = Self::mft_hash(added.object().content().to_bytes().as_ref());

            entries.insert(name.into(), hash);
        }

        for updated in delta.updated() {
            let name = updated.name().clone();
            let hash = Self::mft_hash(updated.object().content().to_bytes().as_ref());

            entries.insert(name.into(), hash);
        }

        for withdraw in delta.withdrawn() {
            let name: Bytes = withdraw.name().clone().into();
            entries.remove(&name);
        }

        ManifestBuilder { entries }
    }

    pub fn build<S: Signer>(
        self,
        signing_key: &PublicKey,
        signing_cert: &RcvdCert,
        number: u64,
        old: Option<HexEncodedHash>,
        signer: &S,
    ) -> ca::Result<ManifestInfo> {
        let aia = signing_cert.uri();
        let aki = KeyIdentifier::from_public_key(signing_key);
        let serial_number = Serial::from(number);

        let now = Time::five_minutes_ago();
        let tomorrow = Time::tomorrow();
        let next_week = Time::next_week();

        let entries = self.entries.iter().map(|(k, v)| FileAndHash::new(k, v));

        let manifest: Manifest = {
            let mft_content = ManifestContent::new(
                serial_number,
                now,
                tomorrow,
                DigestAlgorithm::default(),
                entries,
            );

            mft_content
                .into_manifest(
                    SignedObjectBuilder::new(
                        Serial::random(signer).map_err(ca::Error::signer)?,
                        Validity::new(now, next_week),
                        signing_cert.crl_uri(),
                        aia.clone(),
                        signing_cert.mft_uri(),
                    ),
                    signer,
                    &aki,
                )
                .map_err(ca::Error::signer)?
        };

        let name = ObjectName::from(&manifest);

        Ok(ManifestInfo {
            name,
            manifest,
            old,
        })
    }

    fn mft_hash(bytes: &[u8]) -> Bytes {
        Bytes::from(DigestAlgorithm::default().digest(bytes).as_ref())
    }
}
