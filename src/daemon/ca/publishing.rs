//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::{collections::HashMap, path::PathBuf};

use std::sync::RwLock;

use bytes::Bytes;
use chrono::Duration;

use rpki::crl::{Crl, TbsCertList};
use rpki::crypto::{DigestAlgorithm, KeyIdentifier};
use rpki::manifest::{FileAndHash, Manifest, ManifestContent};
use rpki::sigobj::SignedObjectBuilder;
use rpki::x509::{Serial, Time, Validity};

use crate::commons::error::Error;
use crate::commons::eventsourcing::KeyValueStore;
use crate::commons::KrillResult;
use crate::commons::{crypto::KrillSigner, eventsourcing::KeyStoreKey};
use crate::daemon::ca::{RoaInfo, RouteAuthorization};
use crate::daemon::config::IssuanceTimingConfig;
use crate::{
    commons::api::{
        AddedObject, CurrentObject, Handle, HexEncodedHash, IssuedCert, ObjectName, ObjectsDelta, RcvdCert, RepoInfo,
        ResourceClassName, Revocation, Revocations, RevocationsDelta, UpdatedObject, WithdrawnObject,
    },
    constants::CA_OBJECTS_DIR,
};

//------------ CaObjectsStore ----------------------------------------------

/// This component is responsible for storing the latest objects for each CA.
///
/// By using a stateful store for this purpose we can generate Manifests and
/// CRLs outside of the normal event-sourcing framework used to track the
/// history and state of CAs. I.e. we treat the frequent republish cycle as
/// something that does not intrinsically modify the CA itself.
///
/// In earlier generations of Krill the simple republish operation to generate
/// new Manifests and CRLs was done through the event sourcing framework. However,
/// this led to excessive use of disk space, makes the history more difficult to
/// inspect, and causes issues with regards to replaying CA state from scratch.
pub struct CaObjectsStore {
    store: RwLock<KeyValueStore>,
}

/// # Construct
impl CaObjectsStore {
    pub fn disk(work_dir: &PathBuf) -> KrillResult<Self> {
        let store = KeyValueStore::disk(work_dir, CA_OBJECTS_DIR)?;
        let store = RwLock::new(store);
        Ok(CaObjectsStore { store })
    }
}

impl CaObjectsStore {
    fn key(ca: &Handle) -> KeyStoreKey {
        KeyStoreKey::simple(format!("{}.json", ca))
    }

    pub fn ca_objects(&self, ca: &Handle) -> KrillResult<Option<CaObjects>> {
        self.store
            .read()
            .unwrap()
            .get(&Self::key(ca))
            .map_err(Error::KeyValueError)
    }

    pub fn put_ca_objects(&self, ca: &Handle, objects: &CaObjects) -> KrillResult<()> {
        self.store
            .write()
            .unwrap()
            .store(&Self::key(ca), objects)
            .map_err(Error::KeyValueError)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaObjects(#[serde(with = "ca_objects_items")] HashMap<ResourceClassName, ResourceClassObjects>);

mod ca_objects_items {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;

    #[derive(Debug, Deserialize)]
    struct CaObjectsItem {
        class_name: ResourceClassName,
        keys: ResourceClassObjects,
    }

    #[derive(Debug, Serialize)]
    struct CaObjectsItemRef<'a> {
        class_name: &'a ResourceClassName,
        keys: &'a ResourceClassObjects,
    }

    pub fn serialize<S>(
        map: &HashMap<ResourceClassName, ResourceClassObjects>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(k, v)| CaObjectsItemRef { class_name: k, keys: v }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ResourceClassName, ResourceClassObjects>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<CaObjectsItem>::deserialize(deserializer)? {
            map.insert(item.class_name, item.keys);
        }
        Ok(map)
    }
}

impl Default for CaObjects {
    fn default() -> Self {
        CaObjects(HashMap::new())
    }
}

impl CaObjects {
    pub fn new(objects: HashMap<ResourceClassName, ResourceClassObjects>) -> Self {
        CaObjects(objects)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassObjects(#[serde(with = "key_objects_items")] HashMap<KeyIdentifier, ObjectSet>);

mod key_objects_items {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;

    #[derive(Debug, Deserialize)]
    struct KeyObjectsItem {
        key: KeyIdentifier,
        object_set: ObjectSet,
    }

    #[derive(Debug, Serialize)]
    struct KeyObjectsItemRef<'a> {
        key: &'a KeyIdentifier,
        object_set: &'a ObjectSet,
    }

    pub fn serialize<S>(map: &HashMap<KeyIdentifier, ObjectSet>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(k, v)| KeyObjectsItemRef { key: k, object_set: v }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<KeyIdentifier, ObjectSet>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<KeyObjectsItem>::deserialize(deserializer)? {
            map.insert(item.key, item.object_set);
        }
        Ok(map)
    }
}

impl Default for ResourceClassObjects {
    fn default() -> Self {
        ResourceClassObjects(HashMap::new())
    }
}

impl ResourceClassObjects {
    pub fn add_key(&mut self, ki: KeyIdentifier, objects: ObjectSet) {
        self.0.insert(ki, objects);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectSet {
    number: u64,
    revocations: Revocations,
    manifest: ManifestInfo,
    crl: CrlInfo,
    roas: Vec<RoaObject>,
    certs: Vec<IssuedCertObject>,
}

impl ObjectSet {
    pub fn new(
        number: u64,
        revocations: Revocations,
        manifest: ManifestInfo,
        crl: CrlInfo,
        roas: Vec<RoaObject>,
        certs: Vec<IssuedCertObject>,
    ) -> Self {
        ObjectSet {
            number,
            revocations,
            manifest,
            crl,
            roas,
            certs,
        }
    }
}

//------------ AddedOrUpdated ----------------------------------------------

pub enum AddedOrUpdated {
    Added(AddedObject),
    Updated(UpdatedObject),
}

//------------ IssuedCertInfo ----------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuedCertObject {
    name: ObjectName,
    current: CurrentObject,
}

impl From<&IssuedCert> for IssuedCertObject {
    fn from(issued: &IssuedCert) -> Self {
        let name = ObjectName::from(issued.cert());
        let current = CurrentObject::from(issued.cert());
        IssuedCertObject { name, current }
    }
}

//------------ RoaObjectInfo -----------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoaObject {
    name: ObjectName,
    current: CurrentObject,
}

impl RoaObject {
    pub fn new(name: ObjectName, current: CurrentObject) -> Self {
        RoaObject { name, current }
    }
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
    pub fn new(name: ObjectName, current: CurrentObject, next_update: Time, old: Option<HexEncodedHash>) -> Self {
        ManifestInfo {
            name,
            current,
            next_update,
            old,
        }
    }

    pub fn for_manifest(mft: &Manifest, old: Option<HexEncodedHash>) -> Self {
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
    pub fn new(name: ObjectName, current: CurrentObject, old: Option<HexEncodedHash>) -> Self {
        CrlInfo { name, current, old }
    }
    pub fn for_crl(crl: &Crl, old: Option<HexEncodedHash>) -> Self {
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
    pub fn create(
        signing_cert: &RcvdCert,
        repo_info: &RepoInfo,
        name_space: &str,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Self> {
        let number = 1;
        let revocations = Revocations::default();
        let (crl_info, _) = CrlBuilder::build(
            revocations.clone(),
            vec![],
            number,
            None,
            signing_cert,
            issuance_timing.timing_publish_next_hours,
            signer,
        )?;

        let manifest_info = ManifestBuilder::with_crl_only(&crl_info).build(
            signing_cert,
            repo_info,
            name_space,
            number,
            None,
            issuance_timing,
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
    pub fn build(
        mut revocations: Revocations,
        new_revocations: Vec<Revocation>,
        number: u64,
        old: Option<HexEncodedHash>,
        signing_cert: &RcvdCert,
        next_hours: i64,
        signer: &KrillSigner,
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

        let this_update = Time::five_minutes_ago();
        let next_update = Time::now() + Duration::hours(next_hours);
        let serial_number = Serial::from(number);

        let mut crl = TbsCertList::new(
            Default::default(),
            signing_key.to_subject_name(),
            this_update,
            next_update,
            revocations.to_crl_entries(),
            aki,
            serial_number,
        );
        crl.set_issuer(signing_cert.cert().subject().clone());

        let crl = signer.sign_crl(crl, &aki)?;

        let crl_info = CrlInfo::for_crl(&crl, old);

        Ok((crl_info, revocations_delta))
    }
}

#[allow(clippy::mutable_key_type)]
pub struct ManifestBuilder {
    entries: HashMap<Bytes, Bytes>,
}

impl ManifestBuilder {
    #[allow(clippy::mutable_key_type)]
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
        #[allow(clippy::mutable_key_type)]
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

    #[allow(clippy::too_many_arguments)]
    pub fn build(
        self,
        signing_cert: &RcvdCert,
        repo_info: &RepoInfo,
        name_space: &str,
        number: u64,
        old: Option<HexEncodedHash>,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<ManifestInfo> {
        let signing_key = signing_cert.cert().subject_public_key_info();

        let signing_ki = signing_key.key_identifier();

        let crl_uri = repo_info.crl_distribution_point(name_space, &signing_ki);
        let mft_uri = repo_info.rpki_manifest(name_space, &signing_ki);

        let aia = signing_cert.uri();
        let aki = KeyIdentifier::from_public_key(signing_key);
        let serial_number = Serial::from(number);

        let this_update = Time::five_minutes_ago();
        let now = Time::now();
        let next_update = Time::now() + Duration::hours(issuance_timing.timing_publish_next_hours);
        let valid_until = Time::now() + Duration::days(issuance_timing.timing_publish_valid_days);

        let entries = self.entries.iter().map(|(k, v)| FileAndHash::new(k, v));

        let manifest: Manifest = {
            let mft_content = ManifestContent::new(
                serial_number,
                this_update,
                next_update,
                DigestAlgorithm::default(),
                entries,
            );
            let mut object_builder = SignedObjectBuilder::new(
                signer.random_serial()?,
                Validity::new(this_update, valid_until),
                crl_uri,
                aia.clone(),
                mft_uri,
            );
            object_builder.set_issuer(Some(signing_cert.cert().subject().clone()));
            object_builder.set_signing_time(Some(now));

            signer.sign_manifest(mft_content, object_builder, &aki)?
        };

        Ok(ManifestInfo::for_manifest(&manifest, old))
    }

    fn mft_hash(bytes: &[u8]) -> Bytes {
        let digest = DigestAlgorithm::default().digest(bytes);
        Bytes::copy_from_slice(digest.as_ref())
    }
}

mod test {

    use super::*;

    #[test]
    pub fn ca_objects_ser_de() {
        let json = include_str!("../../../test-resources/ca_objects_store/ca_objects.json");
        let ca_objects: CaObjects = serde_json::from_str(json).unwrap();

        let serialized = serde_json::to_string(&ca_objects).unwrap();
        let ca_objects_again: CaObjects = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ca_objects, ca_objects_again);
    }
}
