//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::{
    borrow::BorrowMut,
    collections::HashMap,
    ops::{Deref, DerefMut},
    str::FromStr,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use chrono::Duration;

use rpki::{
    cert::Cert,
    crl::{Crl, TbsCertList},
    crypto::{DigestAlgorithm, KeyIdentifier, PublicKey},
    manifest::{FileAndHash, Manifest, ManifestContent},
    roa::Roa,
    sigobj::SignedObjectBuilder,
    x509::{Name, Serial, Time, Validity},
};

use crate::{
    commons::{
        api::{
            AddedObject, CurrentObject, Handle, HexEncodedHash, IssuedCert, ObjectName, ObjectsDelta, RcvdCert,
            ResourceClassName, Revocation, Revocations, RevocationsDelta, UpdatedObject, WithdrawnObject,
        },
        crypto::KrillSigner,
        error::Error,
        eventsourcing::{KeyStoreKey, KeyValueStore, SyncEventListener},
        KrillResult,
    },
    constants::CA_OBJECTS_DIR,
    daemon::{
        ca::{CaEvt, CertAuth, RoaInfo, RouteAuthorization},
        config::{Config, IssuanceTimingConfig},
    },
};

use super::{CertifiedKey, ChildCertificateUpdates, RoaUpdates};

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
#[derive(Clone, Debug)]
pub struct CaObjectsStore {
    store: Arc<RwLock<KeyValueStore>>,
    signer: Arc<KrillSigner>,
    config: Arc<Config>,
}

/// # Construct
impl CaObjectsStore {
    pub fn disk(config: Arc<Config>, signer: Arc<KrillSigner>) -> KrillResult<Self> {
        let work_dir = &config.data_dir;
        let store = KeyValueStore::disk(work_dir, CA_OBJECTS_DIR)?;
        let store = Arc::new(RwLock::new(store));
        Ok(CaObjectsStore { store, config, signer })
    }
}

/// # Process new objects as they are being produced
impl SyncEventListener<CertAuth> for CaObjectsStore {
    fn listen(&self, ca: &CertAuth, events: &[CaEvt]) -> KrillResult<()> {
        // Note that the `CertAuth` which is passed in has already been
        // updated with the state changes contained in the event.

        let timing = &self.config.issuance_timing;
        let signer = &self.signer;

        self.with_ca_objects(ca.handle(), |objects| {
            for event in events {
                match event.details() {
                    super::CaEvtDet::RoasUpdated(rcn, roa_updates) => {
                        objects.update_roas(rcn, roa_updates, timing, signer)?;
                    }
                    super::CaEvtDet::ChildCertificatesUpdated(rcn, cert_updates) => {
                        objects.update_certs(rcn, cert_updates, timing, signer)?;
                    }
                    super::CaEvtDet::KeyPendingToActive(rcn, key, _) => {
                        objects.add_class(rcn, key, timing, signer)?;
                    }
                    super::CaEvtDet::KeyPendingToNew(rcn, key, _) => {
                        objects.keyroll_stage(rcn, key, timing, signer)?;
                    }
                    super::CaEvtDet::KeyRollActivated(rcn, _) => {
                        objects.keyroll_activate(rcn, timing, signer)?;
                    }
                    super::CaEvtDet::KeyRollFinished(rcn, _) => {
                        objects.keyroll_finish(rcn)?;
                    }
                    super::CaEvtDet::CertificateReceived(rcn, _ki, cert) => {
                        // Update the received certificate if needed. If the URIs changed we may need to re-issue things
                        objects.update_received_cert(rcn, cert)?;
                        objects.re_issue_if_required(&self.config.issuance_timing, &self.signer)?;
                    }
                    super::CaEvtDet::ResourceClassRemoved(rcn, _, _, _) => {
                        objects.remove_class(rcn);
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }
}

impl CaObjectsStore {
    fn key(ca: &Handle) -> KeyStoreKey {
        KeyStoreKey::simple(format!("{}.json", ca))
    }

    fn cas(&self) -> KrillResult<Vec<Handle>> {
        let cas = self
            .store
            .read()
            .unwrap()
            .keys(None, ".json")?
            .iter()
            .map(|k| Handle::from_str(k.name()).unwrap()) // These are always supposed to be safe
            .collect();
        Ok(cas)
    }

    /// Get objects for this CA, create a new empty CaObjects if there is none.
    pub fn ca_objects(&self, ca: &Handle) -> KrillResult<CaObjects> {
        let key = Self::key(ca);

        match self.store.read().unwrap().get(&key).map_err(Error::KeyValueError)? {
            None => {
                let objects = CaObjects::new(ca.clone(), HashMap::new());
                Ok(objects)
            }
            Some(objects) => Ok(objects),
        }
    }

    fn with_ca_objects<F>(&self, ca: &Handle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut CaObjects) -> KrillResult<()>,
    {
        let mut objects = self.ca_objects(ca)?;
        op(&mut objects)?;
        self.put_ca_objects(ca, &objects)?;
        Ok(())
    }

    pub fn put_ca_objects(&self, ca: &Handle, objects: &CaObjects) -> KrillResult<()> {
        self.store
            .write()
            .unwrap()
            .store(&Self::key(ca), objects)
            .map_err(Error::KeyValueError)
    }

    // Re-issue MFT and CRL for all CAs (if needed)
    pub fn reissue_all(&self) -> KrillResult<()> {
        let mut failures = false;
        let mut failure_msg = "".to_string();
        for ca in self.cas()? {
            if let Err(e) = self.with_ca_objects(&ca, |objects| {
                objects.re_issue_if_required(&self.config.issuance_timing, &self.signer)
            }) {
                failures = true;
                failure_msg.push_str(&format!(" CA '{}', Error: '{}'", ca, e));
            }
        }
        if failures {
            Err(Error::Custom(format!("Reissuance failure(s) found: {}", failure_msg)))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaObjects {
    ca: Handle,
    #[serde(with = "ca_objects_classes_serde")]
    classes: HashMap<ResourceClassName, ResourceClassObjects>,
}

mod ca_objects_classes_serde {

    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct ClassesItem {
        class_name: ResourceClassName,
        objects: ResourceClassObjects,
    }

    #[derive(Debug, Serialize)]
    struct ClassesItemRef<'a> {
        class_name: &'a ResourceClassName,
        objects: &'a ResourceClassObjects,
    }

    pub fn serialize<S>(
        map: &HashMap<ResourceClassName, ResourceClassObjects>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(
            map.iter()
                .map(|(class_name, objects)| ClassesItemRef { class_name, objects }),
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ResourceClassName, ResourceClassObjects>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<ClassesItem>::deserialize(deserializer)? {
            map.insert(item.class_name, item.objects);
        }
        Ok(map)
    }
}

impl CaObjects {
    pub fn new(ca: Handle, classes: HashMap<ResourceClassName, ResourceClassObjects>) -> Self {
        CaObjects { ca, classes }
    }

    /// Add a new resource class, this returns an error in case the class already exists.
    fn add_class(
        &mut self,
        class_name: &ResourceClassName,
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        if self.classes.contains_key(class_name) {
            Err(Error::publishing("Duplicate resource class"))
        } else {
            self.classes
                .insert(class_name.clone(), ResourceClassObjects::create(key, timing, signer)?);
            Ok(())
        }
    }

    fn remove_class(&mut self, class_name: &ResourceClassName) {
        self.classes.remove(class_name);
    }

    fn get_class_mut(&mut self, rcn: &ResourceClassName) -> KrillResult<&mut ResourceClassObjects> {
        self.classes
            .get_mut(rcn)
            .ok_or_else(|| Error::publishing("Missing resource class"))
    }

    // Add a staging key to the set, this will fail in case the class is missing, or in case
    // the class is not in state 'current'.
    fn keyroll_stage(
        &mut self,
        rcn: &ResourceClassName,
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.keyroll_stage(key, timing, signer)
    }

    // Activates the keyset by retiring the current set, and promoting
    // the staging set to current.
    fn keyroll_activate(
        &mut self,
        rcn: &ResourceClassName,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.keyroll_activate(timing, signer)
    }

    // Finish a keyroll
    fn keyroll_finish(&mut self, rcn: &ResourceClassName) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.keyroll_finish()
    }

    // Update the ROAs in the current set
    fn update_roas(
        &mut self,
        rcn: &ResourceClassName,
        roa_updates: &RoaUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.update_roas(roa_updates, timing, signer)
    }

    // Update the delegated certificates in the current set
    fn update_certs(
        &mut self,
        rcn: &ResourceClassName,
        cert_updates: &ChildCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.update_certs(cert_updates, timing, signer)
    }

    // Update the received certificate.
    fn update_received_cert(&mut self, rcn: &ResourceClassName, cert: &RcvdCert) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.update_received_cert(cert)
    }

    /// Reissue the MFT and CRL in this set if needed, i.e. if it's close to the next
    /// update time, or in case the AIA has changed.. the latter really should not happen,
    /// but ultimately we have no control over this, so better safe.
    fn re_issue_if_required(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        let hours = timing.timing_publish_hours_before_next;

        let required = self.classes.values().any(|rco| rco.requires_reissuance(hours));

        if !required {
            Ok(())
        } else {
            for (_, rco) in self.classes.iter_mut() {
                if rco.requires_reissuance(hours) {
                    rco.reissue(timing, signer)?;
                }
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassObjects {
    keys: ResourceClassKeyState,
}

impl ResourceClassObjects {
    pub fn new(keys: ResourceClassKeyState) -> Self {
        ResourceClassObjects { keys }
    }

    fn create(key: &CertifiedKey, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Self> {
        let current_set = BasicKeyObjectSet::create(key, timing, signer)?.into();

        Ok(ResourceClassObjects {
            keys: ResourceClassKeyState::Current(CurrentKeyState { current_set }),
        })
    }

    fn keyroll_stage(
        &mut self,
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let current_set = match &self.keys {
            ResourceClassKeyState::Current(state) => state.current_set.clone(),
            _ => return Err(Error::publishing("published resource class in the wrong key state")),
        };

        let staging_set = BasicKeyObjectSet::create(key, timing, signer)?;

        self.keys = ResourceClassKeyState::Staging(StagingKeyState {
            staging_set,
            current_set,
        });

        Ok(())
    }

    fn keyroll_activate(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        self.keys = match &self.keys {
            ResourceClassKeyState::Staging(state) => {
                let old_set = state.current_set.retire(timing, signer)?;
                let current_set = state.staging_set.clone().into();
                ResourceClassKeyState::Old(OldKeyState { current_set, old_set })
            }
            _ => return Err(Error::publishing("published resource class in the wrong key state")),
        };

        Ok(())
    }

    fn keyroll_finish(&mut self) -> KrillResult<()> {
        self.keys = match &self.keys {
            ResourceClassKeyState::Old(old) => {
                let current_set = old.current_set.clone();
                ResourceClassKeyState::current(current_set)
            }
            _ => return Err(Error::publishing("published resource class in the wrong key state")),
        };

        Ok(())
    }

    fn update_received_cert(&mut self, updated_cert: &RcvdCert) -> KrillResult<()> {
        self.keys.update_received_cert(updated_cert)
    }

    fn update_roas(
        &mut self,
        roa_updates: &RoaUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_roas(roa_updates, timing, signer),
            ResourceClassKeyState::Staging(state) => state.current_set.update_roas(roa_updates, timing, signer),
            ResourceClassKeyState::Old(state) => state.current_set.update_roas(roa_updates, timing, signer),
        }
    }

    fn update_certs(
        &mut self,
        cert_updates: &ChildCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_certs(cert_updates, timing, signer),
            ResourceClassKeyState::Staging(state) => state.current_set.update_certs(cert_updates, timing, signer),
            ResourceClassKeyState::Old(state) => state.current_set.update_certs(cert_updates, timing, signer),
        }
    }

    fn requires_reissuance(&self, hours: i64) -> bool {
        match &self.keys {
            ResourceClassKeyState::Current(state) => state.current_set.requires_reissuance(hours),
            ResourceClassKeyState::Old(state) => {
                state.old_set.requires_reissuance(hours) || state.current_set.requires_reissuance(hours)
            }
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.requires_reissuance(hours) || state.current_set.requires_reissuance(hours)
            }
        }
    }

    fn reissue(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.reissue(timing, signer),
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.reissue(timing, signer)?;
                state.current_set.reissue(timing, signer)
            }
            ResourceClassKeyState::Old(state) => {
                state.old_set.reissue(timing, signer)?;
                state.current_set.reissue(timing, signer)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceClassKeyState {
    Current(CurrentKeyState),
    Staging(StagingKeyState),
    Old(OldKeyState),
}

impl ResourceClassKeyState {
    pub fn current(current_set: CurrentKeyObjectSet) -> Self {
        ResourceClassKeyState::Current(CurrentKeyState { current_set })
    }

    pub fn staging(staging_set: BasicKeyObjectSet, current_set: CurrentKeyObjectSet) -> Self {
        ResourceClassKeyState::Staging(StagingKeyState {
            staging_set,
            current_set,
        })
    }

    pub fn old(current_set: CurrentKeyObjectSet, old_set: BasicKeyObjectSet) -> Self {
        ResourceClassKeyState::Old(OldKeyState { current_set, old_set })
    }

    fn update_received_cert(&mut self, cert: &RcvdCert) -> KrillResult<()> {
        match self {
            ResourceClassKeyState::Current(state) => state.current_set.update_signing_cert(cert),
            ResourceClassKeyState::Staging(state) => {
                if state.staging_set.update_signing_cert(cert).is_ok() {
                    Ok(())
                } else {
                    state.current_set.update_signing_cert(cert)
                }
            }
            ResourceClassKeyState::Old(state) => {
                if state.old_set.update_signing_cert(cert).is_ok() {
                    Ok(())
                } else {
                    state.current_set.update_signing_cert(cert)
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentKeyState {
    current_set: CurrentKeyObjectSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StagingKeyState {
    staging_set: BasicKeyObjectSet,
    current_set: CurrentKeyObjectSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldKeyState {
    current_set: CurrentKeyObjectSet,
    old_set: BasicKeyObjectSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentKeyObjectSet {
    #[serde(flatten)]
    basic: BasicKeyObjectSet,
    #[serde(with = "objects_to_roas_serde")]
    roas: HashMap<ObjectName, PublishedRoa>,
    #[serde(with = "objects_to_certs_serde")]
    certs: HashMap<ObjectName, PublishedCert>,
}

impl CurrentKeyObjectSet {
    pub fn new(
        signing_cert: RcvdCert,
        number: u64,
        revocations: Revocations,
        manifest: PublishedManifest,
        crl: PublishedCrl,
        roas: HashMap<ObjectName, PublishedRoa>,
        certs: HashMap<ObjectName, PublishedCert>,
    ) -> Self {
        let basic = BasicKeyObjectSet {
            signing_cert,
            number,
            revocations,
            manifest,
            crl,
        };
        CurrentKeyObjectSet { basic, roas, certs }
    }

    fn update_roas(
        &mut self,
        roa_updates: &RoaUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        for (name, roa) in roa_updates.added_roas()? {
            if let Some(old) = self.roas.insert(name, roa) {
                self.revocations.add(Revocation::from(&old));
            }
        }
        for name in roa_updates.removed_roas() {
            if let Some(old) = self.roas.remove(&name) {
                self.revocations.add(Revocation::from(&old));
            }
        }

        self.reissue(timing, signer)
    }

    fn update_certs(
        &mut self,
        cert_updates: &ChildCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        for removed in cert_updates.removed() {
            let name = ObjectName::new(removed, "cer");
            if let Some(old) = self.certs.remove(&name) {
                self.revocations.add(Revocation::from(&old));
            }
        }

        for issued in cert_updates.issued() {
            let name = ObjectName::from(issued.cert());
            if let Some(old) = self.certs.insert(name, issued.clone().into()) {
                self.revocations.add(Revocation::from(&old));
            }
        }

        self.reissue(timing, signer)
    }

    fn reissue(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        self.revocations.purge();

        self.crl = self.reissue_crl(&self.revocations, timing, signer)?;
        self.manifest = self.reissue_mft(&self.crl, timing, signer)?;
        self.number = self.next();

        Ok(())
    }

    fn retire(&self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<BasicKeyObjectSet> {
        let mut revocations = self.revocations.clone();
        for roa in self.roas.values() {
            revocations.add(roa.into());
        }

        for cert in self.certs.values() {
            revocations.add(cert.into())
        }

        revocations.purge();

        let crl = self.basic.reissue_crl(&revocations, timing, signer)?;
        let manifest = self.basic.reissue_mft(&crl, timing, signer)?;

        Ok(BasicKeyObjectSet {
            signing_cert: self.signing_cert.clone(),
            number: self.next(),
            revocations,
            manifest,
            crl,
        })
    }

    fn reissue_mft(
        &self,
        new_crl: &PublishedCrl,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedManifest> {
        ManifestBuilder::with_objects(new_crl, &self.roas, &self.certs)
            .build_new_mft(&self.signing_cert, self.next(), timing, signer)
            .map(|m| m.into())
    }
}

impl From<BasicKeyObjectSet> for CurrentKeyObjectSet {
    fn from(basic: BasicKeyObjectSet) -> Self {
        CurrentKeyObjectSet {
            basic,
            roas: HashMap::new(),
            certs: HashMap::new(),
        }
    }
}

impl Deref for CurrentKeyObjectSet {
    type Target = BasicKeyObjectSet;

    fn deref(&self) -> &Self::Target {
        &self.basic
    }
}

impl DerefMut for CurrentKeyObjectSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.basic
    }
}

mod objects_to_roas_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameRoaItem {
        name: ObjectName,
        roa: PublishedRoa,
    }

    #[derive(Debug, Serialize)]
    struct NameRoaItemRef<'a> {
        name: &'a ObjectName,
        roa: &'a PublishedRoa,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, PublishedRoa>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, roa)| NameRoaItemRef { name, roa }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, PublishedRoa>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameRoaItem>::deserialize(deserializer)? {
            map.insert(item.name, item.roa);
        }
        Ok(map)
    }
}

mod objects_to_certs_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameCertItem {
        name: ObjectName,
        issued: PublishedCert,
    }

    #[derive(Debug, Serialize)]
    struct NameCertItemRef<'a> {
        name: &'a ObjectName,
        issued: &'a PublishedCert,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, PublishedCert>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, issued)| NameCertItemRef { name, issued }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, PublishedCert>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameCertItem>::deserialize(deserializer)? {
            map.insert(item.name, item.issued);
        }
        Ok(map)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BasicKeyObjectSet {
    signing_cert: RcvdCert,
    number: u64,
    revocations: Revocations,
    manifest: PublishedManifest,
    crl: PublishedCrl,
}

impl BasicKeyObjectSet {
    pub fn new(
        signing_cert: RcvdCert,
        number: u64,
        revocations: Revocations,
        manifest: PublishedManifest,
        crl: PublishedCrl,
    ) -> Self {
        BasicKeyObjectSet {
            signing_cert,
            number,
            revocations,
            manifest,
            crl,
        }
    }

    fn create(key: &CertifiedKey, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Self> {
        let signing_cert = key.incoming_cert().clone();

        let signing_key = signing_cert.subject_public_key_info();
        let issuer = signing_cert.subject().clone();
        let revocations = Revocations::default();
        let number = 1;
        let next_hours = timing.timing_publish_next_hours;

        let crl = CrlBuilder::build(signing_key, issuer, &revocations, number, next_hours, signer)?;

        let manifest = ManifestBuilder::with_crl_only(&crl)
            .build_new_mft(&signing_cert, number, timing, signer)
            .map(|m| m.into())?;

        Ok(BasicKeyObjectSet::new(signing_cert, number, revocations, manifest, crl))
    }

    pub fn requires_reissuance(&self, hours: i64) -> bool {
        Time::now() + Duration::hours(hours) > self.manifest.next_update()
            || Some(self.signing_cert.uri()) != self.manifest.cert().ca_issuer()
    }

    fn next(&self) -> u64 {
        self.number + 1
    }

    // Returns an error in case the KeyIdentifiers don't match.
    fn update_signing_cert(&mut self, cert: &RcvdCert) -> KrillResult<()> {
        if self.signing_cert.subject_key_identifier() == cert.subject_key_identifier() {
            self.signing_cert = cert.clone();
            Ok(())
        } else {
            Err(Error::publishing("received new cert for unknown keyid"))
        }
    }

    fn reissue(&self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Self> {
        let mut revocations = self.revocations.clone();
        revocations.purge();

        let crl = self.reissue_crl(&revocations, timing, signer)?;
        let manifest = self.reissue_mft(&crl, timing, signer)?;

        Ok(BasicKeyObjectSet {
            signing_cert: self.signing_cert.clone(),
            number: self.next(),
            revocations,
            manifest,
            crl,
        })
    }

    fn reissue_crl(
        &self,
        revocations: &Revocations,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedCrl> {
        let signing_key = self.signing_cert.subject_public_key_info();
        let issuer = self.crl.issuer().clone();
        let number = self.next();

        let next_hours = timing.timing_publish_next_hours;

        CrlBuilder::build(signing_key, issuer, revocations, number, next_hours, signer)
    }

    fn reissue_mft(
        &self,
        new_crl: &PublishedCrl,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedManifest> {
        ManifestBuilder::with_crl_only(new_crl)
            .build_new_mft(&self.signing_cert, self.next(), timing, signer)
            .map(|m| m.into())
    }
}

//------------ AddedOrUpdated ----------------------------------------------

pub enum AddedOrUpdated {
    Added(AddedObject),
    Updated(UpdatedObject),
}

//------------ PublishedCert -----------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedCert(IssuedCert);

impl PublishedCert {
    pub fn to_bytes(&self) -> Bytes {
        self.0.to_captured().into_bytes()
    }

    pub fn mft_hash(&self) -> Bytes {
        mft_hash(self.to_bytes().as_ref())
    }
}

impl From<IssuedCert> for PublishedCert {
    fn from(issued: IssuedCert) -> Self {
        PublishedCert(issued)
    }
}

impl From<&PublishedCert> for Revocation {
    fn from(c: &PublishedCert) -> Self {
        Revocation::from(c.0.cert())
    }
}

impl Deref for PublishedCert {
    type Target = IssuedCert;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Cert> for PublishedCert {
    fn as_ref(&self) -> &Cert {
        &self.0.as_ref()
    }
}

//------------ PublishedRoa -----------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedRoa(Roa);

impl PublishedRoa {
    pub fn new(roa: Roa) -> Self {
        PublishedRoa(roa)
    }

    pub fn to_bytes(&self) -> Bytes {
        self.0.to_captured().into_bytes()
    }

    pub fn mft_hash(&self) -> Bytes {
        mft_hash(self.to_bytes().as_ref())
    }
}

impl From<&PublishedRoa> for Revocation {
    fn from(r: &PublishedRoa) -> Self {
        Revocation::from(&r.0)
    }
}

impl Deref for PublishedRoa {
    type Target = Roa;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for PublishedRoa {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublishedRoa {}

//------------ PublishedManifest ------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedManifest(Manifest);

impl PublishedManifest {
    pub fn to_bytes(&self) -> Bytes {
        self.0.to_captured().into_bytes()
    }

    pub fn name(&self) -> ObjectName {
        ObjectName::from(&self.0)
    }

    pub fn next_update(&self) -> Time {
        self.0.next_update()
    }
}

impl PartialEq for PublishedManifest {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublishedManifest {}

impl From<Manifest> for PublishedManifest {
    fn from(mft: Manifest) -> Self {
        PublishedManifest(mft)
    }
}

impl Deref for PublishedManifest {
    type Target = Manifest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//------------ PublishedCrl ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedCrl(Crl);

impl PublishedCrl {
    pub fn to_bytes(&self) -> Bytes {
        self.0.to_captured().into_bytes()
    }

    pub fn name(&self) -> ObjectName {
        ObjectName::from(&self.0)
    }

    pub fn mft_hash(&self) -> Bytes {
        mft_hash(self.to_bytes().as_ref())
    }
}

impl PartialEq for PublishedCrl {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublishedCrl {}

impl From<Crl> for PublishedCrl {
    fn from(crl: Crl) -> Self {
        PublishedCrl(crl)
    }
}

impl Deref for PublishedCrl {
    type Target = Crl;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//------------ ManifestInfo ------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[deprecated]
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

    fn for_manifest(mft: &Manifest, old: Option<HexEncodedHash>) -> Self {
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
#[deprecated]
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
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Self> {
        let number = 1;
        let revocations = Revocations::default();
        let (crl_info, _) = CrlBuilder::build_deprecated(
            revocations.clone(),
            vec![],
            number,
            None,
            signing_cert,
            issuance_timing.timing_publish_next_hours,
            signer,
        )?;

        let crl = Crl::decode(crl_info.current().content().to_bytes()).unwrap().into();
        let roas = HashMap::new();
        let certs = HashMap::new();

        let manifest_info = ManifestBuilder::with_objects(&crl, &roas, &certs).build(
            signing_cert,
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
        signing_key: &PublicKey,
        issuer: Name,
        revocations: &Revocations,
        number: u64,
        next_hours: i64,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedCrl> {
        let aki = KeyIdentifier::from_public_key(signing_key);

        let this_update = Time::five_minutes_ago();
        let next_update = Time::now() + Duration::hours(next_hours);
        let serial_number = Serial::from(number);

        let crl = TbsCertList::new(
            Default::default(),
            issuer,
            this_update,
            next_update,
            revocations.to_crl_entries(),
            aki,
            serial_number,
        );

        let crl = signer.sign_crl(crl, &aki)?;

        Ok(crl.into())
    }

    #[deprecated]
    pub fn build_deprecated(
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
    pub fn with_objects(
        crl: &PublishedCrl,
        roas: &HashMap<ObjectName, PublishedRoa>,
        certs: &HashMap<ObjectName, PublishedCert>,
    ) -> Self {
        let mut entries: HashMap<Bytes, Bytes> = HashMap::new();

        // Add entry for CRL
        entries.insert(crl.name().into(), crl.mft_hash());

        // Add ROAs
        for (name, roa) in roas {
            let hash = roa.mft_hash();
            entries.insert(name.clone().into(), hash);
        }

        // Add all issued certs
        for (name, cert) in certs {
            let hash = cert.mft_hash();
            entries.insert(name.clone().into(), hash);
        }

        ManifestBuilder { entries }
    }

    #[allow(clippy::mutable_key_type)]
    pub fn with_crl_only(crl: &PublishedCrl) -> Self {
        let mut entries: HashMap<Bytes, Bytes> = HashMap::new();
        entries.insert(crl.name().into(), crl.mft_hash());
        ManifestBuilder { entries }
    }

    #[deprecated]
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
            mft_hash(&crl_info.current().content().to_bytes()),
        );

        // Add all *current* issued certs
        for issued in issued {
            let cert = issued.cert();
            let name = ObjectName::from(cert);
            let hash = mft_hash(cert.to_captured().as_slice());

            entries.insert(name.into(), hash);
        }

        // Add all *current* ROAs
        for (_auth, roa_info) in roas {
            let name = roa_info.name().clone();
            let hash = mft_hash(&roa_info.object().content().to_bytes());

            entries.insert(name.into(), hash);
        }

        // Add all *new* objects
        for added in delta.added() {
            let name = added.name().clone();
            let hash = mft_hash(added.object().content().to_bytes().as_ref());

            entries.insert(name.into(), hash);
        }

        // Add all *updated* objects, note that this may (should) update any ROAs that
        // existed under the same name, but that are now updated (issued under a new key,
        // or validation time).
        for updated in delta.updated() {
            let name = updated.name().clone();
            let hash = mft_hash(updated.object().content().to_bytes().as_ref());

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
        number: u64,
        old: Option<HexEncodedHash>,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<ManifestInfo> {
        let manifest = self.build_new_mft(signing_cert, number, issuance_timing, signer)?;
        Ok(ManifestInfo::for_manifest(&manifest, old))
    }

    fn build_new_mft(
        self,
        signing_cert: &RcvdCert,
        number: u64,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Manifest> {
        let signing_key = signing_cert.cert().subject_public_key_info();

        let mft_uri = signing_cert.mft_uri();
        let crl_uri = signing_cert.crl_uri();

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

        Ok(manifest)
    }
}

fn mft_hash(bytes: &[u8]) -> Bytes {
    let digest = DigestAlgorithm::default().digest(bytes);
    Bytes::copy_from_slice(digest.as_ref())
}

#[cfg(test)]
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
