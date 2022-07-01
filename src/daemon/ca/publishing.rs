//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::{
    borrow::BorrowMut,
    collections::HashMap,
    ops::{Deref, DerefMut},
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use chrono::Duration;

use rpki::{
    ca::{idexchange::CaHandle, provisioning::ResourceClassName, publication::Base64},
    crypto::{DigestAlgorithm, KeyIdentifier},
    repository::{
        aspa::Aspa,
        crl::{Crl, TbsCertList},
        manifest::{FileAndHash, Manifest, ManifestContent},
        roa::Roa,
        sigobj::SignedObjectBuilder,
        x509::{Name, Serial, Time, Validity},
    },
};

use crate::{
    commons::{
        api::{
            rrdp::PublishElement, DelegatedCertificate, ObjectName, RcvdCert, RepositoryContact, Revocation,
            Revocations, Timestamp,
        },
        crypto::KrillSigner,
        error::Error,
        eventsourcing::{KeyStoreKey, KeyValueStore, PreSaveEventListener},
        KrillResult,
    },
    constants::CA_OBJECTS_DIR,
    daemon::{
        ca::{CaEvt, CertAuth, CertifiedKey, ChildCertificateUpdates, RoaUpdates},
        config::IssuanceTimingConfig,
    },
};

use super::{AspaObjectsUpdates, BgpSecCertInfo, BgpSecCertificateUpdates};

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
    issuance_timing: IssuanceTimingConfig,
}

/// # Construct
impl CaObjectsStore {
    pub fn disk(work_dir: &Path, issuance_timing: IssuanceTimingConfig, signer: Arc<KrillSigner>) -> KrillResult<Self> {
        let store = KeyValueStore::disk(work_dir, CA_OBJECTS_DIR)?;
        let store = Arc::new(RwLock::new(store));
        Ok(CaObjectsStore {
            store,
            signer,
            issuance_timing,
        })
    }
}

/// # Process new objects as they are being produced
impl PreSaveEventListener<CertAuth> for CaObjectsStore {
    fn listen(&self, ca: &CertAuth, events: &[CaEvt]) -> KrillResult<()> {
        // Note that the `CertAuth` which is passed in has already been
        // updated with the state changes contained in the event.

        let timing = &self.issuance_timing;
        let signer = &self.signer;

        self.with_ca_objects(ca.handle(), |objects| {
            for event in events {
                match event.details() {
                    super::CaEvtDet::RoasUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_roas(resource_class_name, updates, timing, signer)?;
                    }
                    super::CaEvtDet::AspaObjectsUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_aspas(resource_class_name, updates, timing, signer)?;
                    }
                    super::CaEvtDet::BgpSecCertificatesUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_bgpsec_certs(resource_class_name, updates, timing, signer)?;
                    }
                    super::CaEvtDet::ChildCertificatesUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_certs(resource_class_name, updates, timing, signer)?;
                    }
                    super::CaEvtDet::KeyPendingToActive {
                        resource_class_name,
                        current_key,
                    } => {
                        objects.add_class(resource_class_name, current_key, timing, signer)?;
                    }
                    super::CaEvtDet::KeyPendingToNew {
                        resource_class_name,
                        new_key,
                    } => {
                        objects.keyroll_stage(resource_class_name, new_key, timing, signer)?;
                    }
                    super::CaEvtDet::KeyRollActivated {
                        resource_class_name, ..
                    } => {
                        objects.keyroll_activate(resource_class_name, timing, signer)?;
                    }
                    super::CaEvtDet::KeyRollFinished { resource_class_name } => {
                        objects.keyroll_finish(resource_class_name)?;
                    }
                    super::CaEvtDet::CertificateReceived {
                        resource_class_name,
                        rcvd_cert,
                        ..
                    } => {
                        // Update the received certificate if needed. If the URIs changed we may need to re-issue things
                        objects.update_received_cert(resource_class_name, rcvd_cert)?;
                        objects.re_issue_if_required(&self.issuance_timing, &self.signer)?;
                    }
                    super::CaEvtDet::ResourceClassRemoved {
                        resource_class_name, ..
                    } => {
                        objects.remove_class(resource_class_name);
                    }
                    super::CaEvtDet::RepoUpdated { contact } => {
                        objects.update_repo(contact);
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }
}

impl CaObjectsStore {
    fn key(ca: &CaHandle) -> KeyStoreKey {
        KeyStoreKey::simple(format!("{}.json", ca))
    }

    fn cas(&self) -> KrillResult<Vec<CaHandle>> {
        let cas = self
            .store
            .read()
            .unwrap()
            .keys(None, ".json")?
            .iter()
            .flat_map(|k| {
                // Only add entries that end with .json AND for which the first part can be parsed as a handle
                let mut res = None;
                if let Some(name) = k.name().strip_suffix(".json") {
                    if let Ok(handle) = CaHandle::from_str(name) {
                        res = Some(handle)
                    }
                }
                res
            })
            .collect();
        Ok(cas)
    }

    /// Get objects for this CA, create a new empty CaObjects if there is none.
    pub fn ca_objects(&self, ca: &CaHandle) -> KrillResult<CaObjects> {
        let key = Self::key(ca);

        match self.store.read().unwrap().get(&key).map_err(Error::KeyValueError)? {
            None => {
                let objects = CaObjects::new(ca.clone(), None, HashMap::new(), vec![]);
                Ok(objects)
            }
            Some(objects) => Ok(objects),
        }
    }

    /// Perform an action (closure) on a mutable instance of the CaObjects for a
    /// CA. If the CA did not have any CaObjects yet, one will be created. The
    /// closure is executed within a write lock.
    pub fn with_ca_objects<F>(&self, ca: &CaHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut CaObjects) -> KrillResult<()>,
    {
        let lock = self.store.write().unwrap();

        let key = Self::key(ca);

        let mut objects = lock
            .get(&key)
            .map_err(Error::KeyValueError)?
            .unwrap_or_else(|| CaObjects::new(ca.clone(), None, HashMap::new(), vec![]));

        op(&mut objects)?;

        lock.store(&key, &objects).map_err(Error::KeyValueError)?;

        Ok(())
    }

    pub fn put_ca_objects(&self, ca: &CaHandle, objects: &CaObjects) -> KrillResult<()> {
        self.store
            .write()
            .unwrap()
            .store(&Self::key(ca), objects)
            .map_err(Error::KeyValueError)
    }

    // Re-issue MFT and CRL for all CAs *if needed*, returns all CAs which were updated.
    pub fn reissue_all(&self) -> KrillResult<Vec<CaHandle>> {
        let mut res = vec![];
        for ca in self.cas()? {
            self.with_ca_objects(&ca, |objects| {
                if objects.re_issue_if_required(&self.issuance_timing, &self.signer)? {
                    res.push(ca.clone())
                }
                Ok(())
            })?;
        }
        Ok(res)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaObjects {
    ca: CaHandle,
    repo: Option<RepositoryContact>,

    #[serde(with = "ca_objects_classes_serde")]
    classes: HashMap<ResourceClassName, ResourceClassObjects>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    deprecated_repos: Vec<DeprecatedRepository>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeprecatedRepository {
    contact: RepositoryContact,
    clean_attempts: usize,
}

impl DeprecatedRepository {
    pub fn new(contact: RepositoryContact, clean_attempts: usize) -> Self {
        DeprecatedRepository {
            contact,
            clean_attempts,
        }
    }

    pub fn contact(&self) -> &RepositoryContact {
        &self.contact
    }

    pub fn clean_attempts(&self) -> usize {
        self.clean_attempts
    }

    pub fn inc_clean_attempts(&mut self) {
        self.clean_attempts += 1;
    }
}

impl From<DeprecatedRepository> for RepositoryContact {
    fn from(deprecated: DeprecatedRepository) -> Self {
        deprecated.contact
    }
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
    pub fn new(
        ca: CaHandle,
        repo: Option<RepositoryContact>,
        classes: HashMap<ResourceClassName, ResourceClassObjects>,
        deprecated_repos: Vec<DeprecatedRepository>,
    ) -> Self {
        CaObjects {
            ca,
            repo,
            classes,
            deprecated_repos,
        }
    }

    #[allow(clippy::mutable_key_type)]
    /// Returns all PublishedElements mapped to each RepositoryContact.
    /// There could be more than one repository - although usually there isn't.
    pub fn repo_elements_map(&self) -> HashMap<RepositoryContact, Vec<PublishElement>> {
        let mut res = HashMap::new();

        if let Some(repo) = &self.repo {
            res.insert(repo.clone(), vec![]);

            for resource_class_objects in self.classes.values() {
                // Note the map 'res' will get entries for other (old) repositories
                // if there are any keys with such repositories.
                resource_class_objects.add_elements(&mut res, repo);
            }
        }

        res
    }

    /// Returns all PublishElements in all repositories (if there is more than one).
    pub fn all_publish_elements(&self) -> Vec<PublishElement> {
        let mut all_elements = vec![];

        // slightly inefficient since we drop the RepositoryContact keys again, but this leverages existing code.
        for elements in self.repo_elements_map().values_mut() {
            all_elements.append(elements);
        }

        all_elements
    }

    /// Returns the closest next update time from among manifests held by this CA
    pub fn closest_next_update(&self) -> Option<Timestamp> {
        let mut closest = None;

        for resource_class_objects in self.classes.values() {
            let rco_time = Timestamp::from(resource_class_objects.next_update_time());
            if let Some(current_closest) = closest {
                if current_closest > rco_time {
                    closest = Some(rco_time);
                }
            } else {
                closest = Some(rco_time);
            }
        }

        closest
    }

    pub fn deprecated_repos(&self) -> &Vec<DeprecatedRepository> {
        &self.deprecated_repos
    }

    pub fn deprecated_repo_remove(&mut self, to_remove: &RepositoryContact) {
        self.deprecated_repos.retain(|current| current.contact() != to_remove);
    }

    pub fn deprecated_repo_inc_clean_attempts(&mut self, contact: &RepositoryContact) {
        for current in self.deprecated_repos.iter_mut() {
            if current.contact() == contact {
                current.inc_clean_attempts()
            }
        }
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
        let old_repo_opt = self.classes.get(class_name).and_then(|rco| rco.old_repo()).cloned();

        self.classes.remove(class_name);

        if let Some(old_repo) = old_repo_opt {
            self.deprecate_repo_if_no_longer_used(old_repo);
        }
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
        self.get_class_mut(rcn)?.keyroll_stage(key, timing, signer)
    }

    // Activates the keyset by retiring the current set, and promoting
    // the staging set to current.
    fn keyroll_activate(
        &mut self,
        rcn: &ResourceClassName,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)?.keyroll_activate(timing, signer)
    }

    // Finish a keyroll
    fn keyroll_finish(&mut self, rcn: &ResourceClassName) -> KrillResult<()> {
        let resource_class_objects = self.get_class_mut(rcn)?;

        // finish the key roll for this resource class objects. This will remove the old
        // key, and return an old_repo if there was one.
        if let Some(old_repo) = resource_class_objects.keyroll_finish()? {
            self.deprecate_repo_if_no_longer_used(old_repo);
        }

        Ok(())
    }

    // Update the ROAs in the current set
    fn update_roas(
        &mut self,
        rcn: &ResourceClassName,
        roa_updates: &RoaUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)?.update_roas(roa_updates, timing, signer)
    }

    // Update the ASPAs in the current set
    fn update_aspas(
        &mut self,
        rcn: &ResourceClassName,
        updates: &AspaObjectsUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.update_aspas(updates, timing, signer)
    }

    // Update the BGPSec certificates in the current set
    fn update_bgpsec_certs(
        &mut self,
        rcn: &ResourceClassName,
        updates: &BgpSecCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let rco = self.get_class_mut(rcn)?;
        rco.update_bgpsec_certs(updates, timing, signer)
    }

    // Update the delegated certificates in the current set
    fn update_certs(
        &mut self,
        rcn: &ResourceClassName,
        cert_updates: &ChildCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)?.update_certs(cert_updates, timing, signer)
    }

    // Update the received certificate.
    fn update_received_cert(&mut self, rcn: &ResourceClassName, cert: &RcvdCert) -> KrillResult<()> {
        self.get_class_mut(rcn)?.update_received_cert(cert)
    }

    /// Reissue the MFT and CRL in this set if needed, i.e. if it's close to the next
    /// update time, or in case the AIA has changed.. the latter really should not happen,
    /// but ultimately we have no control over this, so better safe.
    fn re_issue_if_required(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<bool> {
        let hours = timing.timing_publish_hours_before_next;
        let mut required = false;

        for (_, resource_class_objects) in self.classes.iter_mut() {
            if resource_class_objects.requires_re_issuance(hours) {
                required = true;
                resource_class_objects.reissue(timing, signer)?;
            }
        }

        Ok(required)
    }

    // Update the repository.
    //
    // If the repository is being migrated, i.e. there already is a current repository,
    // then make sure that the current repository is preserved as the old repository for
    // existing keys.
    fn update_repo(&mut self, repo: &RepositoryContact) {
        if let Some(old) = &self.repo {
            for resource_class_objects in self.classes.values_mut() {
                resource_class_objects.set_old_repo(old);
            }
        }
        self.repo = Some(repo.clone());
    }

    fn has_old_repo(&self, old_repo: &RepositoryContact) -> bool {
        self.classes.values().any(|rco| rco.has_old_repo(old_repo))
    }

    // Marks a repository as deprecated unless it's (still) in use by any key
    fn deprecate_repo_if_no_longer_used(&mut self, old_repo: RepositoryContact) {
        if !self.has_old_repo(&old_repo) {
            self.deprecated_repos.push(DeprecatedRepository::new(old_repo, 0));
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

    #[allow(clippy::mutable_key_type)]
    /// Adds all the elements for this resource class to the map which is passed on. It will use
    /// the default repository, or an optional old repository if any of the keys had one as part
    /// of a repository migration.
    fn add_elements(&self, map: &mut HashMap<RepositoryContact, Vec<PublishElement>>, dflt_repo: &RepositoryContact) {
        match &self.keys {
            ResourceClassKeyState::Current(state) => state.current_set.add_elements(map, dflt_repo),
            ResourceClassKeyState::Staging(state) => {
                state.current_set.add_elements(map, dflt_repo);
                state.staging_set.add_elements(map, dflt_repo);
            }
            ResourceClassKeyState::Old(state) => {
                state.current_set.add_elements(map, dflt_repo);
                state.old_set.add_elements(map, dflt_repo);
            }
        }
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

    fn keyroll_finish(&mut self) -> KrillResult<Option<RepositoryContact>> {
        match self.keys.clone() {
            ResourceClassKeyState::Old(old) => {
                let current_set = old.current_set;
                self.keys = ResourceClassKeyState::current(current_set);
                Ok(old.old_set.old_repo)
            }
            _ => Err(Error::publishing("published resource class in the wrong key state")),
        }
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

    fn update_aspas(
        &mut self,
        updates: &AspaObjectsUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_aspas(updates, timing, signer),
            ResourceClassKeyState::Staging(state) => state.current_set.update_aspas(updates, timing, signer),
            ResourceClassKeyState::Old(state) => state.current_set.update_aspas(updates, timing, signer),
        }
    }

    fn update_bgpsec_certs(
        &mut self,
        updates: &BgpSecCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_bgpsec_certs(updates, timing, signer),
            ResourceClassKeyState::Staging(state) => state.current_set.update_bgpsec_certs(updates, timing, signer),
            ResourceClassKeyState::Old(state) => state.current_set.update_bgpsec_certs(updates, timing, signer),
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

    fn requires_re_issuance(&self, hours: i64) -> bool {
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

    fn next_update_time(&self) -> Time {
        match &self.keys {
            ResourceClassKeyState::Current(state) => state.current_set.next_update_time(),
            ResourceClassKeyState::Old(state) => state.current_set.next_update_time(),
            ResourceClassKeyState::Staging(state) => state.current_set.next_update_time(),
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

    fn set_old_repo(&mut self, repo: &RepositoryContact) {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.set_old_repo(repo),
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.set_old_repo(repo);
                state.current_set.set_old_repo(repo);
            }
            ResourceClassKeyState::Old(state) => {
                state.old_set.set_old_repo(repo);
                state.current_set.set_old_repo(repo);
            }
        }
    }

    fn has_old_repo(&self, repo: &RepositoryContact) -> bool {
        match &self.keys {
            ResourceClassKeyState::Current(state) => state.current_set.old_repo() == Some(repo),
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.old_repo() == Some(repo) || state.current_set.old_repo() == Some(repo)
            }
            ResourceClassKeyState::Old(state) => {
                state.old_set.old_repo() == Some(repo) || state.current_set.old_repo() == Some(repo)
            }
        }
    }

    fn old_repo(&self) -> Option<&RepositoryContact> {
        // Note: we can only have 1 old repo, because new repositories can only be introduced
        // when there is no key roll in progress. So, it's not possible to introduce a second
        // repo until the previous old_repo is rolled out completely.
        match &self.keys {
            ResourceClassKeyState::Current(state) => state.current_set.old_repo(),
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.old_repo().or_else(|| state.current_set.old_repo())
            }
            ResourceClassKeyState::Old(state) => state.old_set.old_repo().or_else(|| state.current_set.old_repo()),
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

impl CurrentKeyState {
    pub fn new(current_set: CurrentKeyObjectSet) -> Self {
        CurrentKeyState { current_set }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StagingKeyState {
    staging_set: BasicKeyObjectSet,
    current_set: CurrentKeyObjectSet,
}

impl StagingKeyState {
    pub fn new(staging_set: BasicKeyObjectSet, current_set: CurrentKeyObjectSet) -> Self {
        StagingKeyState {
            staging_set,
            current_set,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldKeyState {
    current_set: CurrentKeyObjectSet,
    old_set: BasicKeyObjectSet,
}

impl OldKeyState {
    pub fn new(current_set: CurrentKeyObjectSet, old_set: BasicKeyObjectSet) -> Self {
        OldKeyState { current_set, old_set }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentKeyObjectSet {
    #[serde(flatten)]
    basic: BasicKeyObjectSet,
    #[serde(with = "objects_to_roas_serde")]
    roas: HashMap<ObjectName, PublishedRoa>,
    #[serde(with = "objects_to_aspas_serde", skip_serializing_if = "HashMap::is_empty", default)]
    aspas: HashMap<ObjectName, PublishedAspa>,
    #[serde(
        with = "objects_to_bgpsec_certs_serde",
        skip_serializing_if = "HashMap::is_empty",
        default
    )]
    bgpsec_certs: HashMap<ObjectName, BgpSecCertInfo>,
    #[serde(with = "objects_to_certs_serde")]
    certs: HashMap<ObjectName, PublishedCert>,
}

impl CurrentKeyObjectSet {
    pub fn new(
        basic: BasicKeyObjectSet,
        roas: HashMap<ObjectName, PublishedRoa>,
        aspas: HashMap<ObjectName, PublishedAspa>,
        bgpsec_certs: HashMap<ObjectName, BgpSecCertInfo>,
        certs: HashMap<ObjectName, PublishedCert>,
    ) -> Self {
        CurrentKeyObjectSet {
            basic,
            roas,
            aspas,
            bgpsec_certs,
            certs,
        }
    }

    /// Adds all the elements for this set to the map which is passed on. It will use
    /// the default repository unless this key had an old repository set - as part of
    /// repository migration.
    #[allow(clippy::mutable_key_type)]
    fn add_elements(&self, map: &mut HashMap<RepositoryContact, Vec<PublishElement>>, dflt_repo: &RepositoryContact) {
        let repo = self.old_repo.as_ref().unwrap_or(dflt_repo);

        let base_uri = self.signing_cert.ca_repository();
        let mft_uri = base_uri.join(self.manifest.name().as_bytes()).unwrap();
        let crl_uri = base_uri.join(self.crl.name().as_bytes()).unwrap();

        let elements = map.entry(repo.clone()).or_insert_with(Vec::new);
        elements.push(PublishElement::new(Base64::from(&self.manifest.0), mft_uri));
        elements.push(PublishElement::new(Base64::from(&self.crl.0), crl_uri));

        for (name, roa) in &self.roas {
            elements.push(PublishElement::new(
                Base64::from(&roa.0),
                base_uri.join(name.as_bytes()).unwrap(),
            ));
        }

        for (name, aspa) in &self.aspas {
            elements.push(PublishElement::new(
                Base64::from(&aspa.0),
                base_uri.join(name.as_bytes()).unwrap(),
            ));
        }

        for (name, bgpsec_cert) in &self.bgpsec_certs {
            elements.push(PublishElement::new(
                bgpsec_cert.base64().clone(),
                base_uri.join(name.as_bytes()).unwrap(),
            ));
        }

        for (name, cert) in &self.certs {
            elements.push(PublishElement::new(
                cert.base64().clone(),
                base_uri.join(name.as_bytes()).unwrap(),
            ));
        }
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

    fn update_aspas(
        &mut self,
        updates: &AspaObjectsUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        for aspa_info in updates.updated() {
            let name = ObjectName::aspa(aspa_info.customer());
            let aspa = PublishedAspa::new(aspa_info.aspa().clone());
            if let Some(old) = self.aspas.insert(name, aspa) {
                self.revocations.add(Revocation::from(&old));
            }
        }
        for removed in updates.removed() {
            let name = ObjectName::aspa(*removed);
            if let Some(old) = self.aspas.remove(&name) {
                self.revocations.add(Revocation::from(&old));
            }
        }

        self.reissue(timing, signer)
    }

    fn update_bgpsec_certs(
        &mut self,
        updates: &BgpSecCertificateUpdates,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        for bgpsec_cert in updates.updated() {
            let name = ObjectName::from(bgpsec_cert);
            if let Some(old) = self.bgpsec_certs.insert(name, bgpsec_cert.clone()) {
                self.revocations.add(Revocation::from(&old));
            }
        }

        for removed in updates.removed() {
            let name = ObjectName::from(removed);
            if let Some(old) = self.bgpsec_certs.remove(&name) {
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
                self.revocations.add(old.revoke());
            }
        }

        for issued in cert_updates.issued() {
            if let Some(old) = self.certs.insert(issued.name(), issued.clone().into()) {
                self.revocations.add(old.revoke());
            }
        }

        for cert in cert_updates.unsuspended() {
            self.revocations.remove(&cert.revoke());
            if let Some(old) = self.certs.insert(cert.name(), cert.convert()) {
                // this should not happen, but just to be safe.
                self.revocations.add(old.revoke());
            }
        }

        for suspended in cert_updates.suspended() {
            self.certs.remove(&suspended.name());
            self.revocations.add(suspended.revoke());
        }

        self.reissue(timing, signer)
    }

    fn reissue(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        self.revocations.purge();

        self.crl = self.reissue_crl(&self.revocations, timing, signer)?;
        self.manifest = self.reissue_mft(&self.crl, signer)?;
        self.number = self.next();

        Ok(())
    }

    fn retire(&self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<BasicKeyObjectSet> {
        let mut revocations = self.revocations.clone();
        for roa in self.roas.values() {
            revocations.add(roa.into());
        }

        for cert in self.certs.values() {
            revocations.add(cert.revoke())
        }

        revocations.purge();

        let crl = self.basic.reissue_crl(&revocations, timing, signer)?;
        let manifest = self.basic.reissue_mft(&crl, signer)?;

        Ok(BasicKeyObjectSet {
            signing_cert: self.signing_cert.clone(),
            number: self.next(),
            revocations,
            manifest,
            crl,
            old_repo: self.old_repo.clone(),
        })
    }

    fn reissue_mft(&self, new_crl: &PublishedCrl, signer: &KrillSigner) -> KrillResult<PublishedManifest> {
        ManifestBuilder::with_objects(new_crl, &self.roas, &self.aspas, &self.certs, &self.bgpsec_certs)
            .build_new_mft(&self.signing_cert, self.next(), signer)
            .map(|m| m.into())
    }
}

impl From<BasicKeyObjectSet> for CurrentKeyObjectSet {
    fn from(basic: BasicKeyObjectSet) -> Self {
        CurrentKeyObjectSet {
            basic,
            roas: HashMap::new(),
            aspas: HashMap::new(),
            bgpsec_certs: HashMap::new(),
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

mod objects_to_aspas_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameItem {
        name: ObjectName,
        aspa: PublishedAspa,
    }

    #[derive(Debug, Serialize)]
    struct NameItemRef<'a> {
        name: &'a ObjectName,
        aspa: &'a PublishedAspa,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, PublishedAspa>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, aspa)| NameItemRef { name, aspa }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, PublishedAspa>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameItem>::deserialize(deserializer)? {
            map.insert(item.name, item.aspa);
        }
        Ok(map)
    }
}

mod objects_to_bgpsec_certs_serde {
    use super::*;

    use serde::de::{Deserialize, Deserializer};
    use serde::ser::Serializer;
    #[derive(Debug, Deserialize)]
    struct NameItem {
        name: ObjectName,
        bgpsec_cert: BgpSecCertInfo,
    }

    #[derive(Debug, Serialize)]
    struct NameItemRef<'a> {
        name: &'a ObjectName,
        bgpsec_cert: &'a BgpSecCertInfo,
    }

    pub fn serialize<S>(map: &HashMap<ObjectName, BgpSecCertInfo>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(map.iter().map(|(name, bgpsec_cert)| NameItemRef { name, bgpsec_cert }))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<ObjectName, BgpSecCertInfo>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = HashMap::new();
        for item in Vec::<NameItem>::deserialize(deserializer)? {
            map.insert(item.name, item.bgpsec_cert);
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
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<RepositoryContact>,
}

impl BasicKeyObjectSet {
    pub fn new(
        signing_cert: RcvdCert,
        number: u64,
        revocations: Revocations,
        manifest: PublishedManifest,
        crl: PublishedCrl,
        old_repo: Option<RepositoryContact>,
    ) -> Self {
        BasicKeyObjectSet {
            signing_cert,
            number,
            revocations,
            manifest,
            crl,
            old_repo: None,
        }
    }

    /// Adds all the elements for this set to the map which is passed on. It will use
    /// the default repository unless this key had an old repository set - as part of
    /// repository migration.
    #[allow(clippy::mutable_key_type)]
    fn add_elements(&self, map: &mut HashMap<RepositoryContact, Vec<PublishElement>>, dflt_repo: &RepositoryContact) {
        let repo = self.old_repo.as_ref().unwrap_or(dflt_repo);

        let base_uri = self.signing_cert.ca_repository();
        let mft_uri = base_uri.join(self.manifest.name().as_bytes()).unwrap();
        let crl_uri = base_uri.join(self.crl.name().as_bytes()).unwrap();

        let elements = map.entry(repo.clone()).or_insert_with(Vec::new);
        elements.push(PublishElement::new(Base64::from(&self.manifest.0), mft_uri));
        elements.push(PublishElement::new(Base64::from(&self.crl.0), crl_uri));
    }

    fn create(key: &CertifiedKey, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Self> {
        let signing_cert = key.incoming_cert().clone();

        let signing_key = signing_cert.key_identifier();
        let issuer = signing_cert.subject().clone();
        let revocations = Revocations::default();
        let number = 1;
        let next_update = timing.publish_next();

        let crl = CrlBuilder::build(signing_key, issuer, &revocations, number, next_update, signer)?;

        let manifest = ManifestBuilder::with_crl_only(&crl)
            .build_new_mft(&signing_cert, number, signer)
            .map(|m| m.into())?;

        Ok(BasicKeyObjectSet::new(
            signing_cert,
            number,
            revocations,
            manifest,
            crl,
            None,
        ))
    }

    pub fn requires_reissuance(&self, hours: i64) -> bool {
        Time::now() + Duration::hours(hours) > self.manifest.next_update()
            || Some(self.signing_cert.uri()) != self.manifest.cert().ca_issuer()
    }

    pub fn next_update_time(&self) -> Time {
        self.manifest.next_update()
    }

    fn next(&self) -> u64 {
        self.number + 1
    }

    // Returns an error in case the KeyIdentifiers don't match.
    fn update_signing_cert(&mut self, cert: &RcvdCert) -> KrillResult<()> {
        if self.signing_cert.key_identifier() == cert.key_identifier() {
            self.signing_cert = cert.clone();
            Ok(())
        } else {
            Err(Error::PublishingObjects(format!(
                "received new cert for unknown key id: {}",
                cert.key_identifier()
            )))
        }
    }

    fn reissue(&self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Self> {
        let mut revocations = self.revocations.clone();
        revocations.purge();

        let crl = self.reissue_crl(&revocations, timing, signer)?;
        let manifest = self.reissue_mft(&crl, signer)?;

        Ok(BasicKeyObjectSet {
            signing_cert: self.signing_cert.clone(),
            number: self.next(),
            revocations,
            manifest,
            crl,
            old_repo: self.old_repo.clone(),
        })
    }

    fn reissue_crl(
        &self,
        revocations: &Revocations,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedCrl> {
        let signing_key = self.signing_cert.key_identifier();
        let issuer = self.crl.issuer().clone();
        let number = self.next();

        let next_update = timing.publish_next();

        CrlBuilder::build(signing_key, issuer, revocations, number, next_update, signer)
    }

    fn reissue_mft(&self, new_crl: &PublishedCrl, signer: &KrillSigner) -> KrillResult<PublishedManifest> {
        ManifestBuilder::with_crl_only(new_crl)
            .build_new_mft(&self.signing_cert, self.next(), signer)
            .map(|m| m.into())
    }

    fn set_old_repo(&mut self, repo: &RepositoryContact) {
        self.old_repo = Some(repo.clone())
    }

    fn old_repo(&self) -> Option<&RepositoryContact> {
        self.old_repo.as_ref()
    }
}

//------------ PublishedCert -----------------------------------------------
pub type PublishedCert = DelegatedCertificate;

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

//------------ PublishedAspa ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedAspa(Aspa);

impl PublishedAspa {
    pub fn new(aspa: Aspa) -> Self {
        PublishedAspa(aspa)
    }

    pub fn to_bytes(&self) -> Bytes {
        self.0.to_captured().into_bytes()
    }

    pub fn mft_hash(&self) -> Bytes {
        mft_hash(self.to_bytes().as_ref())
    }
}

impl From<&PublishedAspa> for Revocation {
    fn from(aspa: &PublishedAspa) -> Self {
        Revocation::from(&aspa.0)
    }
}

impl Deref for PublishedAspa {
    type Target = Aspa;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for PublishedAspa {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PublishedAspa {}

//------------ PublishedManifest ------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedManifest(Manifest);

impl PublishedManifest {
    pub fn new(mft: Manifest) -> Self {
        PublishedManifest(mft)
    }

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
    pub fn new(crl: Crl) -> Self {
        PublishedCrl(crl)
    }

    pub fn to_bytes(&self) -> Bytes {
        self.0.to_captured().into_bytes()
    }

    pub fn this_update(&self) -> Time {
        self.0.this_update()
    }

    pub fn next_update(&self) -> Time {
        self.0.next_update()
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

//------------ CrlBuilder --------------------------------------------------

pub struct CrlBuilder {}

impl CrlBuilder {
    pub fn build(
        aki: KeyIdentifier,
        issuer: Name,
        revocations: &Revocations,
        number: u64,
        next_update: Time,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedCrl> {
        let this_update = Time::five_minutes_ago();
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
}

#[allow(clippy::mutable_key_type)]
pub struct ManifestBuilder {
    this_update: Time,
    next_update: Time,
    entries: HashMap<Bytes, Bytes>,
}

impl ManifestBuilder {
    #[allow(clippy::mutable_key_type)]
    pub fn with_objects(
        crl: &PublishedCrl,
        roas: &HashMap<ObjectName, PublishedRoa>,
        aspas: &HashMap<ObjectName, PublishedAspa>,
        certs: &HashMap<ObjectName, PublishedCert>,
        bgpsec_certs: &HashMap<ObjectName, BgpSecCertInfo>,
    ) -> Self {
        let mut entries: HashMap<Bytes, Bytes> = HashMap::new();

        // Add entry for CRL
        entries.insert(crl.name().into(), crl.mft_hash());

        // Add ROAs
        for (name, roa) in roas {
            let hash = roa.mft_hash();
            entries.insert(name.clone().into(), hash);
        }

        // Add ASPAs
        for (name, aspa) in aspas {
            let hash = aspa.mft_hash();
            entries.insert(name.clone().into(), hash);
        }

        // Add all issued certs
        for (name, cert) in certs {
            let hash = cert.hash();
            let hash_bytes = Bytes::copy_from_slice(hash.as_slice());
            entries.insert(name.clone().into(), hash_bytes);
        }

        // Add all bgpsec certs
        for (name, info) in bgpsec_certs {
            let hash = info.base64().to_hash();
            let hash_bytes = Bytes::copy_from_slice(hash.as_slice());
            entries.insert(name.clone().into(), hash_bytes);
        }

        ManifestBuilder {
            this_update: crl.this_update(),
            next_update: crl.next_update(),
            entries,
        }
    }

    #[allow(clippy::mutable_key_type)]
    pub fn with_crl_only(crl: &PublishedCrl) -> Self {
        let mut entries: HashMap<Bytes, Bytes> = HashMap::new();
        entries.insert(crl.name().into(), crl.mft_hash());
        ManifestBuilder {
            this_update: crl.this_update(),
            next_update: crl.next_update(),
            entries,
        }
    }

    fn build_new_mft(self, signing_cert: &RcvdCert, number: u64, signer: &KrillSigner) -> KrillResult<Manifest> {
        let mft_uri = signing_cert.mft_uri();
        let crl_uri = signing_cert.crl_uri();

        let aia = signing_cert.uri();
        let aki = signing_cert.key_identifier();
        let serial_number = Serial::from(number);

        let entries = self.entries.iter().map(|(k, v)| FileAndHash::new(k, v));

        let manifest: Manifest = {
            let mft_content = ManifestContent::new(
                serial_number,
                self.this_update,
                self.next_update,
                DigestAlgorithm::default(),
                entries,
            );
            let mut object_builder = SignedObjectBuilder::new(
                signer.random_serial()?,
                Validity::new(self.this_update, self.next_update),
                crl_uri,
                aia.clone(),
                mft_uri,
            );
            object_builder.set_issuer(Some(signing_cert.subject().clone()));
            object_builder.set_signing_time(Some(Time::now()));

            signer.sign_manifest(mft_content, object_builder, &aki)?
        };

        Ok(manifest)
    }
}

fn mft_hash(bytes: &[u8]) -> Bytes {
    let digest = DigestAlgorithm::default().digest(bytes);
    Bytes::copy_from_slice(digest.as_ref())
}
