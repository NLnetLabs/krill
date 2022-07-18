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

use chrono::Duration;

use rpki::{
    ca::{idexchange::CaHandle, provisioning::ResourceClassName, publication::Base64},
    crypto::{DigestAlgorithm, KeyIdentifier},
    repository::{
        crl::{Crl, TbsCertList},
        manifest::{FileAndHash, Manifest, ManifestContent},
        sigobj::SignedObjectBuilder,
        x509::{Name, Serial, Time, Validity},
    },
    rrdp::Hash,
    uri,
};

use crate::{
    commons::{
        api::{
            rrdp::PublishElement, CertInfo, DelegatedCertificate, ObjectName, ReceivedCert, RepositoryContact,
            Revocation, Revocations, Timestamp,
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

use super::{AspaInfo, AspaObjectsUpdates, BgpSecCertInfo, BgpSecCertificateUpdates, RoaInfo};

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
            let mut force_reissue = false;

            for event in events {
                match event.details() {
                    super::CaEvtDet::RoasUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_roas(resource_class_name, updates)?;
                        force_reissue = true;
                    }
                    super::CaEvtDet::AspaObjectsUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_aspas(resource_class_name, updates)?;
                        force_reissue = true;
                    }
                    super::CaEvtDet::BgpSecCertificatesUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_bgpsec_certs(resource_class_name, updates)?;
                        force_reissue = true;
                    }
                    super::CaEvtDet::ChildCertificatesUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_certs(resource_class_name, updates)?;
                        force_reissue = true;
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
                        objects.keyroll_activate(resource_class_name)?;
                        force_reissue = true;
                    }
                    super::CaEvtDet::KeyRollFinished { resource_class_name } => {
                        objects.keyroll_finish(resource_class_name)?;
                    }
                    super::CaEvtDet::CertificateReceived {
                        resource_class_name,
                        rcvd_cert,
                        ..
                    } => {
                        objects.update_received_cert(resource_class_name, rcvd_cert)?;
                        // this in itself constitutes no need to force re-issuance
                        // if the new certificate triggered that the set of objects changed,
                        // e.g. because a ROA became overclaiming, then we would see another
                        // event for that which *will* result in forcing re-issuance.
                    }
                    super::CaEvtDet::ResourceClassRemoved {
                        resource_class_name, ..
                    } => {
                        objects.remove_class(resource_class_name);
                        force_reissue = true;
                    }
                    super::CaEvtDet::RepoUpdated { contact } => {
                        objects.update_repo(contact);
                        force_reissue = true;
                    }
                    _ => {}
                }
            }
            objects.re_issue(force_reissue, timing, signer)?;
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
    pub fn reissue_all(&self, force: bool) -> KrillResult<Vec<CaHandle>> {
        let mut res = vec![];
        for ca in self.cas()? {
            self.with_ca_objects(&ca, |objects| {
                if objects.re_issue(force, &self.issuance_timing, &self.signer)? {
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
    fn keyroll_activate(&mut self, rcn: &ResourceClassName) -> KrillResult<()> {
        self.get_class_mut(rcn)?.keyroll_activate()
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
    fn update_roas(&mut self, rcn: &ResourceClassName, roa_updates: &RoaUpdates) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_roas(roa_updates))
    }

    // Update the ASPAs in the current set
    fn update_aspas(&mut self, rcn: &ResourceClassName, updates: &AspaObjectsUpdates) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_aspas(updates))
    }

    // Update the BGPSec certificates in the current set
    fn update_bgpsec_certs(&mut self, rcn: &ResourceClassName, updates: &BgpSecCertificateUpdates) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_bgpsec_certs(updates))
    }

    // Update the delegated certificates in the current set
    fn update_certs(&mut self, rcn: &ResourceClassName, cert_updates: &ChildCertificateUpdates) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_certs(cert_updates))
    }

    // Update the received certificate.
    fn update_received_cert(&mut self, rcn: &ResourceClassName, cert: &ReceivedCert) -> KrillResult<()> {
        self.get_class_mut(rcn)?.update_received_cert(cert)
    }

    /// Reissue the MFT and CRL
    ///
    /// If force is true, then re-issuance will always be done. I.e. this is to be used
    /// in case any of the content changed. Otherwise re-issuance will only happen if it's
    /// close to the next update time, or the AIA has changed.. the latter may happen if
    /// the parent migrated repositories.
    fn re_issue(&mut self, force: bool, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<bool> {
        let hours = timing.timing_publish_hours_before_next;
        let mut required = false;

        for (_, resource_class_objects) in self.classes.iter_mut() {
            if force || resource_class_objects.requires_re_issuance(hours) {
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

    fn keyroll_activate(&mut self) -> KrillResult<()> {
        self.keys = match &self.keys {
            ResourceClassKeyState::Staging(state) => {
                let old_set = state.current_set.retire()?;
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

    fn update_received_cert(&mut self, updated_cert: &ReceivedCert) -> KrillResult<()> {
        self.keys.update_received_cert(updated_cert)
    }

    fn update_roas(&mut self, roa_updates: &RoaUpdates) {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_roas(roa_updates),
            ResourceClassKeyState::Staging(state) => state.current_set.update_roas(roa_updates),
            ResourceClassKeyState::Old(state) => state.current_set.update_roas(roa_updates),
        }
    }

    fn update_aspas(&mut self, updates: &AspaObjectsUpdates) {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_aspas(updates),
            ResourceClassKeyState::Staging(state) => state.current_set.update_aspas(updates),
            ResourceClassKeyState::Old(state) => state.current_set.update_aspas(updates),
        }
    }

    fn update_bgpsec_certs(&mut self, updates: &BgpSecCertificateUpdates) {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_bgpsec_certs(updates),
            ResourceClassKeyState::Staging(state) => state.current_set.update_bgpsec_certs(updates),
            ResourceClassKeyState::Old(state) => state.current_set.update_bgpsec_certs(updates),
        }
    }

    fn update_certs(&mut self, cert_updates: &ChildCertificateUpdates) {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.update_certs(cert_updates),
            ResourceClassKeyState::Staging(state) => state.current_set.update_certs(cert_updates),
            ResourceClassKeyState::Old(state) => state.current_set.update_certs(cert_updates),
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
            ResourceClassKeyState::Current(state) => state.current_set.next_update(),
            ResourceClassKeyState::Old(state) => state.current_set.next_update(),
            ResourceClassKeyState::Staging(state) => state.current_set.next_update(),
        }
    }

    fn reissue(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        match self.keys.borrow_mut() {
            ResourceClassKeyState::Current(state) => state.current_set.reissue(timing, signer),
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.reissue_set(timing, signer)?;
                state.current_set.reissue(timing, signer)
            }
            ResourceClassKeyState::Old(state) => {
                state.old_set.reissue_set(timing, signer)?;
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

    fn update_received_cert(&mut self, cert: &ReceivedCert) -> KrillResult<()> {
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

    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    published_objects: HashMap<ObjectName, PublishedObject>,
}

impl CurrentKeyObjectSet {
    pub fn new(basic: BasicKeyObjectSet, published_objects: HashMap<ObjectName, PublishedObject>) -> Self {
        CurrentKeyObjectSet {
            basic,
            published_objects,
        }
    }

    /// Adds all the elements for this set to the map which is passed on. It will use
    /// the default repository unless this key had an old repository set - as part of
    /// repository migration.
    #[allow(clippy::mutable_key_type)]
    fn add_elements(&self, map: &mut HashMap<RepositoryContact, Vec<PublishElement>>, dflt_repo: &RepositoryContact) {
        let repo = self.old_repo.as_ref().unwrap_or(dflt_repo);

        let crl_uri = self.signing_cert.crl_uri();
        let mft_uri = self.signing_cert.mft_uri();

        let elements = map.entry(repo.clone()).or_insert_with(Vec::new);

        elements.push(self.manifest.publish_element(mft_uri));
        elements.push(self.crl.publish_element(crl_uri));

        for (name, object) in &self.published_objects {
            elements.push(PublishElement::new(
                object.base64.clone(),
                self.signing_cert.uri_for_name(&name),
            ));
        }
    }

    fn update_roas(&mut self, roa_updates: &RoaUpdates) {
        for (name, roa_info) in roa_updates.added_roas() {
            let published_object = PublishedObject::for_roa(name.clone(), &roa_info);
            if let Some(old) = self.published_objects.insert(name, published_object) {
                self.revocations.add(old.revoke());
            }
        }
        for name in roa_updates.removed_roas() {
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }
    }

    fn update_aspas(&mut self, updates: &AspaObjectsUpdates) {
        for aspa_info in updates.updated() {
            let name = ObjectName::aspa(aspa_info.customer());
            let published_object = PublishedObject::for_aspa(name.clone(), aspa_info);
            if let Some(old) = self.published_objects.insert(name, published_object) {
                self.revocations.add(old.revoke());
            }
        }
        for removed in updates.removed() {
            let name = ObjectName::aspa(*removed);
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }
    }

    fn update_bgpsec_certs(&mut self, updates: &BgpSecCertificateUpdates) {
        for bgpsec_cert_info in updates.updated() {
            let published_object = PublishedObject::for_bgpsec_cert_info(bgpsec_cert_info);
            if let Some(old) = self.published_objects.insert(bgpsec_cert_info.name(), published_object) {
                self.revocations.add(old.revoke());
            }
        }

        for removed in updates.removed() {
            let name = ObjectName::from(removed);
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }
    }

    fn update_certs(&mut self, cert_updates: &ChildCertificateUpdates) {
        for removed in cert_updates.removed() {
            let name = ObjectName::new(removed, "cer");
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }

        for issued in cert_updates.issued() {
            let published_object = PublishedObject::for_cert_info(issued);
            if let Some(old) = self.published_objects.insert(issued.name().clone(), published_object) {
                self.revocations.add(old.revoke());
            }
        }

        for cert in cert_updates.unsuspended() {
            self.revocations.remove(&cert.revocation());
            let published_object = PublishedObject::for_cert_info(cert);
            if let Some(old) = self.published_objects.insert(cert.name().clone(), published_object) {
                // this should not happen, but just to be safe.
                self.revocations.add(old.revoke());
            }
        }

        for suspended in cert_updates.suspended() {
            if let Some(old) = self.published_objects.remove(&suspended.name()) {
                self.revocations.add(old.revoke());
            }
        }
    }

    fn reissue(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        self.revision.next(timing);

        self.revocations.purge();
        let signing_key = self.signing_cert.key_identifier();
        let issuer = self.signing_cert.subject().clone();

        self.crl = CrlBuilder::build(signing_key, issuer, &self.revocations, self.revision, signer)?;

        self.manifest = ManifestBuilder::new(self.revision)
            .with_objects(&self.crl, &self.published_objects)
            .build_new_mft(&self.signing_cert, signer)
            .map(|m| m.into())?;

        Ok(())
    }

    /// Turns this into a BasicObjectSet, revoking and retiring all signed objects.
    fn retire(&self) -> KrillResult<BasicKeyObjectSet> {
        let mut revocations = self.revocations.clone();

        for object in self.published_objects.values() {
            revocations.add(object.revoke());
        }

        revocations.purge();

        let mut basic = self.basic.clone();
        basic.revocations = revocations;

        Ok(basic)
    }
}

impl From<BasicKeyObjectSet> for CurrentKeyObjectSet {
    fn from(basic: BasicKeyObjectSet) -> Self {
        CurrentKeyObjectSet {
            basic,
            published_objects: HashMap::new(),
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BasicKeyObjectSet {
    signing_cert: ReceivedCert,
    revision: ObjectSetRevision,
    revocations: Revocations,
    manifest: PublishedManifest,
    crl: PublishedCrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<RepositoryContact>,
}

impl BasicKeyObjectSet {
    pub fn new(
        signing_cert: ReceivedCert,
        revision: ObjectSetRevision,
        revocations: Revocations,
        manifest: PublishedManifest,
        crl: PublishedCrl,
        old_repo: Option<RepositoryContact>,
    ) -> Self {
        BasicKeyObjectSet {
            signing_cert,
            revision,
            revocations,
            manifest,
            crl,
            old_repo,
        }
    }

    /// Adds all the elements for this set to the map which is passed on. It will use
    /// the default repository unless this key had an old repository set - as part of
    /// repository migration.
    #[allow(clippy::mutable_key_type)]
    fn add_elements(&self, map: &mut HashMap<RepositoryContact, Vec<PublishElement>>, dflt_repo: &RepositoryContact) {
        let repo = self.old_repo.as_ref().unwrap_or(dflt_repo);

        let crl_uri = self.signing_cert.crl_uri();
        let mft_uri = self.signing_cert.mft_uri();

        let elements = map.entry(repo.clone()).or_insert_with(Vec::new);

        elements.push(self.manifest.publish_element(mft_uri));
        elements.push(self.crl.publish_element(crl_uri));
    }

    fn create(key: &CertifiedKey, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<Self> {
        let signing_cert = key.incoming_cert().clone();

        let signing_key = signing_cert.key_identifier();
        let issuer = signing_cert.subject().clone();
        let revocations = Revocations::default();
        let revision = ObjectSetRevision::create(timing);

        let crl = CrlBuilder::build(signing_key, issuer, &revocations, revision, signer)?;

        let manifest = ManifestBuilder::new(revision)
            .with_crl_only(&crl)
            .build_new_mft(&signing_cert, signer)
            .map(|m| m.into())?;

        Ok(BasicKeyObjectSet::new(
            signing_cert,
            revision,
            revocations,
            manifest,
            crl,
            None,
        ))
    }

    pub fn requires_reissuance(&self, hours: i64) -> bool {
        Time::now() + Duration::hours(hours) > self.next_update()
    }

    pub fn next_update(&self) -> Time {
        self.revision.next_update
    }

    // Returns an error in case the KeyIdentifiers don't match.
    fn update_signing_cert(&mut self, cert: &ReceivedCert) -> KrillResult<()> {
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

    fn reissue_set(&mut self, timing: &IssuanceTimingConfig, signer: &KrillSigner) -> KrillResult<()> {
        self.revision.next(timing);

        self.revocations.purge();
        let signing_key = self.signing_cert.key_identifier();
        let issuer = self.signing_cert.subject().clone();

        self.crl = CrlBuilder::build(signing_key, issuer, &self.revocations, self.revision, signer)?;

        self.manifest = ManifestBuilder::new(self.revision)
            .with_crl_only(&self.crl)
            .build_new_mft(&self.signing_cert, signer)
            .map(|m| m.into())?;

        Ok(())
    }

    fn set_old_repo(&mut self, repo: &RepositoryContact) {
        self.old_repo = Some(repo.clone())
    }

    fn old_repo(&self) -> Option<&RepositoryContact> {
        self.old_repo.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectSetRevision {
    number: u64,
    this_update: Time, // backdated 5 minutes to tolerate some clock skew
    next_update: Time,
}

impl ObjectSetRevision {
    pub fn new(number: u64, this_update: Time, next_update: Time) -> Self {
        ObjectSetRevision {
            number,
            this_update,
            next_update,
        }
    }
    fn create(timing: &IssuanceTimingConfig) -> Self {
        ObjectSetRevision {
            number: 1,
            this_update: Time::five_minutes_ago(),
            next_update: timing.publish_next(),
        }
    }

    fn next(&mut self, timing: &IssuanceTimingConfig) {
        self.number += 1;
        self.this_update = Time::five_minutes_ago();
        self.next_update = timing.publish_next();
    }
}

//------------ PublishedCert -----------------------------------------------
pub type PublishedCert = DelegatedCertificate;

//------------ PublishedItem ----------------------------------------------

/// Any item published in the repository.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItem<T> {
    name: ObjectName,
    base64: Base64,
    hash: Hash, // derived from base64 but kept for faster access

    serial: Serial,
    expires: Time,

    // So that we can have different types based on the same structure.
    marker: std::marker::PhantomData<T>,
}

impl<T> PublishedItem<T> {
    pub fn new(name: ObjectName, base64: Base64, serial: Serial, expires: Time) -> Self {
        let hash = base64.to_hash();

        PublishedItem {
            name,
            base64,
            hash,
            serial,
            expires,
            marker: std::marker::PhantomData,
        }
    }

    pub fn publish_element(&self, uri: uri::Rsync) -> PublishElement {
        PublishElement::new(self.base64.clone(), uri)
    }

    pub fn revoke(&self) -> Revocation {
        Revocation::new(self.serial, self.expires)
    }
}

//------------ PublishedManifest ------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItemManifest;
pub type PublishedManifest = PublishedItem<PublishedItemManifest>;

impl From<Manifest> for PublishedManifest {
    fn from(mft: Manifest) -> Self {
        PublishedItem::new(
            ObjectName::from(&mft),
            Base64::from(&mft),
            mft.cert().serial_number(),
            mft.next_update(),
        )
    }
}

//------------ PublishedCrl ------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItemCrl;
pub type PublishedCrl = PublishedItem<PublishedItemCrl>;

impl From<Crl> for PublishedCrl {
    fn from(crl: Crl) -> Self {
        PublishedItem::new(
            ObjectName::from(&crl),
            Base64::from(&crl),
            crl.crl_number(), // Just use this, we won't actually revoke CRLs
            crl.next_update(),
        )
    }
}

//------------ PublishedObject ---------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItemOther;
pub type PublishedObject = PublishedItem<PublishedItemOther>;

impl PublishedObject {
    pub fn for_roa(name: ObjectName, roa_info: &RoaInfo) -> Self {
        PublishedObject::new(name, roa_info.base64().clone(), roa_info.serial(), roa_info.expires())
    }

    pub fn for_aspa(name: ObjectName, aspa_info: &AspaInfo) -> Self {
        PublishedObject::new(
            name,
            aspa_info.base64().clone(),
            aspa_info.serial(),
            aspa_info.expires(),
        )
    }

    pub fn for_cert_info<T>(cert: &CertInfo<T>) -> Self {
        PublishedObject::new(
            cert.name().clone(),
            cert.base64().clone(),
            cert.serial(),
            cert.expires(),
        )
    }

    pub fn for_bgpsec_cert_info(cert: &BgpSecCertInfo) -> Self {
        PublishedObject::new(
            cert.name().clone(),
            cert.base64().clone(),
            cert.serial(),
            cert.expires(),
        )
    }
}

//------------ CrlBuilder --------------------------------------------------

pub struct CrlBuilder {}

impl CrlBuilder {
    pub fn build(
        aki: KeyIdentifier,
        issuer: Name,
        revocations: &Revocations,
        revision: ObjectSetRevision,
        signer: &KrillSigner,
    ) -> KrillResult<PublishedCrl> {
        let serial_number = Serial::from(revision.number);

        let crl = TbsCertList::new(
            Default::default(),
            issuer,
            revision.this_update,
            revision.next_update,
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
    revision: ObjectSetRevision,
    entries: HashMap<ObjectName, Hash>,
}

impl ManifestBuilder {
    pub fn new(revision: ObjectSetRevision) -> Self {
        ManifestBuilder {
            revision,
            entries: HashMap::new(),
        }
    }

    #[allow(clippy::mutable_key_type)]
    pub fn with_objects(
        mut self,
        crl: &PublishedCrl,
        published_objects: &HashMap<ObjectName, PublishedObject>,
    ) -> Self {
        // Add entry for CRL
        self.entries.insert(crl.name.clone(), crl.hash);

        // Add other objects
        for (name, object) in published_objects {
            self.entries.insert(name.clone(), object.hash);
        }

        self
    }

    #[allow(clippy::mutable_key_type)]
    pub fn with_crl_only(mut self, crl: &PublishedCrl) -> Self {
        self.entries.insert(crl.name.clone(), crl.hash);
        self
    }

    fn build_new_mft(self, signing_cert: &ReceivedCert, signer: &KrillSigner) -> KrillResult<Manifest> {
        let mft_uri = signing_cert.mft_uri();
        let crl_uri = signing_cert.crl_uri();

        let aia = signing_cert.uri();
        let aki = signing_cert.key_identifier();
        let serial_number = Serial::from(self.revision.number);

        let entries = self.entries.iter().map(|(k, v)| FileAndHash::new(k, v));

        let manifest: Manifest = {
            let mft_content = ManifestContent::new(
                serial_number,
                self.revision.this_update,
                self.revision.next_update,
                DigestAlgorithm::default(),
                entries,
            );
            let mut object_builder = SignedObjectBuilder::new(
                signer.random_serial()?,
                Validity::new(self.revision.this_update, self.revision.next_update),
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
