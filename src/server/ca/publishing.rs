//! Management of objects published by a CA.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use chrono::Duration;
use log::debug;
use rpki::{rrdp, uri};
use rpki::ca::idexchange::CaHandle;
use rpki::ca::provisioning::ResourceClassName;
use rpki::ca::publication::Base64;
use rpki::crypto::{DigestAlgorithm, KeyIdentifier};
use rpki::repository::crl::{Crl, TbsCertList};
use rpki::repository::manifest::{FileAndHash, Manifest, ManifestContent};
use rpki::repository::sigobj::SignedObjectBuilder;
use rpki::repository::x509::{Name, Serial, Time, Validity};
use serde::{Deserialize, Serialize};
use url::Url;
use crate::api::admin::{PublishedFile, RepositoryContact};
use crate::api::ca::{
    CertInfo, IssuedCertificate, ObjectName, ReceivedCert, Revocation,
    Revocations,
};
use crate::api::roa::RoaInfo;
use crate::commons::KrillResult;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::Error;
use crate::commons::eventsourcing::PreSaveEventListener;
use crate::commons::storage::{Ident, KeyValueStore};
use crate::constants::CA_OBJECTS_NS;
use crate::config::IssuanceTimingConfig;
use crate::server::manager::KrillHandle;
use super::aspa::{AspaInfo, AspaObjectsUpdates};
use super::bgpsec::{BgpSecCertInfo, BgpSecCertificateUpdates};
use super::certauth::CertAuth;
use super::child::ChildCertificateUpdates;
use super::events::CertAuthEvent;
use super::keys::CertifiedKey; 
use super::roa::RoaUpdates;


//------------ CaObjectsStore ----------------------------------------------

/// The component storing the latest objects for each CA.
///
/// By using a stateful store for this purpose we can generate manifests and
/// CRLs outside of the normal event-sourcing framework used to track the
/// history and state of CAs. I.e., we treat the frequent republish cycle as
/// something that does not intrinsically modify the CA itself.
///
/// In earlier generations of Krill the simple republish operation to generate
/// new manifests and CRLs was done through the event sourcing framework.
/// However, this led to excessive use of disk space, makes the history more
/// difficult to inspect, and causes issues with regards to replaying CA state
/// from scratch.
///
/// # Key-value store usage
///
/// The CA objects store uses the key-value store directly. It uses the
/// namespace defined by [`CA_OBJECTS_NS`], currently `"ca_objects"`. For
/// each CA, it keeps a single value under the single-element scope of the
/// CA’s handle suffixed by `.json`.
#[derive(Debug)]
pub struct CaObjectsStore {
    /// The key-value store where objects are stored.
    store: KeyValueStore,
}

impl CaObjectsStore {
    /// Creates a new CA objects store using the given configuration.
    pub fn create(storage_uri: &Url) -> KrillResult<Self> {
        let store = KeyValueStore::create(
            storage_uri, CA_OBJECTS_NS
        )?;
        Ok(CaObjectsStore {
            store,
        })
    }
}

impl CaObjectsStore {
    /// Returns the key for the given CA to be used in the store.
    fn key(ca: &CaHandle) -> Box<Ident> {
        // XXX This seems quite expensive to do. Maybe we should use the
        //     handle as the scope and a static identifier for the key?
        //
        //     This would need a migration, though.
        Ident::builder(
            Ident::from_handle(ca).into_owned()
        ).finish_with_extension(
            const { Ident::make("json") }
        )
    }

    /// Returns all CA handles present in the object store.
    pub fn cas(&self) -> KrillResult<Vec<CaHandle>> {
        // XXX The previous code only added keys that could directly be
        //     parsed as handles. We keep to this for now because we convert
        //     both slashes and backslashes into plusses and so can’t quite
        //     distinguish the two cases. This ought to be changed once
        //     we got rid of backslashes.
        Ok(
            self.store.keys(None, ".json")?.iter().filter_map(|k| {
                let name = k.as_str().strip_suffix(".json")?;
                CaHandle::from_str(name).ok()
            }).collect()
        )
    }

    /// Removes a CA from the store.
    pub fn remove_ca(&self, ca: &CaHandle) -> KrillResult<()> {
        let ca_key = Self::key(ca);
        self.store.execute(None, |kv| {
            if kv.has(None, &ca_key)? {
                kv.delete(None, &ca_key)
            } else {
                Ok(())
            }
        }).map_err(Error::KeyValueError)
    }

    /// Loads the CA objects for this CA.
    ///
    /// If the CA isn’t present in the store yet, creates a new empty
    /// CA objects value and returns it.
    pub fn ca_objects(&self, ca: &CaHandle) -> KrillResult<CaObjects> {
        match self.store.get(
            None, &Self::key(ca)
        ).map_err(Error::KeyValueError)? {
            None => Ok(CaObjects::new(ca.clone())),
            Some(objects) => Ok(objects),
        }
    }

    /// Performs an action on the CA objects for a CA.
    ///
    /// If the CA did not have any CA objects yet, one will be created. The
    /// closure is executed within a store-wide write lock.
    pub fn with_ca_objects<F, T>(
        &self,
        ca: &CaHandle,
        op: F,
    ) -> KrillResult<T>
    where
        F: Fn(&mut CaObjects) -> KrillResult<T>,
    {
        self.store.execute(None, |kv| {
            let key = Self::key(ca);

            let mut objects: CaObjects = match kv.get(None, &key)? {
                Some(value) => value,
                None => CaObjects::new(ca.clone()),
            };

            match op(&mut objects) {
                Err(e) => Ok(Err(e)),
                Ok(t) => {
                    kv.store(None, &key, &objects)?;
                    Ok(Ok(t))
                }
            }
        }).map_err(Error::KeyValueError)?
    }

    /// Re-issues manifests and CRLs for the CA if needed.
    ///
    /// If `force` is `true`, forces a re-issue. Returns whether it did
    /// re-issue.
    pub fn reissue_if_needed(
        &self,
        force: bool,
        ca_handle: &CaHandle,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<bool> {
        debug!("Re-issue for CA {ca_handle} using force: {force}");
        self.with_ca_objects(ca_handle, |objects| {
            objects.re_issue(force, issuance_timing, signer)
        })
    }
}


//------------CaObjects ------------------------------------------------------

/// All the published objects of a CA.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaObjects {
    /// The handle of the CA.
    ca: CaHandle,

    /// The repository the CA publishes too.
    ///
    /// This is `None` if there isn’t a repository assigned yet.
    repo: Option<RepositoryContact>,

    /// The resource classes and their published objects.
    classes: HashMap<ResourceClassName, ResourceClassObjects>,

    /// Repositories we consider deprecated and are trying to remove.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    deprecated_repos: Vec<DeprecatedRepository>,
}

impl CaObjects {
    /// Creates a new CA objects with only the handle assigned yet.
    pub fn new(
        ca: CaHandle,
    ) -> Self {
        CaObjects {
            ca,
            repo: None,
            classes: HashMap::new(),
            deprecated_repos: Vec::new(),
        }
    }

    /// Creates a CA objects using the given parts.
    ///
    /// This is only used for upgrading.
    pub fn from_parts(
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

    /// Returns all PublishedElements mapped to each RepositoryContact.
    ///
    /// There could be more than one repository, although usually there
    /// isn't.
    #[allow(clippy::mutable_key_type)]
    pub fn repo_elements_map(
        &self,
    ) -> HashMap<RepositoryContact, Vec<PublishedFile>> {
        let mut res = HashMap::new();

        if let Some(repo) = &self.repo {
            res.insert(repo.clone(), vec![]);

            for resource_class_objects in self.classes.values() {
                // Note the map 'res' will get entries for other (old)
                // repositories if there are any keys with
                // such repositories.
                resource_class_objects.add_elements(&mut res, repo);
            }
        }

        res
    }

    /// Returns all PublishedFiles in all repositories.
    pub fn all_publish_elements(&self) -> Vec<PublishedFile> {
        let mut all_elements = vec![];

        // slightly inefficient since we drop the RepositoryContact keys
        // again, but this leverages existing code.
        for elements in self.repo_elements_map().values_mut() {
            all_elements.append(elements);
        }

        all_elements
    }

    /// Returns an iterator over all deprecated repos.
    pub fn deprecated_repos(
        &self
    ) -> impl Iterator<Item = &DeprecatedRepository> + '_ {
        self.deprecated_repos.iter()
    }

    /// Removes a deprecated repository.
    pub fn deprecated_repo_remove(&mut self, to_remove: &RepositoryContact) {
        self.deprecated_repos.retain(|current| current.contact() != to_remove)
    }

    /// Increments the number of cleaning attempts for a deprecated repo.
    pub fn deprecated_repo_inc_clean_attempts(
        &mut self,
        contact: &RepositoryContact,
    ) {
        for current in self.deprecated_repos.iter_mut() {
            if current.contact() == contact {
                current.inc_clean_attempts()
            }
        }
    }
}

/// # Actions invoked by the event listener
///
/// Most of these methods are simple enough that they could be rolled into
/// the event listener directly. However, we plan to get rid of listening
/// altogether and these methods will somehow be called in `CertAuths` command
/// processing directly. So we might as well keep them for now.
impl CaObjects {
    /// Adds a new resource class.
    ///
    /// This returns an error in case the class already exists.
    fn add_class(
        &mut self,
        class_name: &ResourceClassName,
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        if self.classes.contains_key(class_name) {
            return Err(Error::publishing("Duplicate resource class"))
        }

        self.classes.insert(
            class_name.clone(),
            ResourceClassObjects::create(key, timing, signer)?,
        );
        Ok(())
    }

    /// Removes a resource class.
    fn remove_class(&mut self, class_name: &ResourceClassName) {
        let old_repo_opt = self.classes.get(class_name).and_then(|rco| {
            rco.old_repo()
        }).cloned();

        self.classes.remove(class_name);

        if let Some(old_repo) = old_repo_opt {
            self.deprecate_repo_if_no_longer_used(old_repo);
        }
    }

    /// Returns the class objects for the given class.
    ///
    /// Returns an error if they don’t exist.
    fn get_class_mut(
        &mut self,
        rcn: &ResourceClassName,
    ) -> KrillResult<&mut ResourceClassObjects> {
        self.classes.get_mut(rcn).ok_or_else(|| {
            Error::publishing("Missing resource class")
        })
    }

    /// Adds a staging key to the set.
    ///
    /// This will fail in case the class is missing, or in case the class is
    /// not in state 'current'.
    fn keyroll_stage(
        &mut self,
        rcn: &ResourceClassName,
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)?.keyroll_stage(key, timing, signer)
    }

    /// Activates the keyset.
    ///
    /// Retires the current set and promotes the staging set to current.
    fn keyroll_activate(
        &mut self,
        rcn: &ResourceClassName,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)?.keyroll_activate()
    }

    /// Finishes a keyroll
    fn keyroll_finish(&mut self, rcn: &ResourceClassName) -> KrillResult<()> {
        let resource_class_objects = self.get_class_mut(rcn)?;

        // finish the key roll for this resource class objects. This will
        // remove the old key, and return an old_repo if there was
        // one.
        if let Some(old_repo) = resource_class_objects.keyroll_finish()? {
            self.deprecate_repo_if_no_longer_used(old_repo);
        }

        Ok(())
    }

    /// Updates the ROAs in the current set
    fn update_roas(
        &mut self,
        rcn: &ResourceClassName,
        roa_updates: &RoaUpdates,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)
            .map(|rco| rco.update_roas(roa_updates))
    }

    /// Updates the ASPAs in the current set
    fn update_aspas(
        &mut self,
        rcn: &ResourceClassName,
        updates: &AspaObjectsUpdates,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_aspas(updates))
    }

    /// Updates the BGPSec certificates in the current set
    fn update_bgpsec_certs(
        &mut self,
        rcn: &ResourceClassName,
        updates: &BgpSecCertificateUpdates,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_bgpsec_certs(updates))
    }

    /// Updates the issued certificates in the current set
    fn update_certs(
        &mut self,
        rcn: &ResourceClassName,
        cert_updates: &ChildCertificateUpdates,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn).map(|rco| rco.update_certs(cert_updates))
    }

    /// Updates the received certificate.
    fn update_received_cert(
        &mut self,
        rcn: &ResourceClassName,
        cert: &ReceivedCert,
    ) -> KrillResult<()> {
        self.get_class_mut(rcn)?.update_received_cert(cert)
    }

    /// Reissues the MFT and CRL
    ///
    /// If `force` is `true`, re-issuance will always be done. This is
    /// to be used in case any of the content changed. Otherwise
    /// re-issuance will only happen if it's close to the next update
    /// time, or the AIA has changed. The latter may happen if the parent
    /// migrated repositories.
    fn re_issue(
        &mut self,
        force: bool,
        issuance_timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<bool> {
        let hours = issuance_timing.publish_hours_before_next();
        let mut required = false;

        for (_, resource_class_objects) in self.classes.iter_mut() {
            if force || resource_class_objects.requires_re_issuance(hours) {
                required = true;
                resource_class_objects.reissue(issuance_timing, signer)?;
            }
        }

        Ok(required)
    }

    /// Updates the repository.
    ///
    /// If the repository is being migrated, i.e. there already is a current
    /// repository, then make sure that the current repository is preserved
    /// as the old repository for existing keys.
    fn update_repo(&mut self, repo: &RepositoryContact) {
        if let Some(old) = &self.repo {
            for resource_class_objects in self.classes.values_mut() {
                resource_class_objects.set_old_repo(old);
            }
        }
        self.repo = Some(repo.clone());
    }

    /// Marks a repository as deprecated unless it's in use by any key.
    fn deprecate_repo_if_no_longer_used(
        &mut self,
        old_repo: RepositoryContact,
    ) {
        if !self.has_old_repo(&old_repo) {
            self.deprecated_repos
                .push(DeprecatedRepository::new(old_repo, 0));
        }
    }

    fn has_old_repo(&self, old_repo: &RepositoryContact) -> bool {
        self.classes.values().any(|rco| rco.has_old_repo(old_repo))
    }
}


//------------ DeprecatedRepository ------------------------------------------

/// A previously used repository that hasn’t been successfully cleaned out.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeprecatedRepository {
    /// The repository contact.
    contact: RepositoryContact,

    /// The number of times we‘ve tried to clean it out.
    clean_attempts: usize,
}

impl DeprecatedRepository {
    /// Creates a new deprecated repository.
    pub fn new(contact: RepositoryContact, clean_attempts: usize) -> Self {
        DeprecatedRepository {
            contact,
            clean_attempts,
        }
    }

    /// Returns the repository contact.
    pub fn contact(&self) -> &RepositoryContact {
        &self.contact
    }

    /// Converts the value into the repository contact.
    pub fn into_contact(self) -> RepositoryContact {
        self.contact
    }

    /// Returns the number of cleaning attempts.
    pub fn clean_attempts(&self) -> usize {
        self.clean_attempts
    }

    /// Increases the number of cleaning attempts.
    pub fn inc_clean_attempts(&mut self) {
        self.clean_attempts += 1;
    }
}


//------------ ResourceClassObjects ------------------------------------------

/// The objects for a resource class.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceClassObjects {
    keys: ResourceClassKeyState,
}

impl ResourceClassObjects {
    /// Creates a new value.
    ///
    /// This is only used by upgrades.
    pub fn new(keys: ResourceClassKeyState) -> Self {
        ResourceClassObjects { keys }
    }

    /// Creates a new resource class objects set.
    fn create(
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Self> {
        let current_set = KeyObjectSet::create(key, timing, signer)?;

        Ok(ResourceClassObjects {
            keys: ResourceClassKeyState::Current(CurrentKeyState {
                current_set,
            }),
        })
    }

    /// Adds all the elements for this resource class to the map.
    /// 
    /// It will use the default repository, or an optional old
    /// repository if any of the keys had one as part of a repository
    /// migration.
    #[allow(clippy::mutable_key_type)]
    fn add_elements(
        &self,
        map: &mut HashMap<RepositoryContact, Vec<PublishedFile>>,
        dflt_repo: &RepositoryContact,
    ) {
        match &self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.add_elements(map, dflt_repo)
            }
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

    fn keyroll_stage(
        &mut self,
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        let current_set = match &self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.clone()
            }
            _ => {
                return Err(Error::publishing(
                    "published resource class in the wrong key state",
                ))
            }
        };

        let staging_set = KeyObjectSet::create(key, timing, signer)?;

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
                let current_set = state.staging_set.clone();

                ResourceClassKeyState::Old(OldKeyState {
                    current_set,
                    old_set,
                })
            }
            _ => {
                return Err(Error::publishing(
                    "published resource class in the wrong key state",
                ))
            }
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
            _ => Err(Error::publishing(
                "published resource class in the wrong key state",
            )),
        }
    }

    fn update_received_cert(
        &mut self,
        updated_cert: &ReceivedCert,
    ) -> KrillResult<()> {
        self.keys.update_received_cert(updated_cert)
    }

    fn update_roas(&mut self, roa_updates: &RoaUpdates) {
        match &mut self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.update_roas(roa_updates)
            }
            ResourceClassKeyState::Staging(state) => {
                state.current_set.update_roas(roa_updates)
            }
            ResourceClassKeyState::Old(state) => {
                state.current_set.update_roas(roa_updates)
            }
        }
    }

    fn update_aspas(&mut self, updates: &AspaObjectsUpdates) {
        match &mut self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.update_aspas(updates)
            }
            ResourceClassKeyState::Staging(state) => {
                state.current_set.update_aspas(updates)
            }
            ResourceClassKeyState::Old(state) => {
                state.current_set.update_aspas(updates)
            }
        }
    }

    fn update_bgpsec_certs(&mut self, updates: &BgpSecCertificateUpdates) {
        match &mut self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.update_bgpsec_certs(updates)
            }
            ResourceClassKeyState::Staging(state) => {
                state.current_set.update_bgpsec_certs(updates)
            }
            ResourceClassKeyState::Old(state) => {
                state.current_set.update_bgpsec_certs(updates)
            }
        }
    }

    fn update_certs(&mut self, cert_updates: &ChildCertificateUpdates) {
        match &mut self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.update_certs(cert_updates)
            }
            ResourceClassKeyState::Staging(state) => {
                state.current_set.update_certs(cert_updates)
            }
            ResourceClassKeyState::Old(state) => {
                state.current_set.update_certs(cert_updates)
            }
        }
    }

    fn requires_re_issuance(&self, hours: i64) -> bool {
        match &self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.requires_reissuance(hours)
            }
            ResourceClassKeyState::Old(state) => {
                state.old_set.requires_reissuance(hours)
                    || state.current_set.requires_reissuance(hours)
            }
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.requires_reissuance(hours)
                    || state.current_set.requires_reissuance(hours)
            }
        }
    }

    fn reissue(
        &mut self,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        match &mut self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.reissue(timing, signer)
            }
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
        match &mut self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.set_old_repo(repo)
            }
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
            ResourceClassKeyState::Current(state) => {
                state.current_set.old_repo() == Some(repo)
            }
            ResourceClassKeyState::Staging(state) => {
                state.staging_set.old_repo() == Some(repo)
                    || state.current_set.old_repo() == Some(repo)
            }
            ResourceClassKeyState::Old(state) => {
                state.old_set.old_repo() == Some(repo)
                    || state.current_set.old_repo() == Some(repo)
            }
        }
    }

    fn old_repo(&self) -> Option<&RepositoryContact> {
        // Note: we can only have 1 old repo, because new repositories can
        // only be introduced when there is no key roll in progress.
        // So, it's not possible to introduce a second repo until the
        // previous old_repo is rolled out completely.
        match &self.keys {
            ResourceClassKeyState::Current(state) => {
                state.current_set.old_repo()
            }
            ResourceClassKeyState::Staging(state) => state
                .staging_set
                .old_repo()
                .or_else(|| state.current_set.old_repo()),
            ResourceClassKeyState::Old(state) => state
                .old_set
                .old_repo()
                .or_else(|| state.current_set.old_repo()),
        }
    }
}


//------------ ResourceClassKeyState -----------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceClassKeyState {
    Current(CurrentKeyState),
    Staging(StagingKeyState),
    Old(OldKeyState),
}

impl ResourceClassKeyState {
    pub fn current(current_set: KeyObjectSet) -> Self {
        ResourceClassKeyState::Current(CurrentKeyState { current_set })
    }

    pub fn staging(
        staging_set: KeyObjectSet,
        current_set: KeyObjectSet,
    ) -> Self {
        ResourceClassKeyState::Staging(StagingKeyState {
            staging_set,
            current_set,
        })
    }

    pub fn old(current_set: KeyObjectSet, old_set: KeyObjectSet) -> Self {
        ResourceClassKeyState::Old(OldKeyState {
            current_set,
            old_set,
        })
    }

    fn update_received_cert(
        &mut self,
        cert: &ReceivedCert,
    ) -> KrillResult<()> {
        match self {
            ResourceClassKeyState::Current(state) => {
                state.current_set.update_signing_cert(cert)
            }
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


//------------ CurrentKeyState -----------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurrentKeyState {
    current_set: KeyObjectSet,
}

impl CurrentKeyState {
    pub fn new(current_set: KeyObjectSet) -> Self {
        CurrentKeyState { current_set }
    }
}

//------------ StagingKeyState -----------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StagingKeyState {
    staging_set: KeyObjectSet,
    current_set: KeyObjectSet,
}

impl StagingKeyState {
    pub fn new(staging_set: KeyObjectSet, current_set: KeyObjectSet) -> Self {
        StagingKeyState {
            staging_set,
            current_set,
        }
    }
}


//------------ OldKeyState ---------------------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldKeyState {
    current_set: KeyObjectSet,
    old_set: KeyObjectSet,
}

impl OldKeyState {
    pub fn new(current_set: KeyObjectSet, old_set: KeyObjectSet) -> Self {
        OldKeyState {
            current_set,
            old_set,
        }
    }
}

//------------ KeyObjectSet ------------------------------------------------

/// Maintains the set of objects published for a key.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyObjectSet {
    /// The latest received certificate for the owning key.
    ///
    /// This is used when signing a new manifest and CRL.
    signing_cert: ReceivedCert,

    /// The revision of the set.
    ///
    /// Its number and the "this update" and "next update" values used on the
    /// manifest and CRL.
    revision: ObjectSetRevision,

    /// The revocations that need go on the CRL.
    ///
    /// The CRL object has no convenient access to this, so we keep that
    /// immutable. Whenever we re-issue, we create a new CRL using these
    /// revocations.
    ///
    /// When objects are replaced or removed we add a revocation. When
    /// publishing revocations for expired certificates are removed.
    revocations: Revocations,

    /// The last manifest generated for this set.
    ///
    /// When a set is first created, we will have a manifest and a CRL, but
    /// it will have an empty map of "published_objects".
    ///
    /// A new manifest is generated when we re-issue the set. This may happen
    /// when published objects are added/updated/removed, or in case, well
    /// some time before, the manifest and CRL would expire.
    manifest: PublishedManifest,

    /// The last CRL generated for this set.
    ///
    /// We always generate the manifest and CRL together. When we re-issue a
    /// set we first generate a new CRL which will revoke the previous
    /// manifest. The CRL (name and hash) is included in the new manifest.
    ///
    /// Strictly speaking this revocation could be considered redundant,
    /// because the new CRL will not be considered valid (hash mismatch)
    /// under the old manifest. So, a Relying Party will only consider
    /// the CRL when it is using the new manifest.
    crl: PublishedCrl,

    /// The published objects of this set.
    ///
    /// Will be empty if the owning key is not "current". I.e., this is empty
    /// when a new KeyObjectSet is created (new staging key for a key roll,
    /// or the first certified key under a new resource class).
    ///
    /// The "current" key will see updates to the published objects.
    ///
    /// When a key becomes "old" - just before it is subsequently removed -
    /// when it is replaced as part of a key roll, then `retire` is called
    /// on the set: all objects are revoked, and then this becomes empty
    /// again.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    published_objects: HashMap<ObjectName, PublishedObject>,

    /// The old repository this key publishes to.
    ///
    /// We implement repository migration as a key roll where the new
    /// key uses the new (then default) repository. Existing keys will
    /// keep track of the old repository contact using this following
    /// field so that they can continue to publish / withdraw there,
    /// until they (the owning key) are complete removed when the key
    /// rollover is finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    old_repo: Option<RepositoryContact>,
}

impl KeyObjectSet {
    /// Creates a new key set from its components.
    ///
    /// This is only used by upgrades.
    pub fn new(
        signing_cert: ReceivedCert,
        revision: ObjectSetRevision,
        revocations: Revocations,
        manifest: PublishedManifest,
        crl: PublishedCrl,
        published_objects: HashMap<ObjectName, PublishedObject>,
        old_repo: Option<RepositoryContact>,
    ) -> Self {
        KeyObjectSet {
            signing_cert,
            revision,
            revocations,
            manifest,
            crl,
            published_objects,
            old_repo,
        }
    }

    /// Creates a new key set for the given key.
    ///
    /// Creates an initial manifest and CRL but keeps the list of published
    /// objects empty.
    fn create(
        key: &CertifiedKey,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<Self> {
        let signing_cert = key.incoming_cert().clone();

        let signing_key = signing_cert.key_identifier();
        let issuer = signing_cert.subject.clone();
        let revocations = Revocations::default();
        let revision = ObjectSetRevision::create(timing.publish_next());
        let published_objects = HashMap::new();

        let crl = PublishedCrl::build(
            signing_key,
            issuer,
            &revocations,
            revision,
            signer,
        )?;
        let manifest = ManifestBuilder::new(revision)
            .with_objects(&crl, &published_objects)
            .build_new_mft(&signing_cert, signer)
            .map(|m| m.into())?;


        Ok(KeyObjectSet {
            signing_cert,
            revision,
            revocations,
            manifest,
            crl,
            published_objects,
            old_repo: None,
        })
    }

    /// Adds all the elements for this set to the map which is passed on.
    ///
    /// It will use the default repository unless this key had an old
    /// repository set - as part of repository migration.
    #[allow(clippy::mutable_key_type)]
    fn add_elements(
        &self,
        map: &mut HashMap<RepositoryContact, Vec<PublishedFile>>,
        dflt_repo: &RepositoryContact,
    ) {
        let repo = self.old_repo.as_ref().unwrap_or(dflt_repo);

        let crl_uri = self.signing_cert.crl_uri();
        let mft_uri = self.signing_cert.mft_uri();

        let elements = map.entry(repo.clone()).or_default();

        elements.push(self.manifest.published_file(mft_uri));
        elements.push(self.crl.published_file(crl_uri));

        for (name, object) in &self.published_objects {
            elements.push(PublishedFile {
                uri: self.signing_cert.uri_for_name(name),
                base64: object.base64.clone(),
            });
        }
    }

    /// Returns whether the set needs re-issuance within the given hours.
    pub fn requires_reissuance(&self, hours: i64) -> bool {
        Time::now() > self.next_update() - Duration::hours(hours)
    }

    /// Returns the next update time.
    pub fn next_update(&self) -> Time {
        self.revision.next_update
    }

    /// Updates the signing certificate for the set.
    ///
    /// Returns an error in case the KeyIdentifiers don't match.
    fn update_signing_cert(
        &mut self,
        cert: &ReceivedCert,
    ) -> KrillResult<()> {
        if self.signing_cert.key_identifier() == cert.key_identifier() {
            self.signing_cert = cert.clone();
            Ok(())
        }
        else {
            Err(Error::PublishingObjects(format!(
                "received new cert for unknown key id: {}",
                cert.key_identifier()
            )))
        }
    }

    /// Updates the ROAs.
    fn update_roas(&mut self, roa_updates: &RoaUpdates) {
        for (name, roa_info) in roa_updates.added_roas() {
            let published_object = PublishedObject::for_roa(
                name.clone(), roa_info
            );
            if let Some(old) = self.published_objects.insert(
                name, published_object
            ) {
                self.revocations.add(old.revoke());
            }
        }
        for name in roa_updates.removed_roas() {
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }
    }

    /// Updates the ASPAs.
    fn update_aspas(&mut self, updates: &AspaObjectsUpdates) {
        for aspa_info in updates.updated() {
            let name = ObjectName::aspa_from_customer(aspa_info.customer());
            let published_object =
                PublishedObject::for_aspa(name.clone(), aspa_info);
            if let Some(old) =
                self.published_objects.insert(name, published_object)
            {
                self.revocations.add(old.revoke());
            }
        }
        for removed in updates.removed() {
            let name = ObjectName::aspa_from_customer(*removed);
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }
    }

    /// Updates the BGPset router key certificates.
    fn update_bgpsec_certs(&mut self, updates: &BgpSecCertificateUpdates) {
        for bgpsec_cert_info in updates.updated() {
            let published_object =
                PublishedObject::for_bgpsec_cert_info(bgpsec_cert_info);
            if let Some(old) = self
                .published_objects
                .insert(bgpsec_cert_info.name(), published_object)
            {
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

    /// Updates the child CA certificates.
    fn update_certs(&mut self, cert_updates: &ChildCertificateUpdates) {
        for removed in &cert_updates.removed {
            let name = ObjectName::from_key(removed, "cer");
            if let Some(old) = self.published_objects.remove(&name) {
                self.revocations.add(old.revoke());
            }
        }

        for issued in &cert_updates.issued {
            let published_object = PublishedObject::for_cert_info(issued);
            if let Some(old) = self
                .published_objects
                .insert(issued.name.clone(), published_object)
            {
                self.revocations.add(old.revoke());
            }
        }

        for cert in &cert_updates.unsuspended {
            self.revocations.remove(&cert.revocation());
            let published_object = PublishedObject::for_cert_info(cert);
            if let Some(old) = self
                .published_objects
                .insert(cert.name.clone(), published_object)
            {
                // this should not happen, but just to be safe.
                self.revocations.add(old.revoke());
            }
        }

        for suspended in &cert_updates.suspended {
            if let Some(old) = self.published_objects.remove(&suspended.name)
            {
                self.revocations.add(old.revoke());
            }
        }
    }

    /// Re-issues manifest and CRL.
    fn reissue(
        &mut self,
        timing: &IssuanceTimingConfig,
        signer: &KrillSigner,
    ) -> KrillResult<()> {
        debug!(
            "Will re-issue for key: {}. Current revision: {} and next \
             update: {}",
            self.signing_cert.key_identifier(),
            self.revision.number,
            self.revision.next_update.to_rfc3339()
        );

        self.revision.next(timing.publish_next(), None);

        self.revocations.remove_expired();
        let signing_key = self.signing_cert.key_identifier();
        let issuer = self.signing_cert.subject.clone();

        self.crl = PublishedCrl::build(
            signing_key,
            issuer,
            &self.revocations,
            self.revision,
            signer,
        )?;

        self.manifest = ManifestBuilder::new(self.revision)
            .with_objects(&self.crl, &self.published_objects)
            .build_new_mft(&self.signing_cert, signer)
            .map(|m| m.into())?;

        Ok(())
    }

    /// Returns a retired key object set for this set.
    ///
    /// Revokes and retires all signed objects.
    fn retire(&self) -> KrillResult<KeyObjectSet> {
        let mut revocations = self.revocations.clone();
        for object in self.published_objects.values() {
            revocations.add(object.revoke());
        }
        revocations.remove_expired();

        let retired_set = KeyObjectSet {
            signing_cert: self.signing_cert.clone(),
            revision: self.revision,
            revocations,
            manifest: self.manifest.clone(),
            crl: self.crl.clone(),
            published_objects: HashMap::new(),
            old_repo: self.old_repo.clone(),
        };

        Ok(retired_set)
    }

    /// Sets the old repository for this object set.
    fn set_old_repo(&mut self, repo: &RepositoryContact) {
        self.old_repo = Some(repo.clone())
    }

    /// Returns the old repo for this object set if there is one.
    fn old_repo(&self) -> Option<&RepositoryContact> {
        self.old_repo.as_ref()
    }
}


//------------ ObjectSetRevision ---------------------------------------------

/// The current revision information for a key object set.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObjectSetRevision {
    /// The manifest and CRL number.
    number: u64,

    /// The issue time of this manifest and CRL.
    ///
    /// This is backdated 5 minutes to tolerate some clock skew.
    this_update: Time,

    /// The next update of this manifest and CRL.
    next_update: Time,
}

impl ObjectSetRevision {
    /// Creates a new revision with the given parameters.
    pub fn new(number: u64, this_update: Time, next_update: Time) -> Self {
        ObjectSetRevision {
            number,
            this_update,
            next_update,
        }
    }

    /// Creates an initial revision.
    fn create(next_update: Time) -> Self {
        ObjectSetRevision {
            number: 1,
            this_update: Time::five_minutes_ago(),
            next_update,
        }
    }

    pub fn number(&self) -> u64 {
        self.number
    }

    pub fn this_update(&self) -> Time {
        self.this_update
    }

    pub fn next_update(&self) -> Time {
        self.next_update
    }

    /// Updates the revision to the following revision.
    pub fn next(
        &mut self,
        next_update: Time,
        mft_number_override: Option<u64>,
    ) {
        if let Some(forced_next) = mft_number_override {
            self.number = forced_next;
        } else {
            self.number += 1;
        }
        self.this_update = Time::five_minutes_ago();
        self.next_update = next_update;
    }
}

//------------ PublishedCert -------------------------------------------------

/// A published certificate.
pub type PublishedCert = IssuedCertificate;


//------------ PublishedItem -------------------------------------------------

/// Any item published in the repository.
///
/// The concrete type of object is provided through the marker type `T`. This
/// is only used to make sure we add objects in the right place.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItem<T> {
    /// The name of the object.
    name: ObjectName,

    /// The content of the object.
    base64: Base64,

    /// The RRDP hash of the object.
    ///
    /// This is derived from `base64` but kept for faster access.
    hash: rrdp::Hash,

    /// The serial number of the certificate the object is signed with.
    serial: Serial,

    /// The expiry time of the object.
    expires: Time,

    /// A marker for the object type.
    marker: std::marker::PhantomData<T>,
}

impl<T> PublishedItem<T> {
    /// Creates a new published object.
    pub fn new(
        name: ObjectName,
        base64: Base64,
        serial: Serial,
        expires: Time,
    ) -> Self {
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

    /// Returns a published file for the object.
    pub fn published_file(&self, uri: uri::Rsync) -> PublishedFile {
        PublishedFile { uri, base64: self.base64.clone() }
    }

    /// Returns a revocation for the object.
    pub fn revoke(&self) -> Revocation {
        Revocation::new(self.serial, self.expires)
    }
}


//------------ PublishedManifest ---------------------------------------------

/// A published manifest.
//
//  *Warning:* This type is used in stored state.
pub type PublishedManifest = PublishedItem<PublishedItemManifest>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItemManifest;

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


//------------ PublishedCrl --------------------------------------------------

/// A published CRL.
//
//  *Warning:* This type is used in stored state.
pub type PublishedCrl = PublishedItem<PublishedItemCrl>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItemCrl;

impl PublishedCrl {
    pub fn build(
        aki: KeyIdentifier,
        issuer: Name,
        revocations: &Revocations,
        revision: ObjectSetRevision,
        signer: &KrillSigner,
    ) -> KrillResult<Self> {
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

//------------ PublishedObject -----------------------------------------------

/// A generic published object.
//
//  *Warning:* This type is used in stored state.
pub type PublishedObject = PublishedItem<PublishedItemOther>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedItemOther;

impl PublishedObject {
    /// Creates a published ROA.
    pub fn for_roa(name: ObjectName, roa_info: &RoaInfo) -> Self {
        PublishedObject::new(
            name,
            roa_info.base64.clone(),
            roa_info.serial,
            roa_info.expires(),
        )
    }

    /// Creates a published ASPA object.
    pub fn for_aspa(name: ObjectName, aspa_info: &AspaInfo) -> Self {
        PublishedObject::new(
            name,
            aspa_info.base64.clone(),
            aspa_info.serial,
            aspa_info.expires(),
        )
    }

    /// Creates a published child CA certificate.
    pub fn for_cert_info<T>(cert: &CertInfo<T>) -> Self {
        PublishedObject::new(
            cert.name.clone(),
            cert.base64.clone(),
            cert.serial,
            cert.expires(),
        )
    }

    /// Creates a published BGPsec router key certificate.
    pub fn for_bgpsec_cert_info(cert: &BgpSecCertInfo) -> Self {
        PublishedObject::new(
            cert.name(),
            cert.base64.clone(),
            cert.serial,
            cert.expires,
        )
    }
}


//------------ ManifestBuilder -----------------------------------------------

/// A helper type to create a manifest.
#[allow(clippy::mutable_key_type)]
pub struct ManifestBuilder {
    /// The revision of the manifest.
    revision: ObjectSetRevision,

    /// The entries of the manifest.
    entries: HashMap<ObjectName, rrdp::Hash>,
}

impl ManifestBuilder {
    /// Creates a new builder with the given revision.
    pub fn new(revision: ObjectSetRevision) -> Self {
        ManifestBuilder {
            revision,
            entries: HashMap::new(),
        }
    }

    /// Adds the given objects to the manifest’s entries.
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

    /// Buidlds a new manifest.
    pub fn build_new_mft(
        self,
        signing_cert: &ReceivedCert,
        signer: &KrillSigner,
    ) -> KrillResult<Manifest> {
        let mft_uri = signing_cert.mft_uri();
        let crl_uri = signing_cert.crl_uri();

        let aia = &signing_cert.uri;
        let aki = signing_cert.key_identifier();
        let serial_number = Serial::from(self.revision.number);

        let entries =
            self.entries.iter().map(|(k, v)| FileAndHash::new(k, v));

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
                Validity::new(
                    self.revision.this_update,
                    self.revision.next_update,
                ),
                crl_uri,
                aia.clone(),
                mft_uri,
            );
            object_builder.set_issuer(Some(signing_cert.subject.clone()));
            object_builder.set_signing_time(Some(Time::now()));

            signer.sign_manifest(mft_content, object_builder, &aki)?
        };

        Ok(manifest)
    }
}


//------------ ObjectStoreListener ------------------------------------------

pub struct ObjectsStoreListener {
    ca_objects: Arc<CaObjectsStore>,
    krill: KrillHandle,
}

impl ObjectsStoreListener {
    pub fn new(ca_objects: Arc<CaObjectsStore>, krill: KrillHandle) -> Self {
        Self { ca_objects, krill }
    }
}

/// React to any events on a CA that cause the set of object to change.
impl PreSaveEventListener<CertAuth> for ObjectsStoreListener {
    fn listen(
        &self,
        ca: &CertAuth,
        events: &[CertAuthEvent],
    ) -> KrillResult<()> {
        // Note that the `CertAuth` which is passed in has already been
        // updated with the state changes contained in the event.

        self.ca_objects.with_ca_objects(ca.handle(), |objects| {
            let mut force_reissue = false;

            for event in events {
                match event {
                    CertAuthEvent::RoasUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_roas(resource_class_name, updates)?;
                        force_reissue = true;
                    }
                    CertAuthEvent::AspaObjectsUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_aspas(resource_class_name, updates)?;
                        force_reissue = true;
                    }
                    CertAuthEvent::BgpSecCertificatesUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_bgpsec_certs(
                            resource_class_name,
                            updates,
                        )?;
                        force_reissue = true;
                    }
                    CertAuthEvent::ChildCertificatesUpdated {
                        resource_class_name,
                        updates,
                    } => {
                        objects.update_certs(resource_class_name, updates)?;
                        force_reissue = true;
                    }
                    CertAuthEvent::KeyPendingToActive {
                        resource_class_name,
                        current_key,
                    } => {
                        objects.add_class(
                            resource_class_name,
                            current_key,
                            &self.krill.config().issuance_timing,
                            self.krill.signer(),
                        )?;
                    }
                    CertAuthEvent::KeyPendingToNew {
                        resource_class_name,
                        new_key,
                    } => {
                        objects.keyroll_stage(
                            resource_class_name,
                            new_key,
                            &self.krill.config().issuance_timing,
                            self.krill.signer(),
                        )?;
                    }
                    CertAuthEvent::KeyRollActivated {
                        resource_class_name,
                        ..
                    } => {
                        objects.keyroll_activate(resource_class_name)?;
                        force_reissue = true;
                    }
                    CertAuthEvent::KeyRollFinished {
                        resource_class_name,
                    } => {
                        objects.keyroll_finish(resource_class_name)?;
                    }
                    CertAuthEvent::CertificateReceived {
                        resource_class_name,
                        rcvd_cert,
                        ..
                    } => {
                        objects.update_received_cert(
                            resource_class_name,
                            rcvd_cert,
                        )?;
                        // this in itself constitutes no need to force
                        // re-issuance if the new
                        // certificate triggered that the set of objects
                        // changed, e.g. because a ROA
                        // became overclaiming, then we would see another
                        // event for that which *will* result in forcing
                        // re-issuance.
                    }
                    CertAuthEvent::ResourceClassRemoved {
                        resource_class_name,
                        ..
                    } => {
                        objects.remove_class(resource_class_name);
                        force_reissue = true;
                    }
                    CertAuthEvent::RepoUpdated { contact } => {
                        objects.update_repo(contact);
                        force_reissue = true;
                    }
                    _ => {}
                }
            }
            objects.re_issue(
                force_reissue,
                &self.krill.config().issuance_timing,
                self.krill.signer()
            )?;
            Ok(())
        })
    }
}

