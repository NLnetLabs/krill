use std::{collections::HashMap, path::Path, str::FromStr, sync::RwLock};

use rpki::ca::{
    idexchange::{CaHandle, ChildHandle, ParentHandle, ServiceUri},
    provisioning::ResourceClassListResponse as Entitlements,
    publication::PublishDelta,
};

use crate::commons::{
    api::{
        ChildConnectionStats, ChildStatus, ChildrenConnectionStats, ErrorResponse, ParentStatus, ParentStatuses,
        RepoStatus,
    },
    error::Error,
    eventsourcing::{KeyStoreKey, KeyValueStore},
    util::httpclient,
    KrillResult,
};

const PARENTS_PREFIX: &str = "parents-";
const CHILDREN_PREFIX: &str = "children-";
const JSON_SUFFIX: &str = ".json";

//------------ CaStatus ------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaStatus {
    repo: RepoStatus,
    parents: ParentStatuses,
    #[serde(skip_serializing_if = "HashMap::is_empty", default = "HashMap::new")]
    children: HashMap<ChildHandle, ChildStatus>,
}

impl CaStatus {
    pub fn get_children_connection_stats(&self) -> ChildrenConnectionStats {
        let children = self
            .children
            .clone()
            .into_iter()
            .map(|(handle, status)| {
                let state = status.child_state();
                ChildConnectionStats::new(handle, status.into(), state)
            })
            .collect();
        ChildrenConnectionStats::new(children)
    }

    pub fn repo(&self) -> &RepoStatus {
        &self.repo
    }

    pub fn parents(&self) -> &ParentStatuses {
        &self.parents
    }

    pub fn children(&self) -> &HashMap<ChildHandle, ChildStatus> {
        &self.children
    }
}

//------------ StatusStore ---------------------------------------------------

pub struct StatusStore {
    store: KeyValueStore,
    cache: RwLock<HashMap<CaHandle, CaStatus>>,
}

impl StatusStore {
    pub fn new(work_dir: &Path, namespace: &str) -> KrillResult<Self> {
        let store = KeyValueStore::disk(work_dir, namespace)?;
        let cache = RwLock::new(HashMap::new());

        let store = StatusStore { store, cache };
        store.warm()?;

        Ok(store)
    }

    /// Load existing status from disk, support the pre 0.9.5 format and silently
    /// convert it if needed.
    fn warm(&self) -> KrillResult<()> {
        for scope in self.store.scopes()? {
            if let Ok(ca) = CaHandle::from_str(&scope) {
                self.convert_pre_0_9_5_full_status_if_present(&ca)?;
                self.load_full_status(&ca)?;
            }
        }

        Ok(())
    }

    /// Load current status from disk, to be used when starting up. If there are any
    /// issues parsing data then default values are used - this data is not critical
    /// so any missing, corrupted, or no longer supported data format - can be ignored.
    /// It will get updated with new status values as Krill is running.
    fn load_full_status(&self, ca: &CaHandle) -> KrillResult<()> {
        let repo: RepoStatus = self.store.get(&Self::repo_status_key(ca))?.unwrap_or_default();

        // We use the following mapping for keystore keys to parents/children:
        //  parents-{parent-handle}.json
        //  children-{child-handle}.json

        // parents
        let mut parents = ParentStatuses::default();
        for parent_key in self.store.keys(Some(ca.to_string()), PARENTS_PREFIX)? {
            // Try to parse the key to get a parent handle
            if let Some(parent) = parent_key
                .name()
                .strip_prefix(PARENTS_PREFIX)
                .and_then(|pfx_stripped| pfx_stripped.strip_suffix(JSON_SUFFIX))
                .and_then(|handle_str| ParentHandle::from_str(handle_str).ok())
            {
                // try to read the status, if there is any issue, e.g. because
                // the format changed in a new version, then just fall back to
                // an empty default value. We will get a new connection status
                // value soon enough as Krill is running.
                let status: ParentStatus = self
                    .store
                    .get(&Self::parent_status_key(ca, &parent))?
                    .unwrap_or_default();

                parents.insert(parent, status);
            }
        }

        // children
        let mut children = HashMap::new();
        for child_key in self.store.keys(Some(ca.to_string()), CHILDREN_PREFIX)? {
            // Try to parse the key to get a child handle
            if let Some(child) = child_key
                .name()
                .strip_prefix(CHILDREN_PREFIX)
                .and_then(|pfx_stripped| pfx_stripped.strip_suffix(JSON_SUFFIX))
                .and_then(|handle_str| ChildHandle::from_str(handle_str).ok())
            {
                // try to read the status, if there is any issue, e.g. because
                // the format changed in a new version, then just fall back to
                // an empty default value. We will get a new connection status
                // value soon enough as Krill is running.
                let status: ChildStatus = self.store.get(&Self::child_status_key(ca, &child))?.unwrap_or_default();

                children.insert(child, status);
            }
        }

        let status = CaStatus {
            repo,
            parents,
            children,
        };

        // Update the cache. Note that this is what we will use at runtime.
        // Changes go directly in to the cached object. We will save smaller
        // JSON files as well but we only do this full parsing on startup.
        self.cache.write().unwrap().insert(ca.clone(), status);

        Ok(())
    }

    fn convert_pre_0_9_5_full_status_if_present(&self, ca: &CaHandle) -> KrillResult<()> {
        let key = KeyStoreKey::scoped(ca.to_string(), "status.json".to_string());
        if let Some(full_status) = self.store.get::<CaStatus>(&key).ok().flatten() {
            info!(
                "Migrating pre 0.9.5 connection status file for CA '{}' to new format",
                ca
            );
            // repo status
            self.store.store(&Self::repo_status_key(ca), full_status.repo())?;

            // parents
            for (parent, status) in full_status.parents().iter() {
                self.store.store(&Self::parent_status_key(ca, parent), status)?;
            }

            // children
            for (child, status) in full_status.children.iter() {
                self.store.store(&Self::child_status_key(ca, child), status)?;
            }

            self.store.drop_key(&key)?;
            info!("Done migrating pre 0.9.5 connection status file");
        }
        Ok(())
    }

    fn repo_status_key(ca: &CaHandle) -> KeyStoreKey {
        // we may need to support multiple repos in future
        KeyStoreKey::scoped(ca.to_string(), "repos-main.json".to_string())
    }

    fn parent_status_key(ca: &CaHandle, parent: &ParentHandle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), format!("{}{}{}", PARENTS_PREFIX, parent, JSON_SUFFIX))
    }

    fn child_status_key(ca: &CaHandle, child: &ChildHandle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), format!("{}{}{}", CHILDREN_PREFIX, child, JSON_SUFFIX))
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    pub fn get_ca_status(&self, ca: &CaHandle) -> CaStatus {
        self.cache.read().unwrap().get(ca).cloned().unwrap_or_default()
    }

    pub fn set_parent_failure(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_ca_parent_status(ca, parent, |status| status.set_failure(uri.clone(), error_response))
    }

    pub fn set_parent_last_updated(&self, ca: &CaHandle, parent: &ParentHandle, uri: &ServiceUri) -> KrillResult<()> {
        self.update_ca_parent_status(ca, parent, |status| status.set_last_updated(uri.clone()))
    }

    pub fn set_parent_entitlements(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        entitlements: &Entitlements,
    ) -> KrillResult<()> {
        self.update_ca_parent_status(ca, parent, |status| status.set_entitlements(uri.clone(), entitlements))
    }

    pub fn remove_parent(&self, ca: &CaHandle, parent: &ParentHandle) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if let Some(ca_status) = cache.get_mut(ca) {
            ca_status.parents.remove(parent);
            self.store.drop_key(&Self::parent_status_key(ca, parent))?;
        }
        Ok(())
    }

    pub fn set_child_success(&self, ca: &CaHandle, child: &ChildHandle, user_agent: Option<String>) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| status.set_success(user_agent))
    }

    pub fn set_child_failure(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
        user_agent: Option<String>,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_ca_child_status(ca, child, |status| status.set_failure(user_agent, error_response))
    }

    /// Marks a child as suspended. Note that it will be implicitly unsuspended whenever a new success or
    /// or failure is recorded for the child.
    pub fn set_child_suspended(&self, ca: &CaHandle, child: &ChildHandle) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| status.set_suspended())
    }

    /// Remove a CA from the saved status
    /// This should be called when the CA is removed from Krill, but note that if this is done for a CA which still exists
    /// a new empty default status will be re-generated when it is accessed for this CA.
    pub fn remove_ca(&self, ca: &CaHandle) -> KrillResult<()> {
        self.cache.write().unwrap().remove(ca);

        let scope = ca.as_str();
        self.store.drop_scope(scope)?; // will only fail if scope is present and cannot be removed

        Ok(())
    }

    /// Removes a child for the given CA.
    pub fn remove_child(&self, ca: &CaHandle, child: &ChildHandle) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if let Some(ca_status) = cache.get_mut(ca) {
            ca_status.children.remove(child);
            self.store.drop_key(&Self::child_status_key(ca, child))?;
        }

        Ok(())
    }

    pub fn set_status_repo_failure(&self, ca: &CaHandle, uri: ServiceUri, error: &Error) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_repo_status(ca, |status| status.set_failure(uri, error_response))
    }

    pub fn set_status_repo_success(&self, ca: &CaHandle, uri: ServiceUri) -> KrillResult<()> {
        self.update_repo_status(ca, |status| status.set_last_updated(uri))
    }

    pub fn set_status_repo_published(&self, ca: &CaHandle, uri: ServiceUri, delta: PublishDelta) -> KrillResult<()> {
        self.update_repo_status(ca, |status| status.update_published(uri, delta))
    }

    fn update_repo_status<F>(&self, ca: &CaHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut RepoStatus),
    {
        let mut cache = self.cache.write().unwrap();

        if !cache.contains_key(ca) {
            cache.insert(ca.clone(), CaStatus::default());
        }

        let ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing
        op(&mut ca_status.repo);

        self.store.store(&Self::repo_status_key(ca), ca_status.repo())?;

        Ok(())
    }

    fn update_ca_child_status<F>(&self, ca: &CaHandle, child: &ChildHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut ChildStatus),
    {
        let status = {
            let mut cache = self.cache.write().unwrap();

            if !cache.contains_key(ca) {
                cache.insert(ca.clone(), CaStatus::default());
            }

            let ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing

            if !ca_status.children.contains_key(child) {
                ca_status.children.insert(child.clone(), ChildStatus::default());
            }

            let child_status = ca_status.children.get_mut(child).unwrap();
            op(child_status);

            child_status.clone()
        };

        self.store.store(&Self::child_status_key(ca, child), &status)?;

        Ok(())
    }

    fn update_ca_parent_status<F>(&self, ca: &CaHandle, parent: &ParentHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut ParentStatus),
    {
        let status = {
            let mut cache = self.cache.write().unwrap();

            if !cache.contains_key(ca) {
                cache.insert(ca.clone(), CaStatus::default());
            }

            let ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing

            let parent_status = ca_status.parents.get_mut_status(parent);
            op(parent_status);
            parent_status.clone()
        };

        self.store.store(&Self::parent_status_key(ca, parent), &status)?;

        Ok(())
    }

    fn error_to_error_res(error: &Error) -> ErrorResponse {
        match error {
            Error::HttpClientError(httpclient::Error::ErrorResponseWithJson(_, _, res)) => *res.clone(),
            _ => error.to_error_response(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::path::PathBuf;

    use crate::commons::util::file;
    use crate::test::test_under_tmp;

    #[test]
    fn read_save_status() {
        test_under_tmp(|d| {
            let source = PathBuf::from("test-resources/status_store/migration-0.9.5/");
            let target = d.join("status");
            file::backup_dir(&source, &target).unwrap();

            let status_testbed_before_migration =
                include_str!("../../../test-resources/status_store/migration-0.9.5/testbed/status.json");

            let status_testbed_before_migration: CaStatus =
                serde_json::from_str(status_testbed_before_migration).unwrap();

            let store = StatusStore::new(&d, "status").unwrap();
            let testbed = CaHandle::from_str("testbed").unwrap();

            let status_testbed_migrated = store.get_ca_status(&testbed);

            assert_eq!(status_testbed_before_migration, status_testbed_migrated);
        });
    }
}
