use std::{
    collections::HashMap,
    path::Path,
    str::FromStr,
    sync::{Arc, RwLock},
};

use crate::commons::{
    api::{
        rrdp::PublishElement, ChildConnectionStats, ChildHandle, ChildStatus, ChildrenConnectionStats, Entitlements,
        ErrorResponse, Handle, ParentHandle, ParentStatus, ParentStatuses, RepoStatus, Timestamp,
    },
    error::Error,
    eventsourcing::{KeyStoreKey, KeyValueStore},
    remote::rfc8183::ServiceUri,
    util::httpclient,
    KrillResult,
};

//------------ CaStatus ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

impl Default for CaStatus {
    fn default() -> Self {
        CaStatus {
            repo: RepoStatus::default(),
            parents: ParentStatuses::default(),
            children: HashMap::new(),
        }
    }
}

//------------ StatusStore ---------------------------------------------------

pub struct StatusStore {
    store: KeyValueStore,
    cache: RwLock<HashMap<Handle, Arc<CaStatus>>>,
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
            if let Ok(ca) = Handle::from_str(&scope) {
                self.convert_pre_0_9_5_full_status_if_present(&ca)?;
                self.load_full_status(&ca)?;
            }
        }

        Ok(())
    }

    /// Load current status from disk, to be used when starting up. Iif there are any
    /// issues parsing data then default values are used - this data is not critical
    /// so any missing, corrupted, or no longer support data format - can be ignored.
    /// It will get updated with new status values as krill is running.
    fn load_full_status(&self, ca: &Handle) -> KrillResult<()> {
        let repo: RepoStatus = self.store.get(&Self::repo_status_key(ca))?.unwrap_or_default();

        // parents
        let mut parents = ParentStatuses::default();
        for parent_key in self.store.keys(Some(ca.to_string()), "parents-")? {
            let parent = parent_key.name().strip_prefix("parents-").unwrap();
            if let Some(parent) = parent.strip_suffix(".json") {
                if let Ok(parent) = ParentHandle::from_str(parent) {
                    let status: ParentStatus = self
                        .store
                        .get(&Self::parent_status_key(ca, &parent))?
                        .unwrap_or_default();

                    parents.add(parent, status);
                }
            }
        }

        // children
        let mut children = HashMap::new();
        for child_key in self.store.keys(Some(ca.to_string()), "children-")? {
            let child = child_key.name().strip_prefix("children-").unwrap();
            if let Some(child) = child.strip_suffix(".json") {
                if let Ok(child) = ChildHandle::from_str(child) {
                    let status: ChildStatus = self.store.get(&Self::child_status_key(ca, &child))?.unwrap_or_default();

                    children.insert(child, status);
                }
            }
        }

        let status = CaStatus {
            repo,
            parents,
            children,
        };

        self.cache.write().unwrap().insert(ca.clone(), Arc::new(status));

        Ok(())
    }

    fn convert_pre_0_9_5_full_status_if_present(&self, ca: &Handle) -> KrillResult<()> {
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

    fn repo_status_key(ca: &Handle) -> KeyStoreKey {
        // we may need to support multiple repos in future
        KeyStoreKey::scoped(ca.to_string(), "repos-main.json".to_string())
    }

    fn parent_status_key(ca: &Handle, parent: &ParentHandle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), format!("parents-{}.json", parent))
    }

    fn child_status_key(ca: &Handle, child: &ChildHandle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), format!("children-{}.json", child))
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    pub fn get_ca_status(&self, ca: &Handle) -> Arc<CaStatus> {
        self.cache
            .read()
            .unwrap()
            .get(ca)
            .cloned()
            .unwrap_or_else(|| Arc::new(CaStatus::default()))
    }

    pub fn set_parent_failure(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);

        // self.update_ca_status(ca, |status| status.parents.set_failure(parent, uri, error_response))
        //     .await

        self.update_ca_parent_status(ca, parent, |status| status.set_failure(uri.clone(), error_response))
    }

    pub fn set_parent_last_updated(&self, ca: &Handle, parent: &ParentHandle, uri: &ServiceUri) -> KrillResult<()> {
        self.update_ca_parent_status(ca, parent, |status| status.set_last_updated(uri.clone()))
    }

    pub fn set_parent_entitlements(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        entitlements: &Entitlements,
    ) -> KrillResult<()> {
        self.update_ca_parent_status(ca, parent, |status| status.set_entitlements(uri.clone(), entitlements))
    }

    pub fn remove_parent(&self, ca: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if let Some(mut ca_status) = cache.get_mut(ca) {
            let ca_status = Arc::make_mut(&mut ca_status);

            ca_status.parents.remove(parent);
            self.store.drop_key(&Self::parent_status_key(ca, parent))?;
        }
        Ok(())
    }

    pub fn set_child_success(&self, ca: &Handle, child: &ChildHandle, user_agent: Option<String>) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| status.set_success(user_agent))
    }

    pub fn set_child_failure(
        &self,
        ca: &Handle,
        child: &ChildHandle,
        user_agent: Option<String>,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_ca_child_status(ca, child, |status| status.set_failure(user_agent, error_response))
    }

    /// Marks a child as suspended. Note that it will be implicitly unsuspended whenever a new success or
    /// or failure is recorded for the child.
    pub fn set_child_suspended(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| status.set_suspended())
    }

    /// Remove a CA from the saved status
    /// This should be called when the CA is removed from Krill, but note that if this is done for a CA which still exists
    /// a new empty default status will be re-generated when it is accessed for this CA.
    pub fn remove_ca(&self, ca: &Handle) -> KrillResult<()> {
        self.cache.write().unwrap().remove(ca);

        let scope = ca.as_str();
        self.store.drop_scope(scope)?; // will only fail if scope is present and cannot be removed

        Ok(())
    }

    /// Removes a child for the given CA.
    pub fn remove_child(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if let Some(mut ca_status) = cache.get_mut(ca) {
            let ca_status = Arc::make_mut(&mut ca_status);

            ca_status.children.remove(child);
            self.store.drop_key(&Self::child_status_key(ca, child))?;
        }

        Ok(())
    }

    pub fn set_status_repo_failure(&self, ca: &Handle, uri: ServiceUri, error: &Error) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_repo_status(ca, |status| status.set_failure(uri, error_response))
    }

    pub fn set_status_repo_success(&self, ca: &Handle, uri: ServiceUri, next_update: Timestamp) -> KrillResult<()> {
        self.update_repo_status(ca, |status| status.set_last_updated(uri, next_update))
    }

    pub fn set_status_repo_published(
        &self,
        ca: &Handle,
        uri: ServiceUri,
        published: Vec<PublishElement>,
        next_update: Timestamp,
    ) -> KrillResult<()> {
        self.update_repo_status(ca, |status| status.set_published(uri, published, next_update))
    }

    fn update_repo_status<F>(&self, ca: &Handle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut RepoStatus),
    {
        let mut cache = self.cache.write().unwrap();

        if !cache.contains_key(ca) {
            cache.insert(ca.clone(), Arc::new(CaStatus::default()));
        }

        let mut ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing
        let ca_status = Arc::make_mut(&mut ca_status);

        op(&mut ca_status.repo);
        self.store.store(&Self::repo_status_key(ca), ca_status.repo())?;

        Ok(())
    }

    fn update_ca_child_status<F>(&self, ca: &Handle, child: &ChildHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut ChildStatus),
    {
        let status = {
            let mut cache = self.cache.write().unwrap();

            if !cache.contains_key(ca) {
                cache.insert(ca.clone(), Arc::new(CaStatus::default()));
            }

            let mut ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing
            let ca_status = Arc::make_mut(&mut ca_status);

            if !ca_status.children.contains_key(child) {
                ca_status.children.insert(child.clone(), ChildStatus::default());
            }

            let mut child_status = ca_status.children.get_mut(child).unwrap();
            op(&mut child_status);

            child_status.clone()
        };

        self.store.store(&Self::child_status_key(ca, child), &status)?;

        Ok(())
    }

    fn update_ca_parent_status<F>(&self, ca: &Handle, parent: &ParentHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut ParentStatus),
    {
        let status = {
            let mut cache = self.cache.write().unwrap();

            if !cache.contains_key(ca) {
                cache.insert(ca.clone(), Arc::new(CaStatus::default()));
            }

            let mut ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing
            let ca_status = Arc::make_mut(&mut ca_status);

            let mut parent_status = ca_status.parents.get_mut_status(parent);
            op(&mut parent_status);
            parent_status.clone()
        };

        // let status = ca_status.parents.get(parent).unwrap();
        self.store.store(&Self::parent_status_key(ca, parent), &status)?;

        Ok(())
    }

    //  async fn update_ca_child_status<F>(&self, ca: &Handle, child: &ChildHandle, op: F) -> KrillResult<()>
    // where
    //     F: FnOnce(&mut ChildStatus),
    // {
    //     self.update_ca_status(ca, |status| {
    //         let child_status = match status.children.get_mut(child) {
    //             Some(child_status) => child_status,
    //             None => {
    //                 status.children.insert(child.clone(), ChildStatus::default());
    //                 status.children.get_mut(child).unwrap()
    //             }
    //         };
    //         op(child_status)
    //     })
    //     .await
    // }

    // fn update_status<F>(&self, ca: &Handle, op: F) -> KrillResult<()>
    // where
    //     F: FnOnce(&mut CaStatus) -> KrillResult<()>,
    // {
    //     let cache = self.cache.write().unwrap();

    //     if !cache.contains_key(ca) {
    //         cache.insert(ca.clone(), Arc::new(CaStatus::default()));
    //     }

    //     let mut ca_status = cache.get_mut(ca).unwrap(); // safe, we just set it if missing
    //     let mut_status = Arc::make_mut(&mut ca_status);

    //     op(&mut mut_status)?;

    //     Ok(())
    // }

    // async fn update_ca_status<F>(&self, ca: &Handle, op: F) -> KrillResult<()>
    // where
    //     F: FnOnce(&mut CaStatus),
    // {
    //     let lock = self.locks.ca(ca).await;
    //     let _ = lock.write().await;

    //     let mut status: CaStatus = self
    //         .store
    //         .get(&Self::full_status_key(ca))
    //         .ok()
    //         .flatten()
    //         .unwrap_or_default();

    //     op(&mut status);

    //     self.store.store(&Self::full_status_key(ca), &status)?;

    //     Ok(())
    // }

    fn error_to_error_res(error: &Error) -> ErrorResponse {
        match error {
            Error::HttpClientError(httpclient::Error::ErrorResponseWithJson(_, _, res)) => res.clone(),
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
            let testbed = Handle::from_str("testbed").unwrap();

            let status_testbed_migrated = store.get_ca_status(&testbed);

            assert_eq!(&status_testbed_before_migration, status_testbed_migrated.as_ref());
        });
    }
}
