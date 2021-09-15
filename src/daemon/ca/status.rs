use std::{collections::HashMap, path::Path, sync::Arc};

use tokio::sync::RwLock;

use crate::commons::{
    api::{
        rrdp::PublishElement, ChildConnectionStats, ChildHandle, ChildStatus, ChildrenConnectionStats, Entitlements,
        ErrorResponse, Handle, ParentHandle, ParentStatuses, RepoStatus,
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
        Ok(StatusStore { store, cache })
    }

    fn status_key(ca: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), "status.json".to_string())
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    pub async fn get_ca_status(&self, ca: &Handle) -> KrillResult<Arc<CaStatus>> {
        // Try to get it from cache first
        {
            if let Some(status) = self.cache.read().await.get(ca) {
                return Ok(status.clone());
            }
        }

        // Try to get it from disk, and if present load the cache
        let status: CaStatus = self.store.get(&Self::status_key(ca))?.unwrap_or_default();
        let status = Arc::new(status);

        self.cache.write().await.insert(ca.clone(), status.clone());
        Ok(status)
    }

    pub async fn set_parent_failure(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        error: &Error,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);

        self.update_ca_status(ca, |status| {
            status
                .parents
                .set_failure(parent, uri, error_response, next_run_seconds)
        })
        .await
    }

    pub async fn set_parent_last_updated(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        self.update_ca_status(ca, |status| {
            status.parents.set_last_updated(parent, uri, next_run_seconds)
        })
        .await
    }

    pub async fn set_parent_entitlements(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        entitlements: &Entitlements,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        self.update_ca_status(ca, |status| {
            status
                .parents
                .set_entitlements(parent, uri, entitlements, next_run_seconds)
        })
        .await
    }

    pub async fn remove_parent(&self, ca: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        self.update_ca_status(ca, |status| status.parents.remove(parent)).await
    }

    pub async fn set_child_success(
        &self,
        ca: &Handle,
        child: &ChildHandle,
        user_agent: Option<String>,
    ) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| status.set_success(user_agent))
            .await
    }

    pub async fn set_child_failure(
        &self,
        ca: &Handle,
        child: &ChildHandle,
        user_agent: Option<String>,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);

        self.update_ca_child_status(ca, child, |status| status.set_failure(user_agent, error_response))
            .await
    }

    /// Marks a child as suspended. Note that it will be implicitly unsuspended whenever a new success or
    /// or failure is recorded for the child.
    pub async fn set_child_suspended(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| status.set_suspended())
            .await
    }

    /// Remove a CA from the saved status
    /// This should be called when the CA is removed from Krill, but note that if this is done for a CA which still exists
    /// a new empty default status will be re-generated when it is accessed for this CA.
    pub async fn remove_ca(&self, ca: &Handle) -> KrillResult<()> {
        let mut cache = self.cache.write().await;

        if !cache.contains_key(ca) {
            Ok(()) // idempotent
        } else {
            let key = Self::status_key(ca);

            // will fail if there is an I/O error, but come back ok if the key had been dropped already.
            self.store.drop_key(&key)?;

            cache.remove(ca);

            Ok(())
        }
    }

    /// Removes a child for the given CA.
    pub async fn remove_child(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<()> {
        self.update_ca_status(ca, |status| {
            status.children.remove(child);
        })
        .await
    }

    pub async fn set_status_repo_failure(&self, ca: &Handle, uri: ServiceUri, error: &Error) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_ca_status(ca, |status| status.repo.set_failure(uri, error_response))
            .await
    }

    pub async fn set_status_repo_success(&self, ca: &Handle, uri: ServiceUri, next_hours: i64) -> KrillResult<()> {
        self.update_ca_status(ca, |status| status.repo.set_last_updated(uri, next_hours))
            .await
    }

    pub async fn set_status_repo_published(
        &self,
        ca: &Handle,
        uri: ServiceUri,
        published: Vec<PublishElement>,
        next_hours: i64,
    ) -> KrillResult<()> {
        self.update_ca_status(ca, |status| status.repo.set_published(uri, published, next_hours))
            .await
    }

    async fn update_ca_status<F>(&self, ca: &Handle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut CaStatus),
    {
        let mut cache = self.cache.write().await;

        let mut status: CaStatus = self.store.get(&Self::status_key(ca))?.unwrap_or_default();

        op(&mut status);

        self.store.store(&Self::status_key(ca), &status)?;
        cache.insert(ca.clone(), Arc::new(status));

        Ok(())
    }

    async fn update_ca_child_status<F>(&self, ca: &Handle, child: &ChildHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut ChildStatus),
    {
        self.update_ca_status(ca, |status| {
            let mut child_status = match status.children.get_mut(child) {
                Some(child_status) => child_status,
                None => {
                    status.children.insert(child.clone(), ChildStatus::default());
                    status.children.get_mut(child).unwrap()
                }
            };
            op(&mut child_status)
        })
        .await
    }

    fn error_to_error_res(error: &Error) -> ErrorResponse {
        match error {
            Error::HttpClientError(httpclient::Error::ErrorWithJson(_, res)) => res.clone(),
            _ => error.to_error_response(),
        }
    }
}
