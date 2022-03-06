use std::{collections::HashMap, path::Path, str::FromStr, sync::Arc};

use crate::commons::{
    api::{
        rrdp::PublishElement, ChildConnectionStats, ChildHandle, ChildStatus, ChildrenConnectionStats, Entitlements,
        ErrorResponse, Handle, ParentHandle, ParentStatuses, RepoStatus, Timestamp,
    },
    error::Error,
    eventsourcing::{KeyStoreKey, KeyValueStore},
    remote::rfc8183::ServiceUri,
    util::httpclient,
    KrillResult,
};

use super::manager::CaLocks;

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
    locks: Arc<CaLocks>,
}

impl StatusStore {
    pub fn new(work_dir: &Path, namespace: &str) -> KrillResult<Self> {
        let store = KeyValueStore::disk(work_dir, namespace)?;

        // Create the per-CA lock structure so that we can guarantee safe access to each CA, while allowing
        // multiple CAs in a single Krill instance to interact: e.g. a child can talk to its parent and they
        // are locked individually.
        let locks = Arc::new(CaLocks::default());
        Ok(StatusStore { store, locks })
    }

    fn status_key(ca: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), "status.json".to_string())
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    pub async fn get_ca_status(&self, ca: &Handle) -> Arc<CaStatus> {
        // Try to get it from disk, if it's missing or corrupt - get a default
        let lock = self.locks.ca(ca).await;
        let _ = lock.read().await;

        let status: CaStatus = self.store.get(&Self::status_key(ca)).ok().flatten().unwrap_or_default();

        Arc::new(status)
    }

    /// Returns all CAs for which a status exists
    pub async fn cas(&self) -> KrillResult<HashMap<Handle, Arc<CaStatus>>> {
        let mut cas = HashMap::new();
        for scope in self.store.scopes()? {
            if let Ok(ca) = Handle::from_str(&scope) {
                let status = self.get_ca_status(&ca).await;
                cas.insert(ca, status);
            }
        }

        Ok(cas)
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

    /// Adds a child with default status values if the child is missing
    pub async fn set_child_default_if_missing(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |_status| {}).await
    }

    /// Remove a CA from the saved status
    /// This should be called when the CA is removed from Krill, but note that if this is done for a CA which still exists
    /// a new empty default status will be re-generated when it is accessed for this CA.
    pub async fn remove_ca(&self, ca: &Handle) -> KrillResult<()> {
        let lock = self.locks.ca(ca).await;
        let _ = lock.write().await;

        let scope = ca.as_str();

        self.store.drop_scope(scope)?; // will fail in case of I/O errors only

        Ok(())
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

    pub async fn set_status_repo_success(
        &self,
        ca: &Handle,
        uri: ServiceUri,
        next_update: Timestamp,
    ) -> KrillResult<()> {
        self.update_ca_status(ca, |status| status.repo.set_last_updated(uri, next_update))
            .await
    }

    pub async fn set_status_repo_published(
        &self,
        ca: &Handle,
        uri: ServiceUri,
        published: Vec<PublishElement>,
        next_update: Timestamp,
    ) -> KrillResult<()> {
        self.update_ca_status(ca, |status| status.repo.set_published(uri, published, next_update))
            .await
    }

    async fn update_ca_status<F>(&self, ca: &Handle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut CaStatus),
    {
        let lock = self.locks.ca(ca).await;
        let _ = lock.write().await;

        let mut status: CaStatus = self.store.get(&Self::status_key(ca)).ok().flatten().unwrap_or_default();

        op(&mut status);

        self.store.store(&Self::status_key(ca), &status)?;

        Ok(())
    }

    async fn update_ca_child_status<F>(&self, ca: &Handle, child: &ChildHandle, op: F) -> KrillResult<()>
    where
        F: FnOnce(&mut ChildStatus),
    {
        self.update_ca_status(ca, |status| {
            let child_status = match status.children.get_mut(child) {
                Some(child_status) => child_status,
                None => {
                    status.children.insert(child.clone(), ChildStatus::default());
                    status.children.get_mut(child).unwrap()
                }
            };
            op(child_status)
        })
        .await
    }

    fn error_to_error_res(error: &Error) -> ErrorResponse {
        match error {
            Error::HttpClientError(httpclient::Error::ErrorResponseWithJson(_, _, res)) => res.clone(),
            _ => error.to_error_response(),
        }
    }
}
