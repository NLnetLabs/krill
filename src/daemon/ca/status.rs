use std::{collections::HashMap, path::Path};

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
struct CaStatus {
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
            .map(|(handle, status)| ChildConnectionStats::new(handle, status.into()))
            .collect();
        ChildrenConnectionStats::new(children)
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
    lock: RwLock<()>,
}

impl StatusStore {
    pub fn new(work_dir: &Path, namespace: &str) -> KrillResult<Self> {
        let store = KeyValueStore::disk(work_dir, namespace)?;
        let lock = RwLock::new(());
        Ok(StatusStore { store, lock })
    }

    fn status_key(ca: &Handle) -> KeyStoreKey {
        KeyStoreKey::scoped(ca.to_string(), "status.json".to_string())
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    fn get_ca_status(&self, ca: &Handle) -> KrillResult<CaStatus> {
        Ok(self.store.get(&Self::status_key(ca))?.unwrap_or_default())
    }

    pub async fn get_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> {
        let _lock = self.lock.read().await;
        let status = self.get_ca_status(ca)?;
        Ok(status.parents)
    }

    pub async fn get_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> {
        let _lock = self.lock.read().await;
        let status = self.get_ca_status(ca)?;
        Ok(status.repo)
    }

    pub async fn set_parent_failure(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        error: &Error,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(&error);

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
        let error_response = Self::error_to_error_res(&error);

        self.update_ca_child_status(ca, child, |status| status.set_failure(user_agent, error_response))
            .await
    }

    pub async fn remove_child(&self, ca: &Handle, child: &ChildHandle) -> KrillResult<()> {
        self.update_ca_status(ca, |status| {
            status.children.remove(child);
        })
        .await
    }

    pub async fn get_stats_child_connections(&self, ca: &Handle) -> KrillResult<ChildrenConnectionStats> {
        let _lock = self.lock.read().await;
        let status = self.get_ca_status(ca)?;

        Ok(status.get_children_connection_stats())
    }

    pub async fn set_status_repo_failure(&self, ca: &Handle, uri: ServiceUri, error: &Error) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(&error);
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
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        op(&mut status);

        self.store.store(&Self::status_key(ca), &status)?;

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
