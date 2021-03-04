use std::path::PathBuf;

use tokio::sync::RwLock;

use crate::commons::api::{
    rrdp::PublishElement, Entitlements, ErrorResponse, Handle, ParentHandle, ParentStatuses, RepoStatus,
};
use crate::commons::error::Error;
use crate::commons::eventsourcing::{KeyStoreKey, KeyValueStore};
use crate::commons::util::httpclient;
use crate::commons::KrillResult;

//------------ CaStatus ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CaStatus {
    repo: RepoStatus,
    parents: ParentStatuses,
}

impl Default for CaStatus {
    fn default() -> Self {
        CaStatus {
            repo: RepoStatus::default(),
            parents: ParentStatuses::default(),
        }
    }
}

//------------ StatusStore ---------------------------------------------------

pub struct StatusStore {
    store: KeyValueStore,
    lock: RwLock<()>,
}

impl StatusStore {
    pub fn new(work_dir: &PathBuf, namespace: &str) -> KrillResult<Self> {
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

    /// Save the status for a CA
    fn set_ca_status(&self, ca: &Handle, status: &CaStatus) -> KrillResult<()> {
        self.store.store(&Self::status_key(ca), status)?;
        Ok(())
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
        uri: String,
        error: &Error,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;

        let error_response = Self::error_to_error_res(&error);

        status
            .parents
            .set_failure(parent, uri, error_response, next_run_seconds);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_parent_last_updated(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: String,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.parents.set_last_updated(parent, uri, next_run_seconds);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_parent_entitlements(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: String,
        entitlements: &Entitlements,
        next_run_seconds: i64,
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status
            .parents
            .set_entitlements(parent, uri, entitlements, next_run_seconds);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_status_repo_failure(&self, ca: &Handle, uri: String, error: &Error) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;

        let error_response = Self::error_to_error_res(&error);

        status.repo.set_failure(uri, error_response);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_status_repo_success(&self, ca: &Handle, uri: String, next_hours: i64) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.repo.set_last_updated(uri, next_hours);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_status_repo_published(
        &self,
        ca: &Handle,
        uri: String,
        published: Vec<PublishElement>,
        next_hours: i64,
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.repo.set_published(uri, published, next_hours);
        self.set_ca_status(ca, &status)
    }

    fn error_to_error_res(error: &Error) -> ErrorResponse {
        match error {
            Error::HttpClientError(http_error) => match http_error {
                httpclient::Error::ErrorWithJson(_, res) => res.clone(),
                _ => error.to_error_response(),
            },
            _ => error.to_error_response(),
        }
    }
}
