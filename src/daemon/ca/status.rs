use std::io;
use std::path::PathBuf;

use tokio::sync::RwLock;

use crate::commons::api::rrdp::PublishElement;
use crate::commons::api::{Entitlements, ErrorResponse, Handle, ParentHandle, ParentStatuses, RepoStatus};
use crate::commons::error::Error;
use crate::commons::eventsourcing::{DiskKeyStore, KeyStore};
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
    store: DiskKeyStore,
    lock: RwLock<()>,
}

impl StatusStore {
    pub fn new(work_dir: &PathBuf, namespace: &str) -> KrillResult<Self> {
        let store = DiskKeyStore::under_work_dir(work_dir, namespace)?;
        let lock = RwLock::new(());
        Ok(StatusStore { store, lock })
    }

    fn status_key() -> PathBuf {
        PathBuf::from("status.json")
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    fn get_ca_status(&self, ca: &Handle) -> KrillResult<CaStatus> {
        Ok(self
            .store
            .get(ca, &Self::status_key())
            .map_err(|e| {
                Error::IoError(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Can't read ca status.json to keystore: {}", e),
                ))
            })?
            .unwrap_or_default())
    }

    /// Save the status for a CA
    fn set_ca_status(&self, ca: &Handle, status: &CaStatus) -> KrillResult<()> {
        self.store.store(ca, &Self::status_key(), status).map_err(|e| {
            Error::IoError(io::Error::new(
                io::ErrorKind::Other,
                format!("Can't save ca status.json to keystore: {}", e),
            ))
        })?;
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
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;

        let error_response = Self::error_to_error_res(&error);

        status.parents.set_failure(parent, uri, error_response);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_parent_last_updated(&self, ca: &Handle, parent: &ParentHandle, uri: String) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.parents.set_last_updated(parent, uri);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_parent_entitlements(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        uri: String,
        entitlements: &Entitlements,
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.parents.set_entitlements(parent, uri, entitlements);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_status_repo_failure(&self, ca: &Handle, uri: String, error: &Error) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;

        let error_response = Self::error_to_error_res(&error);

        status.repo.set_failure(uri, error_response);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_status_repo_success(&self, ca: &Handle, uri: String) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.repo.set_last_updated(uri);
        self.set_ca_status(ca, &status)
    }

    pub async fn set_status_repo_elements(
        &self,
        ca: &Handle,
        uri: String,
        objects: Vec<PublishElement>,
    ) -> KrillResult<()> {
        let _lock = self.lock.write().await;
        let mut status = self.get_ca_status(ca)?;
        status.repo.set_success(uri, objects);
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
