use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::commons::api::rrdp::PublishElement;
use crate::commons::api::{Entitlements, ErrorResponse, Handle, ParentHandle, ParentStatuses, RepoStatus};
use crate::commons::error::Error;
use crate::commons::eventsourcing::{DiskKeyStore, KeyStore};
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
    pub fn new(work_dir: &PathBuf, namespace: &str) -> Self {
        let store = DiskKeyStore::new(work_dir, namespace);
        let lock = RwLock::new(());
        StatusStore { store, lock }
    }

    fn status_key() -> PathBuf {
        PathBuf::from("status.json")
    }

    /// Returns the stored CaStatus for a CA, or a default (empty) status if it can't be found
    fn get_ca_status(&self, ca: &Handle) -> KrillResult<CaStatus> {
        let _read = self.lock.read().unwrap();
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
        let _write = self.lock.write().unwrap();
        self.store.store(ca, &Self::status_key(), status).map_err(|e| {
            Error::IoError(io::Error::new(
                io::ErrorKind::Other,
                format!("Can't save ca status.json to keystore: {}", e),
            ))
        })?;
        Ok(())
    }

    pub fn set_parent_failure(&self, ca: &Handle, parent: &ParentHandle, error: ErrorResponse) -> KrillResult<()> {
        let mut status = self.get_ca_status(ca)?;
        status.parents.set_failure(parent, error);
        self.set_ca_status(ca, &status)
    }

    pub fn set_parent_last_updated(&self, ca: &Handle, parent: &ParentHandle) -> KrillResult<()> {
        let mut status = self.get_ca_status(ca)?;
        status.parents.set_last_updated(parent);
        self.set_ca_status(ca, &status)
    }

    pub fn set_parent_entitlements(
        &self,
        ca: &Handle,
        parent: &ParentHandle,
        entitlements: &Entitlements,
    ) -> KrillResult<()> {
        let mut status = self.get_ca_status(ca)?;
        status.parents.set_entitlements(parent, entitlements);
        self.set_ca_status(ca, &status)
    }

    pub fn get_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> {
        let status = self.get_ca_status(ca)?;
        Ok(status.parents)
    }

    pub fn get_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> {
        let status = self.get_ca_status(ca)?;
        Ok(status.repo)
    }

    pub fn set_status_repo_failure(&self, ca: &Handle, error: ErrorResponse) -> KrillResult<()> {
        let mut status = self.get_ca_status(ca)?;
        status.repo.set_failure(error);
        self.set_ca_status(ca, &status)
    }

    pub fn set_status_repo_success(&self, ca: &Handle, objects: Vec<PublishElement>) -> KrillResult<()> {
        let mut status = self.get_ca_status(ca)?;
        status.repo.set_success(objects);
        self.set_ca_status(ca, &status)
    }
}
