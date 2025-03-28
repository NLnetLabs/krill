//! A separate store to keep the status of each CA.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::RwLock;
use log::info;
use rpki::ca::idexchange::{CaHandle, ChildHandle, ParentHandle, ServiceUri};
use rpki::ca::provisioning::ResourceClassListResponse as Entitlements;
use rpki::ca::publication::PublishDelta;
use serde::{Deserialize, Serialize};
use url::Url;
use crate::api::ca::{
    ChildConnectionStats, ChildStatus, ChildrenConnectionStats, ParentStatus,
    ParentStatuses, RepoStatus,
};
use crate::api::status::ErrorResponse;
use crate::commons::httpclient;
use crate::commons::KrillResult;
use crate::commons::error::Error;
use crate::commons::storage::{Key, KeyValueStore, Namespace, Scope, Segment};

const PARENTS_PREFIX: &Segment = Segment::make("parents-");
const CHILDREN_PREFIX: &Segment = Segment::make("children-");
const JSON_SUFFIX: &str = ".json";


//------------ CaStatusStore -------------------------------------------------

/// A store to keep the curren stastus of each CA.
///
/// The store information about the last contact of a CA with its repository,
/// its parents and its children. The information isn’t authoritative, it acts
/// more as a short-cut. However, the CA manager relies on the information
/// when scheduling the next contact – and will do so right away if it is
/// missing. Thus, if we want to allow a multiple concurrent Krill instances,
/// the concept of this store needs to be rethought.
///
/// # Key-value store usage
///
/// The store uses its own namespace, currently `"status"`. Its key uses a
/// single segment scope comprised of the handle of th CA: The name of the
/// key is `repos-main.json` for the repository status,
/// `parent-<handle>.json` for the parent status of a parent with the handle
/// `<handle>`, or `children-<handle>.json` for the child status of the child
/// CA with the handle `<handle>`.
pub struct CaStatusStore {
    /// The key-value store for the status.
    ///
    /// Any status changes are written to the store for persistence. The
    /// store will, however, only be read upon startup.
    store: KeyValueStore,

    /// The in-memory store for the status.
    ///
    /// During running, we only ever read data from here.
    //
    //  XXX Maybe this should be a broken up into the parts as well? And
    //      then use arcswap rather than cloning?
    cache: RwLock<HashMap<CaHandle, CaStatus>>,
}

impl CaStatusStore {
    /// Creates a new status store with the givn storage URI and namespace.
    pub fn create(
        storage_uri: &Url,
        namespace: &Namespace,
    ) -> KrillResult<Self> {
        let store = KeyValueStore::create(storage_uri, namespace)?;
        let cache = RwLock::new(HashMap::new());

        let store = Self { store, cache };
        store.warm()?;

        Ok(store)
    }

    /// Load existing status from disk.
    ///
    /// It supports the pre 0.9.5 format and silently convert it if needed.
    fn warm(&self) -> KrillResult<()> {
        for scope in self.store.scopes()? {
            if let Ok(ca) = CaHandle::from_str(&scope.to_string()) {
                self.convert_pre_0_9_5_full_status_if_present(&ca)?;
                self.load_full_status(&ca)?;
            }
        }

        Ok(())
    }

    /// Loads the current status from disk.
    ///
    /// This is to be used when starting up. If there are any issues parsing
    /// data, default values are used ~ this data is not critical so any
    /// missing, corrupted, or no longer supported data format can be
    /// ignored. It will get updated with new status values as Krill is
    /// running.
    fn load_full_status(&self, ca: &CaHandle) -> KrillResult<()> {
        // Get the repo status.
        let repo: RepoStatus = match self.store.get(
            &Self::repo_status_key(ca)
        ) {
            Ok(Some(status)) => status,
            _ => RepoStatus::default(),
        };

        // Parents
        let mut parents = ParentStatuses::default();
        let keys = self.store.keys(
            &Scope::from_segment(Segment::parse_lossy(ca.as_str())),
            PARENTS_PREFIX.as_str(),
        )?;
        for parent_key in keys {
            // Try to parse the key to get a parent handle
            if let Some(parent) = parent_key
                .name()
                .as_str()
                .strip_prefix(PARENTS_PREFIX.as_str())
                .and_then(|pfx_stripped| {
                    pfx_stripped.strip_suffix(JSON_SUFFIX)
                })
                .and_then(|handle_str| {
                    ParentHandle::from_str(handle_str).ok()
                })
            {
                // try to read the status, if there is any issue, e.g. because
                // the format changed in a new version, then just fall back to
                // an empty default value. We will get a new connection status
                // value soon enough as Krill is running.
                let status: ParentStatus = match self.store.get(
                    &Self::parent_status_key(ca, &parent)
                ) {
                    Ok(Some(status)) => status,
                    _ => ParentStatus::default(),
                };

                parents.insert(parent, status);
            }
        }

        // Children
        let mut children = HashMap::new();
        let keys = self.store.keys(
            &Scope::from_segment(Segment::parse_lossy(ca.as_str())),
            CHILDREN_PREFIX.as_str(),
        )?;
        for child_key in keys {
            // Try to parse the key to get a child handle
            if let Some(child) = child_key
                .name()
                .as_str()
                .strip_prefix(CHILDREN_PREFIX.as_str())
                .and_then(|pfx_stripped| {
                    pfx_stripped.strip_suffix(JSON_SUFFIX)
                })
                .and_then(|handle_str| ChildHandle::from_str(handle_str).ok())
            {
                // try to read the status, if there is any issue, e.g. because
                // the format changed in a new version, then just fall back to
                // an empty default value. We will get a new connection status
                // value soon enough as Krill is running.
                let status: ChildStatus = match self.store.get(
                    &Self::child_status_key(ca, &child)
                ) {
                    Ok(Some(status)) => status,
                    _ => ChildStatus::default(),
                };

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

    /// Converts pre-0.9.5 status to the current format.
    ///
    /// The difference is that in the old version everything was stored in
    /// one file `status.json` whereas we know have multiple smaller files.
    /// This function reads the old file, breaks it up and writes the smaller
    /// ones.
    fn convert_pre_0_9_5_full_status_if_present(
        &self,
        ca: &CaHandle,
    ) -> KrillResult<()> {
        let key = Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(ca.as_str())),
            const { Segment::make("status.json") },
        );

        let status = self.store.get::<CaStatus>(&key).ok().flatten();
        if let Some(full_status) = status {
            info!(
                "Migrating pre 0.9.5 connection status file for CA '{}' \
                 to new format",
                ca
            );
            // repo status
            self.store.store(
                &Self::repo_status_key(ca),
                full_status.repo()
            )?;

            // parents
            for (parent, status) in full_status.parents().iter() {
                self.store.store(
                    &Self::parent_status_key(ca, parent),
                    status,
                )?;
            }

            // children
            for (child, status) in full_status.children.iter() {
                self.store.store(
                    &Self::child_status_key(ca, child),
                    status,
                )?;
            }

            self.store.drop_key(&key)?;
            info!("Done migrating pre 0.9.5 connection status file");
        }
        Ok(())
    }

    /// Returns the key for the repo status portion of the CA status.
    fn repo_status_key(ca: &CaHandle) -> Key {
        // We may need to support multiple repos in future, so we
        // inject `main` as the repo name here.
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(ca.as_str())),
            const { Segment::make("repos-main.json") },
        )
    }

    /// Returns the key for the given parent.
    fn parent_status_key(ca: &CaHandle, parent: &ParentHandle) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(ca.as_str())),
            Segment::parse_lossy(&format!(
                "{}{}{}",
                PARENTS_PREFIX, parent, JSON_SUFFIX
            )),
        )
    }

    /// Returns the key for the given child.
    fn child_status_key(ca: &CaHandle, child: &ChildHandle) -> Key {
        Key::new_scoped(
            Scope::from_segment(Segment::parse_lossy(ca.as_str())),
            Segment::parse_lossy(&format!(
                "{}{}{}",
                CHILDREN_PREFIX, child, JSON_SUFFIX
            )),
        )
    }

    /// Returns the stored Status for a CA or a default status.
    ///
    /// The status is only read from the cache, not actually from the
    /// persistent store.
    pub fn get_ca_status(&self, ca: &CaHandle) -> CaStatus {
        self.cache
            .read()
            .unwrap()
            .get(ca)
            .cloned()
            .unwrap_or_default()
    }
}

/// # Status Updates
///
impl CaStatusStore {
    /// Sets the last exchange with the parent to the given failure.
    pub fn set_parent_failure(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_ca_parent_status(ca, parent, |status| {
            status.set_failure(uri.clone(), error_response)
        })
    }

    /// Sets the last exchange with the parent to a success.
    pub fn set_parent_last_updated(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        uri: &ServiceUri,
    ) -> KrillResult<()> {
        self.update_ca_parent_status(ca, parent, |status| {
            status.set_last_updated(uri.clone())
        })
    }

    /// Sets the entitlements for the parent
    pub fn set_parent_entitlements(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        uri: &ServiceUri,
        entitlements: &Entitlements,
    ) -> KrillResult<()> {
        self.update_ca_parent_status(ca, parent, |status| {
            status.set_entitlements(uri.clone(), entitlements)
        })
    }

    /// Removes the given parent.
    pub fn remove_parent(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
    ) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if let Some(ca_status) = cache.get_mut(ca) {
            ca_status.parents.remove(parent);
            self.store.drop_key(&Self::parent_status_key(ca, parent))?;
        }
        Ok(())
    }

    /// Sets the last child contact to a success.
    pub fn set_child_success(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
        user_agent: Option<String>,
    ) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| {
            status.set_success(user_agent)
        })
    }

    /// Sets the last child contact to a failure.
    pub fn set_child_failure(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
        user_agent: Option<String>,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_ca_child_status(ca, child, |status| {
            status.set_failure(user_agent, error_response)
        })
    }

    /// Marks a child as suspended.
    ///
    /// Note that it will be implicitly unsuspended whenever a new success
    /// or or failure is recorded for the child.
    pub fn set_child_suspended(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<()> {
        self.update_ca_child_status(ca, child, |status| {
            status.set_suspended()
        })
    }

    /// Removes a child for the given CA.
    pub fn remove_child(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
    ) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if let Some(ca_status) = cache.get_mut(ca) {
            ca_status.children.remove(child);
            self.store.drop_key(&Self::child_status_key(ca, child))?;
        }

        Ok(())
    }

    /// Remove a CA from the saved status.
    ///
    /// This should be called when the CA is removed from Krill, but note
    /// that if this is done for a CA which still exists a new empty default
    /// status will be re-generated when it is accessed for this CA.
    pub fn remove_ca(&self, ca: &CaHandle) -> KrillResult<()> {
        self.cache.write().unwrap().remove(ca);
        self.store.drop_scope(
            &Scope::from_segment(Segment::parse_lossy(
                ca.as_str(),
            ))
        )?; 
        Ok(())
    }

    /// Sets the last repository contact to the given error.
    pub fn set_status_repo_failure(
        &self,
        ca: &CaHandle,
        uri: ServiceUri,
        error: &Error,
    ) -> KrillResult<()> {
        let error_response = Self::error_to_error_res(error);
        self.update_repo_status(ca, |status| {
            status.set_failure(uri, error_response)
        })
    }

    /// Sets the last repository contact to success.
    pub fn set_status_repo_success(
        &self,
        ca: &CaHandle,
        uri: ServiceUri,
    ) -> KrillResult<()> {
        self.update_repo_status(ca, |status| status.set_last_updated(uri))
    }

    /// Sets the last delta sent to the repository.
    pub fn set_status_repo_published(
        &self,
        ca: &CaHandle,
        uri: ServiceUri,
        delta: PublishDelta,
    ) -> KrillResult<()> {
        self.update_repo_status(ca, |status| {
            status.update_published(uri, delta)
        })
    }

    /// Updates the repository status.
    fn update_repo_status<F: FnOnce(&mut RepoStatus)>(
        &self, ca: &CaHandle, op: F
    ) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if !cache.contains_key(ca) {
            cache.insert(ca.clone(), CaStatus::default());
        }

        // Unwrap is safe, we just set it if missing.
        let ca_status = cache.get_mut(ca).unwrap();

        op(&mut ca_status.repo);

        self.store.store(
            &Self::repo_status_key(ca), ca_status.repo()
        )?;

        Ok(())
    }

    /// Updates a child status.
    fn update_ca_child_status<F: FnOnce(&mut ChildStatus)>(
        &self,
        ca: &CaHandle,
        child: &ChildHandle,
        op: F,
    ) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if !cache.contains_key(ca) {
            cache.insert(ca.clone(), CaStatus::default());
        }

        // unwrap is safe, we just set it if missing
        let ca_status = cache.get_mut(ca).unwrap(); 

        if !ca_status.children.contains_key(child) {
            ca_status.children.insert(
                child.clone(), ChildStatus::default()
            );
        }

        let child_status = ca_status.children.get_mut(child).unwrap();
        op(child_status);

        self.store.store(&Self::child_status_key(ca, child), child_status)?;

        Ok(())
    }

    /// Updates a parent status.
    fn update_ca_parent_status<F: FnOnce(&mut ParentStatus)>(
        &self,
        ca: &CaHandle,
        parent: &ParentHandle,
        op: F,
    ) -> KrillResult<()> {
        let mut cache = self.cache.write().unwrap();

        if !cache.contains_key(ca) {
            cache.insert(ca.clone(), CaStatus::default());
        }

        let ca_status = cache.get_mut(ca).unwrap();

        let parent_status = ca_status.parents.get_or_default_mut(parent);
        op(parent_status);

        self.store.store(
            &Self::parent_status_key(ca, parent), &parent_status
        )?;

        Ok(())
    }

    /// Converts an error to an error response.
    fn error_to_error_res(error: &Error) -> ErrorResponse {
        match error {
            Error::HttpClientError(
                httpclient::Error::ErrorResponseWithJson(_, _, res),
            ) => *res.clone(),
            _ => error.to_error_response(),
        }
    }
}


//------------ CaStatus ------------------------------------------------------

/// The status of a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaStatus {
    /// The status of the CA’s repository.
    repo: RepoStatus,

    /// The status of contacts to the parent CAs.
    parents: ParentStatuses,

    /// The status of contacts by the child CAs.
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default = "HashMap::new"
    )]
    children: HashMap<ChildHandle, ChildStatus>,
}

impl CaStatus {
    /// Returns the connection status of all children.
    pub fn get_children_connection_stats(&self) -> ChildrenConnectionStats {
        ChildrenConnectionStats {
            children: self.children().iter().map(|(handle, status)| {
                ChildConnectionStats {
                    handle: handle.clone(),
                    last_exchange: status.last_exchange.clone(),
                    state: status.child_state(),
                }
            }).collect()
        }
    }

    /// Returns a reference to the repository status.
    pub fn repo(&self) -> &RepoStatus {
        &self.repo
    }

    /// Returns a reference to the parent statuses.
    pub fn parents(&self) -> &ParentStatuses {
        &self.parents
    }

    /// Returns a reference to the child statuses.
    pub fn children(&self) -> &HashMap<ChildHandle, ChildStatus> {
        &self.children
    }
}

