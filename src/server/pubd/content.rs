//! Repository content management.

use std::fmt;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use log::{debug, info};
use rpki::uri;
use rpki::ca::idexchange::{MyHandle, PublisherHandle};
use rpki::ca::publication::{ListReply, PublishDelta};
use serde::{Deserialize, Serialize};
use crate::api::admin::PublicationServerUris;
use crate::api::pubd::RepoStats;
use crate::commons::KrillResult;
use crate::commons::error::Error;
use crate::commons::eventsourcing::{
    WalChange, WalCommand, WalSet, WalStore, WalSupport,
};
use crate::constants::PUBSERVER_CONTENT_NS;
use crate::config::{Config, RrdpUpdatesConfig};
use super::rrdp::{
    CurrentObjects, DeltaElements, RrdpServer, RrdpSession, RrdpSessionReset,
    RrdpUpdated, RrdpUpdateNeeded,
};
use super::rsync::RsyncdStore;


//------------ RepositoryContentProxy ----------------------------------------

/// Access to the repository content aggregate.
///
/// We can only have one (1) `RepositoryContent`, but it is stored in a 
/// key value store. This type provides a wrapper around this so that callers
/// don't need to worry about storage details.
#[derive(Debug)]
pub struct RepositoryContentProxy {
    /// The key-value store for the content.
    store: Arc<WalStore<RepositoryContent>>,

    /// The handle for the repository content aggregate.
    default_handle: MyHandle,
}

impl RepositoryContentProxy {
    /// Creates a new repository content proxy.
    pub fn create(config: &Config) -> KrillResult<Self> {
        let store = Arc::new(WalStore::create(
            &config.storage_uri, PUBSERVER_CONTENT_NS,
        )?);
        store.warm()?;

        let default_handle = MyHandle::new("0".into());

        Ok(RepositoryContentProxy {
            store, default_handle,
        })
    }

    /// Initialize the repository content instance.
    pub fn init(
        &self, repo_dir: &Path, uris: PublicationServerUris,
    ) -> KrillResult<()> {
        if self.store.has(&self.default_handle)? {
            return Err(Error::RepositoryServerAlreadyInitialized)
        }

        self.store.add(
            &self.default_handle,
            RepositoryContent::new(
                RrdpServer::create(
                    uris.rrdp_base_uri, repo_dir,
                    RrdpSession::default(),
                ),
                RsyncdStore::new(uris.rsync_jail, repo_dir)
            ),
        )?;

        Ok(())
    }

    /// Returns the repository content aggregate.
    fn read(&self) -> KrillResult<Arc<RepositoryContent>> {
        self.store.get_latest(&self.default_handle)
    }

    /// Converts the RRDP path portion of a HTTP request URI to a path.
    ///
    /// The `path` should contain everything after the `/rrdp/` portion of
    /// the URI’s path. If the path is in principle valid, i.e., could
    /// represent an RRDP resource generated by this RRDP sever, the method
    /// will return a file system path representing this path. This does not
    /// mean there will actually be a file there. The file may have been
    /// deleted or may have never existed at all. This is necessary since
    /// the RRDP server doesn’t track past files, only the currently valid
    /// set of resources.
    ///
    /// If the path is definitely not valid, returns `Ok(None)`. This should
    /// probably be translated into a 404 Not Found response.
    pub fn resolve_rrdp_request_path(
        &self, path: &str
    ) -> KrillResult<Option<PathBuf>> {
        Ok(self.read()?.rrdp.resolve_request_path(path))
    }

    /// Clears all content, so the aggregate can be re-initialized.
    ///
    /// Only to be called after all publishers have been removed from the
    /// RepoAccess as well.
    pub fn clear(&self) -> KrillResult<()> {
        let content = self.read()?;
        content.clear();
        self.store.remove(&self.default_handle)?;

        Ok(())
    }

    /// Returns the repository content stats
    pub fn stats(&self) -> KrillResult<RepoStats> {
        self.read().map(|content| content.stats())
    }

    /// Adds a publisher with an empty set of published objects.
    ///
    /// Replaces an existing publisher if it existed. This is only supposed to
    /// be called after adding the publisher to repository access was
    /// successful which will fail if the publisher is a duplicate.
    ///
    /// The method can only fail if there is an issue with the underlying key
    /// value store.
    pub fn add_publisher(
        &self,
        publisher: PublisherHandle,
    ) -> KrillResult<()> {
        self.store.send_command(
            RepositoryContentCommand::add_publisher(
                self.default_handle.clone(),
                publisher,
            )
        )?;
        Ok(())
    }

    /// Removes a publisher and its content.
    pub fn remove_publisher(
        &self,
        publisher: PublisherHandle,
    ) -> KrillResult<()> {
        self.store.send_command(
            RepositoryContentCommand::remove_publisher(
                self.default_handle.clone(),
                publisher,
            )
        )?;
        Ok(())
    }

    /// Publishes an update for a publisher.
    ///
    /// Assumes that the publication protocol message has been verified, but
    /// will check that all objects are within the publisher's uri space.
    pub fn publish(
        &self,
        publisher: PublisherHandle,
        delta: PublishDelta,
        jail: &uri::Rsync,
    ) -> KrillResult<()> {
        debug!("Publish delta for {publisher}");
        self.store.send_command(
            RepositoryContentCommand::publish(
                self.default_handle.clone(),
                publisher,
                jail.clone(),
                DeltaElements::from(delta),
            )
        )?;
        Ok(())
    }

    /// Checks whether an RRDP update is needed.
    pub fn rrdp_update_needed(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<RrdpUpdateNeeded> {
        self.read().map(|content| {
            content.rrdp.update_rrdp_needed(rrdp_updates_config)
        })
    }

    /// Deletes matching files from the repository and publishers.
    pub fn delete_matching_files(
        &self,
        uri: uri::Rsync,
    ) -> KrillResult<Arc<RepositoryContent>> {
        self.store.send_command(
            RepositoryContentCommand::delete_matching_files(
                self.default_handle.clone(),
                uri,
            )
        )
    }

    /// Updates RRDP and returns the content so it can be used for writing.
    pub fn update_rrdp(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<Arc<RepositoryContent>> {
        self.store.send_command(
            RepositoryContentCommand::create_rrdp_delta(
                self.default_handle.clone(),
                rrdp_updates_config,
            )
        )
    }

    /// Writes all current files to disk
    pub fn write_repository(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<()> {
        self.read()?.write_repository(rrdp_updates_config)
    }

    /// Resets the RRDP session if it is initialized.
    ///
    /// If the session isn’t initialized, does nothing.
    pub fn session_reset(
        &self,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> KrillResult<()> {
        if self.store.has(&self.default_handle)? {
            let content = self.store.send_command(
                RepositoryContentCommand::session_reset(
                    self.default_handle.clone(),
                )
            )?;
            content.write_repository(rrdp_updates_config)
        }
        else {
            // repository server was not initialized on this Krill instance.
            // Nothing to reset.
            Ok(())
        }
    }

    /// Creates a list reply containing all current objects for a publisher.
    pub fn list_reply(
        &self,
        publisher: &PublisherHandle,
    ) -> KrillResult<ListReply> {
        self.read()?.list_reply(publisher)
    }

    /// Returns copies of all current objects for a publisher.
    pub fn current_objects(
        &self,
        name: &PublisherHandle,
    ) -> KrillResult<CurrentObjects> {
        self.read().map(|content| {
            content.objects_for_publisher(name).into_owned()
        })
    }
}

//------------ RepositoryContent -------------------------------------------

/// Manages the content of the repository.
///
/// Access to the repository is managed by an event sourced component which
/// handles the publication protocol, and which can enforce restrictions,
/// such as the base uri for publishers.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryContent {
    /// The revision of aggregate in the WAL store.
    revision: u64,

    /// The RRDP server.
    rrdp: RrdpServer,

    /// The rsync store.
    rsync: RsyncdStore,
}

impl RepositoryContent {
    /// Creates a new repository content manager with the given components.
    ///
    /// This is only used by upgrades.
    pub(super) fn new(rrdp: RrdpServer, rsync: RsyncdStore) -> Self {
        RepositoryContent {
            revision: 0,
            rrdp,
            rsync,
        }
    }

    /// Initializes the repository content.
    pub fn init(
        rrdp_base_uri: uri::Https,
        rsync_jail: uri::Rsync,
        session: RrdpSession,
        repo_base_dir: &Path,
    ) -> Self {
        RepositoryContent {
            revision: 0,
            rrdp: RrdpServer::create(rrdp_base_uri, repo_base_dir, session),
            rsync: RsyncdStore::new(rsync_jail, repo_base_dir),
        }
    }
}

/// # Write-ahead logging support
impl WalSupport for RepositoryContent {
    type Command = RepositoryContentCommand;
    type Change = RepositoryContentChange;
    type Error = Error;

    fn revision(&self) -> u64 {
        self.revision
    }

    fn apply(&mut self, set: WalSet<Self>) {
        for change in set.into_changes() {
            match change {
                RepositoryContentChange::SessionReset { reset } => {
                    self.rrdp.apply_session_reset(reset)
                }
                RepositoryContentChange::RrdpUpdated { update } => {
                    self.rrdp.apply_rrdp_updated(update)
                }
                RepositoryContentChange::RrdpDeltaStaged {
                    publisher, delta,
                } => {
                    self.rrdp.apply_rrdp_staged(publisher, delta)
                }
                RepositoryContentChange::PublisherAdded { publisher } => {
                    self.rrdp.apply_publisher_added(publisher)
                }
                RepositoryContentChange::PublisherRemoved { publisher } => {
                    self.rrdp.apply_publisher_removed(&publisher)
                }
            }
        }
        self.revision += 1;
    }

    fn process_command(
        &self,
        command: Self::Command,
    ) -> Result<Vec<Self::Change>, Self::Error> {
        match command {
            RepositoryContentCommand::ResetSession { .. } => {
                self.reset_session()
            }
            RepositoryContentCommand::CreateRrdpDelta {
                rrdp_updates_config, ..
            } => {
                self.process_create_rrdp_delta(rrdp_updates_config)
            }
            RepositoryContentCommand::AddPublisher { publisher, .. } => {
                self.process_add_publisher(publisher)
            }
            RepositoryContentCommand::RemovePublisher {
                publisher, ..
            } => {
                self.process_remove_publisher(publisher)
            }
            RepositoryContentCommand::DeleteMatchingFiles { uri, .. } => {
                self.process_delete_files(uri)
            }
            RepositoryContentCommand::Publish {
                publisher, jail, delta, ..
            } => {
                self.process_publish(publisher, jail, delta)
            }
        }
    }
}

/// # Publisher Content
impl RepositoryContent {
    /// Clears all content on disk so the repository can be re-initialized.
    fn clear(&self) {
        self.rrdp.clear();
        self.rsync.clear();
    }

    /// Returns all obejcts for a publisher.
    fn objects_for_publisher(
        &self,
        publisher: &PublisherHandle,
    ) -> Cow<CurrentObjects> {
        let current = self.rrdp.snapshot().get_publisher_objects(publisher);
        let staged = self.rrdp.get_publisher_staged(publisher).cloned();

        match (current, staged) {
            (None, None) => Cow::Owned(CurrentObjects::default()),
            (None, Some(staged)) => {
                let mut objects = CurrentObjects::default();
                objects.apply_delta(staged.into());
                Cow::Owned(objects)
            }
            (Some(current), None) => Cow::Borrowed(current),
            (Some(current), Some(staged)) => {
                let mut updated = current.to_owned();
                updated.apply_delta(staged.into());
                Cow::Owned(updated)
            }
        }
    }

    /// Returns a list reply containing all objects for this publisher.
    fn list_reply(
        &self,
        publisher: &PublisherHandle,
    ) -> KrillResult<ListReply> {
        self.objects_for_publisher(publisher).get_list_reply()
    }

    fn reset_session(&self) -> KrillResult<Vec<RepositoryContentChange>> {
        info!("Performing RRDP session reset.");
        let reset = self.rrdp.reset_session();

        Ok(vec![RepositoryContentChange::SessionReset { reset }])
    }

    /// Writes the repository content to disk.
    pub fn write_repository(
        &self,
        config: RrdpUpdatesConfig,
    ) -> KrillResult<()> {
        self.rrdp.update_rrdp_files(config)?;
        self.rsync.write(self.rrdp.serial(), self.rrdp.snapshot())
    }

    /// Processes the “add publisher” command.
    fn process_add_publisher(
        &self,
        publisher: PublisherHandle,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        Ok(vec![RepositoryContentChange::PublisherAdded { publisher }])
    }

    /// Processes the “remove publisher” copmmand.
    ///
    /// Removes the content for a publisher. This function will return
    /// ok if there is no content to remove - it is idempotent in that
    /// sense. However, if there are I/O errors removing the content then
    /// this function will fail.
    fn process_remove_publisher(
        &self,
        publisher: PublisherHandle,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        let mut res = vec![];
        // withdraw objects if any
        let objects = self.objects_for_publisher(&publisher);
        if !objects.is_empty() {
            let withdraws = objects.try_to_withdraw_elements()?;
            let delta = DeltaElements::new(vec![], vec![], withdraws);
            res.push(RepositoryContentChange::RrdpDeltaStaged {
                publisher,
                delta,
            });
        }

        Ok(res)
    }

    /// Processes the “delete files” command.
    ///
    /// Purges content matching the given URI. Recursive if it ends with a
    /// '/'. Removes the content from existing publishers if found, and
    /// removes it from the (global) repository content. Can be used to
    /// fix broken state resulting from issue #981. Can also be used to
    /// remove specific content, although there is nothing stopping the
    /// publisher from publishing that content again.
    fn process_delete_files(
        &self,
        del_uri: uri::Rsync,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        let mut res = vec![];

        info!("Deleting files matching '{del_uri}'");

        for publisher in self.rrdp.publishers() {
            let current_objects = self.objects_for_publisher(&publisher);

            // withdraw objects if any
            let withdraws =
                current_objects.get_matching_withdraws(&del_uri)?;

            if !withdraws.is_empty() {
                info!(
                    "  removing {} matching files from repository for \
                     publisher: {}.",
                    withdraws.len(),
                    publisher
                );
                let delta = DeltaElements::new(vec![], vec![], withdraws);
                res.push(RepositoryContentChange::RrdpDeltaStaged {
                    publisher: publisher.clone(),
                    delta,
                });
            }
        }

        Ok(res)
    }

    /// Processes the “publish” command.
    ///
    /// Publishes the content for a publisher.
    fn process_publish(
        &self,
        publisher: PublisherHandle,
        jail: uri::Rsync,
        delta: DeltaElements,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        if !delta.is_empty() {
            // Verifying the delta first.
            let current_objects = self.objects_for_publisher(&publisher);
            current_objects.verify_delta_applies(&delta, &jail)?;

            Ok(vec![RepositoryContentChange::RrdpDeltaStaged {
                publisher,
                delta,
            }])
        }
        else {
            Ok(vec![])
        }
    }

    /// Processes the “create RRDP delta“ comman which Updates the RRDP state.
    fn process_create_rrdp_delta(
        &self,
        rrdp_config: RrdpUpdatesConfig,
    ) -> KrillResult<Vec<RepositoryContentChange>> {
        if self.rrdp.update_rrdp_needed(rrdp_config) == RrdpUpdateNeeded::Yes
        {
            let update = self.rrdp.update_rrdp(rrdp_config)?;
            Ok(vec![RepositoryContentChange::RrdpUpdated { update }])
        }
        else {
            Ok(vec![])
        }
    }

    /// Returns the content stats for the repo
    fn stats(&self) -> RepoStats {
        RepoStats {
            publishers: self.rrdp.publishers().into_iter().map(|publisher| {
                let stats = self.objects_for_publisher(
                    &publisher
                ).get_stats();
                (publisher, stats)
            }).collect(),
            session: self.rrdp.session().uuid(),
            serial: self.rrdp.serial(),
            last_update: Some(self.rrdp.last_update()),
            rsync_base: self.rsync.base_uri().clone(),
            rrdp_base: self.rrdp.rrdp_base_uri().clone(),
        }
    }
}


//------------ RepositoryContentCommand ------------------------------------

#[derive(Clone, Debug)]
pub enum RepositoryContentCommand {
    ResetSession {
        handle: MyHandle,
    },
    AddPublisher {
        handle: MyHandle,
        publisher: PublisherHandle,
    },
    RemovePublisher {
        handle: MyHandle,
        publisher: PublisherHandle,
    },
    DeleteMatchingFiles {
        handle: MyHandle,
        uri: uri::Rsync,
    },
    Publish {
        handle: MyHandle,
        publisher: PublisherHandle,
        jail: uri::Rsync,
        delta: DeltaElements,
    },
    CreateRrdpDelta {
        handle: MyHandle,
        rrdp_updates_config: RrdpUpdatesConfig,
    },
}

impl RepositoryContentCommand {
    pub fn session_reset(handle: MyHandle) -> Self {
        RepositoryContentCommand::ResetSession { handle }
    }

    pub fn add_publisher(
        handle: MyHandle,
        publisher: PublisherHandle,
    ) -> Self {
        RepositoryContentCommand::AddPublisher { handle, publisher }
    }

    pub fn remove_publisher(
        handle: MyHandle,
        publisher: PublisherHandle,
    ) -> Self {
        RepositoryContentCommand::RemovePublisher { handle, publisher }
    }

    pub fn delete_matching_files(handle: MyHandle, uri: uri::Rsync) -> Self {
        RepositoryContentCommand::DeleteMatchingFiles { handle, uri }
    }

    pub fn publish(
        handle: MyHandle,
        publisher: PublisherHandle,
        jail: uri::Rsync,
        delta: DeltaElements,
    ) -> Self {
        RepositoryContentCommand::Publish {
            handle,
            publisher,
            jail,
            delta,
        }
    }

    pub fn create_rrdp_delta(
        handle: MyHandle,
        rrdp_updates_config: RrdpUpdatesConfig,
    ) -> Self {
        RepositoryContentCommand::CreateRrdpDelta {
            handle,
            rrdp_updates_config,
        }
    }
}

impl WalCommand for RepositoryContentCommand {
    fn handle(&self) -> &MyHandle {
        match self {
            RepositoryContentCommand::ResetSession { handle }
            | RepositoryContentCommand::AddPublisher { handle, .. }
            | RepositoryContentCommand::RemovePublisher { handle, .. }
            | RepositoryContentCommand::Publish { handle, .. }
            | RepositoryContentCommand::DeleteMatchingFiles {
                handle, ..
            }
            | RepositoryContentCommand::CreateRrdpDelta { handle, .. } => {
                handle
            }
        }
    }
}

impl fmt::Display for RepositoryContentCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryContentCommand::ResetSession { handle } => {
                write!(f, "reset session for repository {handle}")
            }
            RepositoryContentCommand::CreateRrdpDelta { handle, .. } => {
                write!(f, "create next RRDP delta for repository {handle}")
            }
            RepositoryContentCommand::AddPublisher { handle, publisher } => {
                write!(
                    f,
                    "add publisher '{publisher}' to repository {handle}"
                )
            }
            RepositoryContentCommand::RemovePublisher {
                handle,
                publisher,
                ..
            } => {
                write!(
                    f,
                    "remove publisher '{publisher}' from repository {handle}"
                )
            }
            RepositoryContentCommand::DeleteMatchingFiles {
                handle,
                uri,
                ..
            } => {
                write!(
                    f,
                    "remove content matching '{uri}' from repository {handle}"
                )
            }
            RepositoryContentCommand::Publish {
                handle, publisher, ..
            } => {
                write!(
                    f,
                    "publish for publisher '{publisher}' under repository {handle}"
                )
            }
        }
    }
}

//------------ RepositoryContentChange -------------------------------------

//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryContentChange {
    SessionReset {
        reset: RrdpSessionReset,
    },
    PublisherAdded {
        publisher: PublisherHandle,
    },
    PublisherRemoved {
        publisher: PublisherHandle,
    },
    RrdpDeltaStaged {
        publisher: PublisherHandle,
        delta: DeltaElements,
    },
    RrdpUpdated {
        update: RrdpUpdated,
    },
}

impl fmt::Display for RepositoryContentChange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryContentChange::SessionReset { reset } => {
                write!(f, "RRDP session reset to: {}", reset.session)
            }
            RepositoryContentChange::RrdpDeltaStaged { .. } => {
                write!(f, "RRDP changes staged")
            }
            RepositoryContentChange::RrdpUpdated { .. } => {
                write!(f, "RRDP updated")
            }
            RepositoryContentChange::PublisherAdded { publisher } => {
                write!(f, "added publisher: {publisher}")
            }
            RepositoryContentChange::PublisherRemoved { publisher } => {
                write!(f, "removed publisher: {publisher}")
            }
        }
    }
}

impl WalChange for RepositoryContentChange {}

