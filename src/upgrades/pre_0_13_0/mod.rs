use std::{collections::HashMap, fmt, path::PathBuf};

use rpki::{ca::idexchange::PublisherHandle, uri};

use crate::{
    commons::{
        api::rrdp::{CurrentObjects, DeltaElements},
        error::Error,
        eventsourcing::{WalChange, WalSupport},
    },
    pubd::{RepositoryContent, RepositoryContentCommand, RrdpServer, RrdpSessionReset, RrdpUpdated, RsyncdStore},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldRepositoryContent {
    #[serde(default)] // Make this backward compatible
    pub revision: u64,

    // The publishers were kept together with their objects
    // in the old RepositoryContent. Data was duplicated between
    // this map and the RrdpServer. Theoretically this could lead
    // to unintended differences.
    //
    // The publisher map was used to inform publisher which files
    // were current. So this should be the authoritative source
    // of info.
    //
    // The RrdpServer kept its own data to make snapshots and
    // deltas - and keep track of staged changes - but this was
    // lacking the information of which publishers owned the files.
    //
    // In this migration we will migrate to using the updated RrdpServer
    // that does keep track of which publisher owns the files in the
    // repository. We will use the old publisher map as the authoritative
    // source to regenerate that data.
    pub publishers: HashMap<PublisherHandle, CurrentObjects>,
    pub rrdp: OldRrdpServer,
    pub rsync: RsyncdStore,
}

/// The Old RRDP server used by a Repository instance.
///
/// Or well. Really just the few bits that we will need
/// to deserialize for migration. We do not need the content
/// as it will be regenerated based on the publishers held
/// by the OldRepositoryContent. And we will do a session
/// reset when we create the new server based on this.
///
/// The additional JSON fields are ignored when deserializing
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldRrdpServer {
    /// The base URI for notification, snapshot and delta files.
    pub rrdp_base_uri: uri::Https,

    /// The base directory where notification, snapshot and deltas will be
    /// published.
    pub rrdp_base_dir: PathBuf,
    pub rrdp_archive_dir: PathBuf,
}

/// Changes for the Old RepositoryContent.
///
/// We will need to replay any unapplied changes to the latest
/// snapshot when we migrate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum OldRepositoryContentChange {
    SessionReset {
        reset: RrdpSessionReset,
    },
    PublisherAdded {
        publisher: PublisherHandle,
    },
    PublisherRemoved {
        publisher: PublisherHandle,
    },
    PublishedObjects {
        publisher: PublisherHandle,
        current_objects: CurrentObjects,
    },
    RrdpDeltaStaged {
        delta: DeltaElements,
    },
    RrdpUpdated {
        update: RrdpUpdated,
    },
}

impl fmt::Display for OldRepositoryContentChange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl WalChange for OldRepositoryContentChange {}

impl WalSupport for OldRepositoryContent {
    // we use the current command type for convenience, but note
    // that we will never send it to this old repository content
    type Command = RepositoryContentCommand;
    type Error = Error;
    type Change = OldRepositoryContentChange;

    fn revision(&self) -> u64 {
        self.revision
    }

    fn apply(&mut self, set: crate::commons::eventsourcing::WalSet<Self>) {
        for change in set.into_changes() {
            match change {
                OldRepositoryContentChange::SessionReset { .. } => {
                    // Ignore this.. we will do a new session reset after migrating
                }
                OldRepositoryContentChange::RrdpUpdated { .. } => {
                    // Ignore.. we will do a session reset on the new content.
                }
                OldRepositoryContentChange::RrdpDeltaStaged { .. } => {
                    // Ignore.. we only need to keep the content as kept
                    // in the publishers hash.
                }
                OldRepositoryContentChange::PublisherAdded { publisher } => {
                    self.publishers.insert(publisher, CurrentObjects::default());
                }
                OldRepositoryContentChange::PublisherRemoved { publisher } => {
                    self.publishers.remove(&publisher);
                }
                OldRepositoryContentChange::PublishedObjects {
                    publisher,
                    current_objects,
                } => {
                    self.publishers.insert(publisher, current_objects);
                }
            }
        }
        self.revision += 1;
    }

    fn process_command(&self, _command: Self::Command) -> Result<Vec<Self::Change>, Self::Error> {
        unreachable!("We will not apply any new commands to the old repository")
    }
}

impl From<OldRepositoryContent> for RepositoryContent {
    fn from(old: OldRepositoryContent) -> Self {
        let rrdp = RrdpServer::migrate_old_content(
            old.rrdp.rrdp_base_uri,
            old.rrdp.rrdp_base_dir,
            old.rrdp.rrdp_archive_dir,
            old.publishers,
        );
        RepositoryContent::new(rrdp, old.rsync)
    }
}
