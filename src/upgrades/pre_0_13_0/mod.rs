use std::{
    collections::{HashMap, VecDeque},
    fmt,
    path::PathBuf,
};

use rpki::{ca::idexchange::PublisherHandle, repository::x509::Time, uri};

use crate::{
    commons::{
        api::rrdp::{
            CurrentObjects, DeltaData, DeltaElements, PublishElement, RrdpFileRandom, RrdpSession, UpdateElement,
            WithdrawElement,
        },
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
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OldRrdpServer {
    /// The base URI for notification, snapshot and delta files.
    pub rrdp_base_uri: uri::Https,

    /// The base directory where notification, snapshot and deltas will be
    /// published.
    pub rrdp_base_dir: PathBuf,
    pub rrdp_archive_dir: PathBuf,

    pub session: RrdpSession,
    pub serial: u64,
    #[serde(default = "Time::now")] // be backward compatible
    pub last_update: Time,

    snapshot: OldSnapshotData,
    deltas: VecDeque<DeltaData>,

    #[serde(default)]
    staged_elements: OldStagedElements,
}

impl OldRrdpServer {
    /// Applies the data from an RrdpUpdated change.
    fn apply_rrdp_updated(&mut self, update: RrdpUpdated) {
        self.serial += 1;

        let mut staged_elements = OldStagedElements::default();
        std::mem::swap(&mut self.staged_elements, &mut staged_elements);

        let mut publishes = vec![];
        let mut updates = vec![];
        let mut withdraws = vec![];
        for el in staged_elements.0.into_values() {
            match el {
                OldDeltaElement::Publish(pbl) => publishes.push(pbl),
                OldDeltaElement::Update(upd) => updates.push(upd),
                OldDeltaElement::Withdraw(wdr) => withdraws.push(wdr),
            }
        }
        let delta_elements = DeltaElements::new(publishes, updates, withdraws);

        let delta = DeltaData::new(self.serial, update.time, update.random, delta_elements);

        self.snapshot = self
            .snapshot
            .with_delta(delta.random().clone(), delta.elements().clone());

        self.deltas.truncate(update.deltas_truncate);
        self.deltas.push_front(delta);
        self.deltas_truncate_size();

        self.last_update = update.time;
    }

    /// Truncate excessive deltas based on size. This is done
    /// after applying an RrdpUpdate because the outcome is
    /// deterministic. Compared to truncating the deltas based
    /// on age and number, because *that* depends on when the
    /// update was generated, and what the RrdpUpdatesConfig
    /// was set to at the time.
    fn deltas_truncate_size(&mut self) {
        let snapshot_size = self.snapshot.size();
        let mut total_deltas_size = 0;
        let mut keep = 0;

        for delta in &self.deltas {
            total_deltas_size += delta.elements().size_approx();
            if total_deltas_size > snapshot_size {
                // never keep more than the size of the snapshot
                break;
            } else {
                keep += 1;
            }
        }

        self.deltas.truncate(keep);
    }

    /// Applies staged DeltaElements
    fn apply_rrdp_staged(&mut self, elements: DeltaElements) {
        let (publishes, updates, withdraws) = elements.unpack();
        for pbl in publishes {
            let uri = pbl.uri().clone();
            // A publish that follows a withdraw for the same URI should be Update.
            if let Some(OldDeltaElement::Withdraw(staged_withdraw)) = self.staged_elements.0.get(&uri) {
                let hash = *staged_withdraw.hash();
                let update = UpdateElement::new(uri.clone(), hash, pbl.base64().clone());
                self.staged_elements.0.insert(uri, OldDeltaElement::Update(update));
            } else {
                // In any other case we just keep the new publish.
                // Because deltas are checked before they are applied we know that publish
                // elements cannot occur after another publish or update. They would have
                // had to be an update in that case.
                // Because this is checked when the publication delta is submitted, we can
                // ignore this case here.
                self.staged_elements.0.insert(uri, OldDeltaElement::Publish(pbl));
            };
        }

        for mut upd in updates {
            let uri = upd.uri().clone();
            // An update that follows a staged publish, should be fresh publish.
            // An update that follows a staged update, should use the hash from the previous update.
            // An update cannot follow a staged withdraw. It would have been a publish in that case.
            if let Some(OldDeltaElement::Publish(_)) = self.staged_elements.0.get(&uri) {
                self.staged_elements
                    .0
                    .insert(uri, OldDeltaElement::Publish(upd.into_publish()));
            } else if let Some(OldDeltaElement::Update(staged_update)) = self.staged_elements.0.get(&uri) {
                upd.with_updated_hash(*staged_update.hash()); // set hash to previous update hash
                self.staged_elements.0.insert(uri, OldDeltaElement::Update(upd));
            } else {
                self.staged_elements.0.insert(uri, OldDeltaElement::Update(upd));
            }
        }

        for wdr in withdraws {
            // withdraws should always remove any staged publishes or updates.
            // they cannot follow staged withdraws (checked when delta is submitted)
            // so just add them all to the staged elements
            self.staged_elements
                .0
                .insert(wdr.uri().clone(), OldDeltaElement::Withdraw(wdr));
        }
    }
}

/// This type is used to combine staged delta elements for publishers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldStagedElements(HashMap<uri::Rsync, OldDeltaElement>);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OldDeltaElement {
    Publish(PublishElement),
    Update(UpdateElement),
    Withdraw(WithdrawElement),
}

/// A structure to contain the data needed to create an RRDP Snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldSnapshotData {
    // The random value will be used to make the snapshot URI unguessable and
    // prevent cache poisoning (through CDN cached 404 not founds).
    //
    // Old versions of Krill did not have this. We can just use a default (new)
    // random value in these cases.
    #[serde(default)]
    random: RrdpFileRandom,

    current_objects: CurrentObjects,
}

impl OldSnapshotData {
    /// Creates a new snapshot with the delta applied. This assumes
    /// that the delta had been checked before. This should not be
    /// any issue as deltas are verified when they are submitted.
    fn with_delta(&self, random: RrdpFileRandom, elements: DeltaElements) -> OldSnapshotData {
        let mut current_objects = self.current_objects.clone();
        current_objects.apply_delta(elements);

        OldSnapshotData {
            random,
            current_objects,
        }
    }

    fn size(&self) -> usize {
        self.current_objects
            .elements()
            .iter()
            .fold(0, |sum, p| sum + p.size_approx())
    }
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
                OldRepositoryContentChange::RrdpUpdated { update } => self.rrdp.apply_rrdp_updated(update),
                OldRepositoryContentChange::RrdpDeltaStaged { delta } => self.rrdp.apply_rrdp_staged(delta),
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
