use std::{collections::HashMap, path::PathBuf};

use rpki::{ca::idexchange::PublisherHandle, uri};

use crate::{commons::api::rrdp::CurrentObjects, pubd::RsyncdStore};

#[derive(Clone, Debug, Deserialize)]
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
#[derive(Clone, Debug, Deserialize)]
pub struct OldRrdpServer {
    /// The base URI for notification, snapshot and delta files.
    pub rrdp_base_uri: uri::Https,

    /// The base directory where notification, snapshot and deltas will be
    /// published.
    pub rrdp_base_dir: PathBuf,
    pub rrdp_archive_dir: PathBuf,
}
