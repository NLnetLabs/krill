use std::fmt;
use std::sync::Arc;

use rpki::ca::idexchange::{MyHandle, PublisherHandle};
use rpki::uri;
use serde::{Deserialize, Serialize};

use crate::commons::crypto::KrillSigner;
use crate::commons::eventsourcing::{
    InitCommandDetails, SentInitCommand, WithStorableDetails,
};
use crate::{
    commons::{
        actor::Actor,
        eventsourcing::{CommandDetails, SentCommand},
    },
    pubd::RepositoryAccessEvent,
};
use crate::commons::api::ca::IdCertInfo;
use crate::commons::api::history::CommandSummary;


//------------ RepositoryAccessCommand -------------------------------------

pub type RepositoryAccessInitCommand =
    SentInitCommand<RepositoryAccessInitCommandDetails>;

//------------ RepositoryAccessInitCommandDetails --------------------------
#[derive(Clone, Debug)]
pub struct RepositoryAccessInitCommandDetails {
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
    signer: Arc<KrillSigner>,
}

impl RepositoryAccessInitCommandDetails {
    pub fn new(
        rrdp_base_uri: uri::Https,
        rsync_jail: uri::Rsync,
        signer: Arc<KrillSigner>,
    ) -> Self {
        RepositoryAccessInitCommandDetails {
            rrdp_base_uri,
            rsync_jail,
            signer,
        }
    }
}

impl RepositoryAccessInitCommandDetails {
    pub fn unpack(self) -> (uri::Https, uri::Rsync, Arc<KrillSigner>) {
        (self.rrdp_base_uri, self.rsync_jail, self.signer)
    }
}

impl fmt::Display for RepositoryAccessInitCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.store().fmt(f)
    }
}

impl InitCommandDetails for RepositoryAccessInitCommandDetails {
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        StorableRepositoryCommand::make_init()
    }
}

//------------ RepositoryAccessCommand -------------------------------------

pub type RepositoryAccessCommand =
    SentCommand<RepositoryAccessCommandDetails>;

//------------ RepositoryAccessCommandDetails ------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryAccessCommandDetails {
    AddPublisher {
        id_cert: IdCertInfo,
        name: PublisherHandle,
        base_uri: uri::Rsync,
    },
    RemovePublisher {
        name: PublisherHandle,
    },
}

impl CommandDetails for RepositoryAccessCommandDetails {
    type Event = RepositoryAccessEvent;
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl RepositoryAccessCommandDetails {
    pub fn add_publisher(
        handle: &MyHandle,
        id_cert: IdCertInfo,
        name: PublisherHandle,
        base_uri: uri::Rsync,
        actor: &Actor,
    ) -> RepositoryAccessCommand {
        SentCommand::new(
            handle,
            None,
            RepositoryAccessCommandDetails::AddPublisher {
                id_cert,
                name,
                base_uri,
            },
            actor,
        )
    }

    pub fn remove_publisher(
        handle: &MyHandle,
        name: PublisherHandle,
        actor: &Actor,
    ) -> RepositoryAccessCommand {
        SentCommand::new(
            handle,
            None,
            RepositoryAccessCommandDetails::RemovePublisher { name },
            actor,
        )
    }
}

impl fmt::Display for RepositoryAccessCommandDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorableRepositoryCommand::from(self.clone()).fmt(f)
    }
}

impl From<RepositoryAccessCommandDetails> for StorableRepositoryCommand {
    fn from(d: RepositoryAccessCommandDetails) -> Self {
        match d {
            RepositoryAccessCommandDetails::AddPublisher { name, .. } => {
                StorableRepositoryCommand::AddPublisher { name }
            }
            RepositoryAccessCommandDetails::RemovePublisher { name } => {
                StorableRepositoryCommand::RemovePublisher { name }
            }
        }
    }
}

//------------ StorableRepositoryCommand -----------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum StorableRepositoryCommand {
    Init,
    AddPublisher { name: PublisherHandle },
    RemovePublisher { name: PublisherHandle },
}

impl WithStorableDetails for StorableRepositoryCommand {
    fn summary(&self) -> CommandSummary {
        match self {
            StorableRepositoryCommand::Init => {
                CommandSummary::new("pubd-init", self)
            }
            StorableRepositoryCommand::AddPublisher { name } => {
                CommandSummary::new("pubd-publisher-add", self)
                    .publisher(name)
            }
            StorableRepositoryCommand::RemovePublisher { name } => {
                CommandSummary::new("pubd-publisher-remove", self)
                    .publisher(name)
            }
        }
    }

    fn make_init() -> Self {
        Self::Init
    }
}

impl fmt::Display for StorableRepositoryCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorableRepositoryCommand::Init => {
                write!(f, "Initialise server")
            }
            StorableRepositoryCommand::AddPublisher { name } => {
                write!(f, "Added publisher '{}'", name)
            }
            StorableRepositoryCommand::RemovePublisher { name } => {
                write!(f, "Removed publisher '{}'", name)
            }
        }
    }
}
