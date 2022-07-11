use std::fmt;

use rpki::uri;

use rpki::ca::idexchange::{MyHandle, PublisherHandle};

use crate::commons::api::IdCertInfo;
use crate::{
    commons::{
        actor::Actor,
        api::StorableRepositoryCommand,
        eventsourcing::{CommandDetails, SentCommand},
    },
    pubd::RepositoryAccessEvent,
};

//------------ Cmd ---------------------------------------------------------
pub type RepoAccessCmd = SentCommand<RepoAccessCmdDet>;

//------------ CmdDet ------------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepoAccessCmdDet {
    AddPublisher {
        id_cert: IdCertInfo,
        name: PublisherHandle,
        base_uri: uri::Rsync,
    },
    RemovePublisher {
        name: PublisherHandle,
    },
}

impl CommandDetails for RepoAccessCmdDet {
    type Event = RepositoryAccessEvent;
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl RepoAccessCmdDet {
    pub fn add_publisher(
        handle: &MyHandle,
        id_cert: IdCertInfo,
        name: PublisherHandle,
        base_uri: uri::Rsync,
        actor: &Actor,
    ) -> RepoAccessCmd {
        SentCommand::new(
            handle,
            None,
            RepoAccessCmdDet::AddPublisher {
                id_cert,
                name,
                base_uri,
            },
            actor,
        )
    }

    pub fn remove_publisher(handle: &MyHandle, name: PublisherHandle, actor: &Actor) -> RepoAccessCmd {
        SentCommand::new(handle, None, RepoAccessCmdDet::RemovePublisher { name }, actor)
    }
}

impl fmt::Display for RepoAccessCmdDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorableRepositoryCommand::from(self.clone()).fmt(f)
    }
}

impl From<RepoAccessCmdDet> for StorableRepositoryCommand {
    fn from(d: RepoAccessCmdDet) -> Self {
        match d {
            RepoAccessCmdDet::AddPublisher { name, .. } => StorableRepositoryCommand::AddPublisher { name },
            RepoAccessCmdDet::RemovePublisher { name } => StorableRepositoryCommand::RemovePublisher { name },
        }
    }
}
