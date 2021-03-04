use std::fmt;

use rpki::uri;

use crate::{
    commons::{
        actor::Actor,
        api::{PublisherHandle, RepositoryHandle, StorableRepositoryCommand},
        eventsourcing::{CommandDetails, SentCommand},
        remote::rfc8183,
    },
    pubd::PubdEvt,
};

//------------ Cmd ---------------------------------------------------------
pub type RepoAccessCmd = SentCommand<RepoAccessCmdDet>;

//------------ CmdDet ------------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepoAccessCmdDet {
    AddPublisher {
        request: rfc8183::PublisherRequest,
        base_uri: uri::Rsync,
    },
    RemovePublisher {
        name: PublisherHandle,
    },
}

impl CommandDetails for RepoAccessCmdDet {
    type Event = PubdEvt;
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl RepoAccessCmdDet {
    pub fn add_publisher(
        handle: &RepositoryHandle,
        request: rfc8183::PublisherRequest,
        base_uri: uri::Rsync,
        actor: &Actor,
    ) -> RepoAccessCmd {
        SentCommand::new(
            handle,
            None,
            RepoAccessCmdDet::AddPublisher { request, base_uri },
            actor,
        )
    }

    pub fn remove_publisher(handle: &RepositoryHandle, name: PublisherHandle, actor: &Actor) -> RepoAccessCmd {
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
            RepoAccessCmdDet::AddPublisher { request, .. } => {
                let (_, name, _) = request.unpack();
                StorableRepositoryCommand::AddPublisher { name }
            }
            RepoAccessCmdDet::RemovePublisher { name } => StorableRepositoryCommand::RemovePublisher { name },
        }
    }
}
