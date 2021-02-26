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
pub type Cmd = SentCommand<CmdDet>;

//------------ CmdDet ------------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CmdDet {
    AddPublisher {
        request: rfc8183::PublisherRequest,
        base_uri: uri::Rsync,
    },
    RemovePublisher {
        name: PublisherHandle,
    },
}

impl CommandDetails for CmdDet {
    type Event = PubdEvt;
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl CmdDet {
    pub fn add_publisher(
        handle: &RepositoryHandle,
        request: rfc8183::PublisherRequest,
        base_uri: uri::Rsync,
        actor: &Actor,
    ) -> Cmd {
        SentCommand::new(handle, None, CmdDet::AddPublisher { request, base_uri }, actor)
    }

    pub fn remove_publisher(handle: &RepositoryHandle, name: PublisherHandle, actor: &Actor) -> Cmd {
        SentCommand::new(handle, None, CmdDet::RemovePublisher { name }, actor)
    }
}

impl fmt::Display for CmdDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        StorableRepositoryCommand::from(self.clone()).fmt(f)
    }
}

impl From<CmdDet> for StorableRepositoryCommand {
    fn from(d: CmdDet) -> Self {
        match d {
            CmdDet::AddPublisher { request, .. } => {
                let (_, name, _) = request.unpack();
                StorableRepositoryCommand::AddPublisher { name }
            }
            CmdDet::RemovePublisher { name } => StorableRepositoryCommand::RemovePublisher { name },
        }
    }
}
