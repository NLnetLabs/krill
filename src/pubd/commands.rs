use std::fmt;

use crate::commons::{actor::Actor, api::{PublishDelta, PublisherHandle, RepositoryHandle, StorableRepositoryCommand}};
use crate::commons::eventsourcing::CommandDetails;
use crate::commons::eventsourcing::SentCommand;
use crate::commons::remote::rfc8183;
use crate::pubd::Evt;

//------------ Cmd ---------------------------------------------------------
pub type Cmd = SentCommand<CmdDet>;

//------------ CmdDet ------------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum CmdDet {
    AddPublisher(rfc8183::PublisherRequest),
    RemovePublisher(PublisherHandle),
    Publish(PublisherHandle, PublishDelta),
    SessionReset,
}

impl CommandDetails for CmdDet {
    type Event = Evt;
    type StorableDetails = StorableRepositoryCommand;

    fn store(&self) -> Self::StorableDetails {
        self.clone().into()
    }
}

impl CmdDet {
    pub fn add_publisher(handle: &RepositoryHandle, request: rfc8183::PublisherRequest, actor: &Actor) -> Cmd {
        SentCommand::new(handle, None, CmdDet::AddPublisher(request), actor)
    }

    pub fn remove_publisher(handle: &RepositoryHandle, publisher: PublisherHandle, actor: &Actor) -> Cmd {
        SentCommand::new(handle, None, CmdDet::RemovePublisher(publisher), actor)
    }

    pub fn publish(handle: &RepositoryHandle, publisher: PublisherHandle, delta: PublishDelta, actor: &Actor) -> Cmd {
        SentCommand::new(handle, None, CmdDet::Publish(publisher, delta), actor)
    }

    pub fn session_reset(handle: &RepositoryHandle, actor: &Actor) -> Cmd {
        SentCommand::new(handle, None, CmdDet::SessionReset, actor)
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
            CmdDet::AddPublisher(req) => {
                let (_, pbl, id) = req.unpack();
                StorableRepositoryCommand::AddPublisher(pbl, id.ski_hex())
            }
            CmdDet::RemovePublisher(pbl) => StorableRepositoryCommand::RemovePublisher(pbl),
            CmdDet::Publish(pbl, delta) => StorableRepositoryCommand::Publish(
                pbl,
                delta.publishes().len(),
                delta.updates().len(),
                delta.withdraws().len(),
            ),
            CmdDet::SessionReset => StorableRepositoryCommand::SessionReset,
        }
    }
}
