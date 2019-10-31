use std::fmt;

use crate::commons::api::PublishDelta;
use crate::commons::api::PublisherHandle;
use crate::commons::api::{PublisherRequest, RepositoryHandle};
use crate::commons::eventsourcing::CommandDetails;
use crate::commons::eventsourcing::SentCommand;
use crate::pubd::Evt;

//------------ Cmd ---------------------------------------------------------
pub type Cmd = SentCommand<CmdDet>;

//------------ CmdDet ------------------------------------------------------
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CmdDet {
    AddPublisher(PublisherRequest),
    RemovePublisher(PublisherHandle),
    Publish(PublisherHandle, PublishDelta),
}

impl CommandDetails for CmdDet {
    type Event = Evt;
}

impl CmdDet {
    pub fn add_publisher(handle: &RepositoryHandle, request: PublisherRequest) -> Cmd {
        SentCommand::new(handle, None, CmdDet::AddPublisher(request))
    }

    pub fn remove_publisher(handle: &RepositoryHandle, publisher: PublisherHandle) -> Cmd {
        SentCommand::new(handle, None, CmdDet::RemovePublisher(publisher))
    }

    pub fn publish(
        handle: &RepositoryHandle,
        publisher: PublisherHandle,
        delta: PublishDelta,
    ) -> Cmd {
        SentCommand::new(handle, None, CmdDet::Publish(publisher, delta))
    }
}

impl fmt::Display for CmdDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CmdDet::AddPublisher(request) => write!(
                f,
                "Added publisher '{}' with id cert hash '{}'",
                request.handle(),
                request.id_cert().ski_hex(),
            ),
            CmdDet::RemovePublisher(publisher) => {
                write!(f, "Remove publisher '{}' and all its objects", publisher)
            }
            CmdDet::Publish(handle, delta) => write!(
                f,
                "Publish for '{}': {} new, {} updated, {} withdrawn objects",
                handle,
                delta.publishes().len(),
                delta.updates().len(),
                delta.withdraws().len()
            ),
        }
    }
}
