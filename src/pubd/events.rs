use std::fmt;

use rpki::{ca::idexchange::PublisherHandle, uri};

use crate::{
    commons::{
        api::IdCertInfo,
        crypto::KrillSigner,
        error::Error,
        eventsourcing::{Event, InitEvent},
        KrillResult,
    },
    pubd::Publisher,
};

//------------ RepositoryAccessInitEvent -------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryAccessInitEvent {
    id_cert: IdCertInfo,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl InitEvent for RepositoryAccessInitEvent {}

impl RepositoryAccessInitEvent {
    pub fn new(
        id_cert: IdCertInfo,
        rrdp_base_uri: uri::Https,
        rsync_jail: uri::Rsync,
    ) -> Self {
        RepositoryAccessInitEvent {
            id_cert,
            rrdp_base_uri,
            rsync_jail,
        }
    }

    pub fn unpack(self) -> (IdCertInfo, uri::Https, uri::Rsync) {
        (self.id_cert, self.rrdp_base_uri, self.rsync_jail)
    }
}

impl RepositoryAccessInitEvent {
    pub fn init(
        rsync_jail: uri::Rsync,
        rrdp_base_uri: uri::Https,
        signer: &KrillSigner,
    ) -> KrillResult<RepositoryAccessInitEvent> {
        signer
            .create_self_signed_id_cert()
            .map_err(Error::signer)
            .map(|id| RepositoryAccessInitEvent {
                id_cert: id.into(),
                rrdp_base_uri,
                rsync_jail,
            })
    }
}

impl fmt::Display for RepositoryAccessInitEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized publication server. RRDP base uri: {}, Rsync Jail: {}",
            self.rrdp_base_uri, self.rsync_jail
        )
    }
}

//------------ RepositoryAccessEvent -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryAccessEvent {
    PublisherAdded {
        name: PublisherHandle,
        publisher: Publisher,
    },
    PublisherRemoved {
        name: PublisherHandle,
    },
}

impl Event for RepositoryAccessEvent {}

impl fmt::Display for RepositoryAccessEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryAccessEvent::PublisherAdded { name, .. } => {
                write!(f, "Publisher '{}' added", name)
            }
            RepositoryAccessEvent::PublisherRemoved { name } => {
                write!(f, "Publisher '{}' removed", name)
            }
        }
    }
}

impl RepositoryAccessEvent {
    pub(super) fn publisher_added(
        name: PublisherHandle,
        publisher: Publisher,
    ) -> RepositoryAccessEvent {
        RepositoryAccessEvent::PublisherAdded { name, publisher }
    }

    pub(super) fn publisher_removed(
        name: PublisherHandle,
    ) -> RepositoryAccessEvent {
        RepositoryAccessEvent::PublisherRemoved { name }
    }
}
