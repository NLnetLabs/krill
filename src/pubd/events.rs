use std::fmt;

use rpki::{
    ca::idexchange::{MyHandle, PublisherHandle},
    repository::x509::Time,
    uri,
};

use crate::{
    commons::{
        api::rrdp::{Delta, DeltaElements, Notification, Snapshot},
        api::IdCertInfo,
        crypto::KrillSigner,
        eventsourcing::StoredEvent,
        KrillResult,
    },
    pubd::Publisher,
};

//------------ RepositoryAccessIni -------------------------------------------

pub type RepositoryAccessIni = StoredEvent<RepositoryAccessInitDetails>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryAccessInitDetails {
    id_cert: IdCertInfo,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl RepositoryAccessInitDetails {
    pub fn new(id_cert: IdCertInfo, rrdp_base_uri: uri::Https, rsync_jail: uri::Rsync) -> Self {
        RepositoryAccessInitDetails {
            id_cert,
            rrdp_base_uri,
            rsync_jail,
        }
    }

    pub fn unpack(self) -> (IdCertInfo, uri::Https, uri::Rsync) {
        (self.id_cert, self.rrdp_base_uri, self.rsync_jail)
    }
}

impl RepositoryAccessInitDetails {
    pub fn init(
        handle: &MyHandle,
        rsync_jail: uri::Rsync,
        rrdp_base_uri: uri::Https,
        signer: &KrillSigner,
    ) -> KrillResult<RepositoryAccessIni> {
        let id_cert = signer.create_self_signed_id_cert()?.into();

        Ok(StoredEvent::new(
            handle,
            0,
            RepositoryAccessInitDetails {
                id_cert,
                rrdp_base_uri,
                rsync_jail,
            },
        ))
    }
}

impl fmt::Display for RepositoryAccessInitDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialized publication server. RRDP base uri: {}, Rsync Jail: {}",
            self.rrdp_base_uri, self.rsync_jail
        )
    }
}

//------------ RrdpUpdate ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpUpdate {
    delta: Delta,
    notification: Notification,
}

impl RrdpUpdate {
    pub fn new(delta: Delta, notification: Notification) -> Self {
        RrdpUpdate { delta, notification }
    }

    pub fn time(&self) -> Time {
        self.notification.time()
    }

    pub fn unpack(self) -> (Delta, Notification) {
        (self.delta, self.notification)
    }

    pub fn elements(&self) -> &DeltaElements {
        self.delta.elements()
    }
}

//------------ RrdpSessionReset ----------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpSessionReset {
    snapshot: Snapshot,
    notification: Notification,
}

impl RrdpSessionReset {
    pub fn new(snapshot: Snapshot, notification: Notification) -> Self {
        RrdpSessionReset { snapshot, notification }
    }

    pub fn time(&self) -> Time {
        self.notification.time()
    }

    pub fn notification(&self) -> &Notification {
        &self.notification
    }

    pub fn unpack(self) -> (Snapshot, Notification) {
        (self.snapshot, self.notification)
    }
}

//------------ RepositoryAccessEvent -----------------------------------------

pub type RepositoryAccessEvent = StoredEvent<RepositoryAccessEventDetails>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepositoryAccessEventDetails {
    PublisherAdded {
        name: PublisherHandle,
        publisher: Publisher,
    },
    PublisherRemoved {
        name: PublisherHandle,
    },
}

impl fmt::Display for RepositoryAccessEventDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepositoryAccessEventDetails::PublisherAdded { name, .. } => write!(f, "Publisher '{}' added", name),
            RepositoryAccessEventDetails::PublisherRemoved { name } => write!(f, "Publisher '{}' removed", name),
        }
    }
}

impl RepositoryAccessEventDetails {
    pub(super) fn publisher_added(
        me: &MyHandle,
        version: u64,
        name: PublisherHandle,
        publisher: Publisher,
    ) -> RepositoryAccessEvent {
        StoredEvent::new(
            me,
            version,
            RepositoryAccessEventDetails::PublisherAdded { name, publisher },
        )
    }

    pub(super) fn publisher_removed(me: &MyHandle, version: u64, name: PublisherHandle) -> RepositoryAccessEvent {
        StoredEvent::new(me, version, RepositoryAccessEventDetails::PublisherRemoved { name })
    }
}
