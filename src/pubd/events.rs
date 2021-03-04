use std::fmt;

use rpki::uri;
use rpki::x509::Time;

use crate::commons::api::rrdp::{Delta, DeltaElements, Notification, Snapshot};
use crate::commons::api::{Handle, PublisherHandle};
use crate::commons::crypto::{IdCert, IdCertBuilder, KrillSigner};
use crate::commons::error::Error;
use crate::commons::eventsourcing::StoredEvent;
use crate::commons::KrillResult;
use crate::pubd::Publisher;

//------------ Ini -----------------------------------------------------------

pub type PubdIni = StoredEvent<PubdIniDet>;

//------------ IniDet --------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PubdIniDet {
    id_cert: IdCert,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl PubdIniDet {
    pub fn new(id_cert: IdCert, rrdp_base_uri: uri::Https, rsync_jail: uri::Rsync) -> Self {
        PubdIniDet {
            id_cert,
            rrdp_base_uri,
            rsync_jail,
        }
    }

    pub fn unpack(self) -> (IdCert, uri::Https, uri::Rsync) {
        (self.id_cert, self.rrdp_base_uri, self.rsync_jail)
    }
}

impl PubdIniDet {
    pub fn init(
        handle: &Handle,
        rsync_jail: uri::Rsync,
        rrdp_base_uri: uri::Https,
        signer: &KrillSigner,
    ) -> KrillResult<PubdIni> {
        let key = signer.create_key()?;

        let id_cert = IdCertBuilder::new_ta_id_cert(&key, signer).map_err(Error::signer)?;

        Ok(StoredEvent::new(
            handle,
            0,
            PubdIniDet {
                id_cert,
                rrdp_base_uri,
                rsync_jail,
            },
        ))
    }
}

impl fmt::Display for PubdIniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialised publication server. RRDP base uri: {}, Rsync Jail: {}",
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

//------------ EvtDet --------------------------------------------------------

pub type PubdEvt = StoredEvent<RepoAccessEvtDet>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RepoAccessEvtDet {
    PublisherAdded {
        name: PublisherHandle,
        publisher: Publisher,
    },
    PublisherRemoved {
        name: PublisherHandle,
    },
}

impl fmt::Display for RepoAccessEvtDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RepoAccessEvtDet::PublisherAdded { name, .. } => write!(f, "Publisher '{}' added", name),
            RepoAccessEvtDet::PublisherRemoved { name } => write!(f, "Publisher '{}' removed", name),
        }
    }
}

impl RepoAccessEvtDet {
    pub(super) fn publisher_added(
        handle: &Handle,
        version: u64,
        name: PublisherHandle,
        publisher: Publisher,
    ) -> PubdEvt {
        StoredEvent::new(handle, version, RepoAccessEvtDet::PublisherAdded { name, publisher })
    }

    pub(super) fn publisher_removed(handle: &Handle, version: u64, name: PublisherHandle) -> PubdEvt {
        StoredEvent::new(handle, version, RepoAccessEvtDet::PublisherRemoved { name })
    }
}
