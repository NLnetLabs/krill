use std::fmt;
use serde::{Deserialize, Serialize};
use rpki::uri;
use rpki::ca::idcert::IdCert;
use rpki::ca::idexchange::PublisherHandle;
use crate::daemon::pubd::access::{
    RepositoryAccessEvent, RepositoryAccessInitEvent
};
use crate::daemon::pubd::publishers::Publisher;

//------------ Pre0_10RepositoryAccessInitDetails ---------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Pre0_10RepositoryAccessInitDetails {
    id_cert: IdCert,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
}

impl From<Pre0_10RepositoryAccessInitDetails> for RepositoryAccessInitEvent {
    fn from(old: Pre0_10RepositoryAccessInitDetails) -> Self {
        RepositoryAccessInitEvent {
            id_cert: old.id_cert.into(),
            rrdp_base_uri: old.rrdp_base_uri,
            rsync_jail: old.rsync_jail,
        }
    }
}

impl fmt::Display for Pre0_10RepositoryAccessInitDetails {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Initialized publication server. RRDP base uri: {}, \
             Rsync Jail: {}",
            self.rrdp_base_uri, self.rsync_jail
        )
    }
}

//------------ Pre0_10RepositoryAccessEventDetails ---------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Pre0_10RepositoryAccessEventDetails {
    PublisherAdded {
        name: PublisherHandle,
        publisher: OldPublisher,
    },
    PublisherRemoved {
        name: PublisherHandle,
    },
}

impl From<Pre0_10RepositoryAccessEventDetails> for RepositoryAccessEvent {
    fn from(old: Pre0_10RepositoryAccessEventDetails) -> Self {
        match old {
            Pre0_10RepositoryAccessEventDetails::PublisherAdded {
                name,
                publisher,
            } => RepositoryAccessEvent::PublisherAdded {
                name,
                publisher: publisher.into(),
            },
            Pre0_10RepositoryAccessEventDetails::PublisherRemoved {
                name,
            } => RepositoryAccessEvent::PublisherRemoved { name },
        }
    }
}

impl fmt::Display for Pre0_10RepositoryAccessEventDetails {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!("not used for migration")
    }
}

//------------ OldPublisher --------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OldPublisher {
    /// Used by remote RFC8181 publishers
    id_cert: IdCert,

    /// Publication jail for this publisher
    base_uri: uri::Rsync,
}

impl From<OldPublisher> for Publisher {
    fn from(old: OldPublisher) -> Self {
        Publisher::new(old.id_cert.into(), old.base_uri)
    }
}

