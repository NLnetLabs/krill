use std::path::PathBuf;
use std::{fmt, fs};

use rpki::crypto::PublicKeyFormat;
use rpki::uri;

use crate::commons::api::rrdp::{Delta, DeltaElements, Notification, RrdpSession};
use crate::commons::api::{Handle, PublisherHandle, RepositoryHandle};
use crate::commons::eventsourcing::StoredEvent;
use crate::commons::remote::builder::IdCertBuilder;
use crate::commons::remote::id::IdCert;
use crate::constants::REPOSITORY_DIR;
use crate::daemon::ca::Signer;
use crate::pubd::{Error, Publisher};

//------------ Ini -----------------------------------------------------------
pub type Ini = StoredEvent<IniDet>;

//------------ IniDet --------------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IniDet {
    id_cert: IdCert,
    session: RrdpSession,
    rrdp_base_uri: uri::Https,
    rsync_jail: uri::Rsync,
    repo_base_dir: PathBuf,
}

impl IniDet {
    pub fn unpack(self) -> (IdCert, RrdpSession, uri::Https, uri::Rsync, PathBuf) {
        (
            self.id_cert,
            self.session,
            self.rrdp_base_uri,
            self.rsync_jail,
            self.repo_base_dir,
        )
    }
}

impl IniDet {
    pub fn init<S: Signer>(
        handle: &Handle,
        rsync_jail: uri::Rsync,
        rrdp_base_uri: uri::Https,
        work_dir: &PathBuf,
        signer: &mut S,
    ) -> Result<Ini, Error> {
        let key = signer
            .create_key(PublicKeyFormat::default())
            .map_err(Error::signer)?;

        let id_cert = IdCertBuilder::new_ta_id_cert(&key, signer).map_err(Error::signer)?;
        let session = RrdpSession::new();

        let mut repo_base_dir = work_dir.clone();
        repo_base_dir.push(REPOSITORY_DIR);

        if !repo_base_dir.is_dir() {
            fs::create_dir_all(&repo_base_dir)?;
        }

        Ok(StoredEvent::new(
            handle,
            0,
            IniDet {
                id_cert,
                session,
                rrdp_base_uri,
                rsync_jail,
                repo_base_dir,
            },
        ))
    }
}

impl fmt::Display for IniDet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Initialised publication server with cert(hash): {}, session: {}, RRDP base uri: {}, repo dir: {}",
            self.id_cert.ski_hex(), self.session, self.rrdp_base_uri, self.repo_base_dir.to_string_lossy().as_ref()
        )
    }
}

//------------ Event ---------------------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RrdpUpdate {
    delta: Delta,
    notification: Notification,
}

impl RrdpUpdate {
    pub fn new(delta: Delta, notification: Notification) -> Self {
        RrdpUpdate {
            delta,
            notification,
        }
    }

    pub fn unpack(self) -> (Delta, Notification) {
        (self.delta, self.notification)
    }

    pub fn elements(&self) -> &DeltaElements {
        self.delta.elements()
    }
}

//------------ Event ---------------------------------------------------------
pub type Evt = StoredEvent<EvtDet>;

#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
pub enum EvtDet {
    // Publisher related events
    #[display(fmt = "Publisher with handle '{}' added", _0)]
    PublisherAdded(PublisherHandle, Publisher),

    #[display(fmt = "Publisher with handle '{}', and its contents, removed", _0)]
    PublisherRemoved(PublisherHandle, RrdpUpdate),

    // RRDP publication events
    #[display(fmt = "Publisher with handle '{}' published", _0)]
    Published(PublisherHandle, RrdpUpdate),
}

impl EvtDet {
    pub(super) fn publisher_added(
        handle: &Handle,
        version: u64,
        publisher_handle: PublisherHandle,
        publisher: Publisher,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::PublisherAdded(publisher_handle, publisher),
        )
    }

    pub(super) fn publisher_removed(
        handle: &Handle,
        version: u64,
        publisher_handle: PublisherHandle,
        update: RrdpUpdate,
    ) -> Evt {
        StoredEvent::new(
            handle,
            version,
            EvtDet::PublisherRemoved(publisher_handle, update),
        )
    }

    pub(super) fn published(
        repository: &RepositoryHandle,
        version: u64,
        publisher: PublisherHandle,
        update: RrdpUpdate,
    ) -> Evt {
        StoredEvent::new(repository, version, EvtDet::Published(publisher, update))
    }
}
