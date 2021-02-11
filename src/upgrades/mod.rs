//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::{fmt, io};
use std::{path::PathBuf, sync::Arc};

use crate::commons::eventsourcing::{
    AggregateStore, AggregateStoreError, KeyStoreKey, KeyStoreVersion, KeyValueError, KeyValueStore,
};
use crate::commons::util::file;
use crate::constants::KRILL_VERSION;
use crate::daemon::ca::CertAuth;
use crate::pubd::Repository;
use crate::{commons::api::Handle, daemon::config::Config};

use self::v0_9_0::CaObjectsMigration;

pub mod v0_9_0;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

//------------ UpgradeError --------------------------------------------------

#[derive(Debug)]
pub enum UpgradeError {
    AggregateStoreError(AggregateStoreError),
    KeyStoreError(KeyValueError),
    IoError(io::Error),
    Unrecognised(String),
    CannotLoadAggregate(Handle),
    KrillError(crate::commons::error::Error),
    Custom(String),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UpgradeError::AggregateStoreError(e) => e.fmt(f),
            UpgradeError::KeyStoreError(e) => e.fmt(f),
            UpgradeError::IoError(e) => e.fmt(f),
            UpgradeError::Unrecognised(s) => write!(f, "Unrecognised command summary: {}", s),
            UpgradeError::CannotLoadAggregate(handle) => write!(f, "Cannot load: {}", handle),
            UpgradeError::KrillError(e) => e.fmt(f),
            UpgradeError::Custom(s) => s.fmt(f),
        }
    }
}
impl UpgradeError {
    pub fn custom(msg: impl fmt::Display) -> Self {
        UpgradeError::Custom(msg.to_string())
    }

    pub fn unrecognised(msg: impl fmt::Display) -> Self {
        UpgradeError::Unrecognised(msg.to_string())
    }
}

impl From<AggregateStoreError> for UpgradeError {
    fn from(e: AggregateStoreError) -> Self {
        UpgradeError::AggregateStoreError(e)
    }
}

impl From<KeyValueError> for UpgradeError {
    fn from(e: KeyValueError) -> Self {
        UpgradeError::KeyStoreError(e)
    }
}

impl From<file::Error> for UpgradeError {
    fn from(e: file::Error) -> Self {
        UpgradeError::IoError(e.into())
    }
}

impl From<io::Error> for UpgradeError {
    fn from(e: io::Error) -> Self {
        UpgradeError::IoError(e)
    }
}

impl From<crate::commons::error::Error> for UpgradeError {
    fn from(e: crate::commons::error::Error) -> Self {
        UpgradeError::KrillError(e)
    }
}

impl std::error::Error for UpgradeError {}

//------------ UpgradeStore --------------------------------------------------

/// Implement this for automatic upgrades to key stores
pub trait UpgradeStore {
    fn needs_migrate(&self) -> Result<bool, UpgradeError>;
    fn migrate(&self) -> Result<(), UpgradeError>;

    fn version_same_or_before(kv: &KeyValueStore, up_to: KeyStoreVersion) -> Result<bool, UpgradeError> {
        let key = KeyStoreKey::simple("version".to_string());
        match kv.get::<KeyStoreVersion>(&key) {
            Err(e) => Err(UpgradeError::KeyStoreError(e)),
            Ok(None) => Ok(true),
            Ok(Some(current_version)) => Ok(current_version <= up_to),
        }
    }
}

/// Should be called when Krill starts, before the KrillServer is initiated
pub fn pre_start_upgrade(config: Arc<Config>) -> Result<(), UpgradeError> {
    upgrade_0_9_0(config)
}

pub async fn update_storage_version(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    let current = KeyStoreVersion::current();

    let mut ca_dir = work_dir.clone();
    ca_dir.push("cas");
    if ca_dir.exists() {
        let ca_store: AggregateStore<CertAuth> = AggregateStore::new(work_dir, "cas")?;
        if ca_store.get_version()? != current {
            ca_store.set_version(&current)?;
        }
    }

    let mut pubd_dir = work_dir.clone();
    pubd_dir.push("pubd");
    if pubd_dir.exists() {
        let pubd_store: AggregateStore<Repository> = AggregateStore::new(work_dir, "pubd")?;
        if pubd_store.get_version()? != current {
            pubd_store.set_version(&current)?;
        }
    }

    info!("Upgraded Krill to version: {}", KRILL_VERSION);
    Ok(())
}

fn upgrade_0_9_0(config: Arc<Config>) -> Result<(), UpgradeError> {
    let mut cas_dir = config.data_dir.clone();
    cas_dir.push("cas");
    if cas_dir.exists() {
        CaObjectsMigration::migrate(config)
    } else {
        Ok(())
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::commons::util::file;
    use crate::test::tmp_dir;

    use super::*;

    #[test]
    fn ca_objects_for_existing_ca() {
        let d = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_9_0/cas/");

        let mut work_dir_cas = d.clone();
        work_dir_cas.push("cas");

        let config = Arc::new(Config::test(&d));

        file::backup_dir(&source, &work_dir_cas).unwrap();

        upgrade_0_9_0(config).unwrap();

        let _ = fs::remove_dir_all(d);
    }
}
