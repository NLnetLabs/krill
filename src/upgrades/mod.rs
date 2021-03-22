//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::{fmt, io, str::FromStr};
use std::{path::PathBuf, sync::Arc};

use serde::de::DeserializeOwned;

use crate::commons::util::file;
use crate::constants::KRILL_VERSION;
use crate::daemon::ca::CertAuth;
use crate::pubd::RepositoryAccess;
use crate::{commons::api::Handle, daemon::config::Config};
use crate::{
    commons::{
        crypto::KrillSigner,
        eventsourcing::{
            AggregateStore, AggregateStoreError, CommandKey, KeyStoreKey, KeyStoreVersion, KeyValueError, KeyValueStore,
        },
    },
    pubd::RepositoryManager,
};

use self::v0_9_0::{CaObjectsMigration, PubdObjectsMigration};

pub mod v0_9_0;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

pub const MIGRATION_SCOPE: &str = "migration";

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

    fn version_before(kv: &KeyValueStore, before: KeyStoreVersion) -> Result<bool, UpgradeError> {
        let key = KeyStoreKey::simple("version".to_string());
        match kv.get::<KeyStoreVersion>(&key) {
            Err(e) => Err(UpgradeError::KeyStoreError(e)),
            Ok(None) => Ok(true),
            Ok(Some(current_version)) => Ok(current_version < before),
        }
    }

    fn store(&self) -> &KeyValueStore;

    // Find all command keys and sort them by sequence.
    // Then turn them back into key store keys for further processing.
    fn command_keys(&self, scope: &str) -> Result<Vec<KeyStoreKey>, UpgradeError> {
        let store = self.store();
        let keys = store.keys(Some(scope.to_string()), "command--")?;
        let mut cmd_keys: Vec<CommandKey> = vec![];
        for key in keys {
            let cmd_key = CommandKey::from_str(key.name()).map_err(|_| {
                UpgradeError::Custom(format!("Found invalid command key: {} for ca: {}", key.name(), scope))
            })?;
            cmd_keys.push(cmd_key);
        }
        cmd_keys.sort_by_key(|k| k.sequence);
        let cmd_keys = cmd_keys
            .into_iter()
            .map(|ck| KeyStoreKey::scoped(scope.to_string(), format!("{}.json", ck)))
            .collect();

        Ok(cmd_keys)
    }

    fn get<V: DeserializeOwned>(&self, key: &KeyStoreKey) -> Result<V, UpgradeError> {
        self.store()
            .get(key)?
            .ok_or_else(|| UpgradeError::Custom(format!("Cannot read key: {}", key)))
    }

    fn event_key(scope: &str, nr: u64) -> KeyStoreKey {
        KeyStoreKey::scoped(scope.to_string(), format!("delta-{}.json", nr))
    }

    fn archive_snapshots(&self, scope: &str) -> Result<(), UpgradeError> {
        let snapshot_key = KeyStoreKey::scoped(scope.to_string(), "snapshot.json".to_string());
        let snapshot_bk_key = KeyStoreKey::scoped(scope.to_string(), "snapshot-bk.json".to_string());

        if self.store().has(&snapshot_key)? {
            self.archive_to_migration_scope(&snapshot_key)?;
        }

        if self.store().has(&snapshot_bk_key)? {
            self.archive_to_migration_scope(&snapshot_bk_key)?;
        }

        Ok(())
    }

    fn archive_to_migration_scope(&self, key: &KeyStoreKey) -> Result<(), UpgradeError> {
        self.store()
            .archive_to(&key, MIGRATION_SCOPE)
            .map_err(UpgradeError::KeyStoreError)
    }

    fn drop_migration_scope(&self, scope: &str) -> Result<(), UpgradeError> {
        let scope = format!("{}/{}", scope, MIGRATION_SCOPE);
        self.store().drop_scope(&scope).map_err(UpgradeError::KeyStoreError)
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
        let ca_store: AggregateStore<CertAuth> = AggregateStore::disk(work_dir, "cas")?;
        if ca_store.get_version()? != current {
            ca_store.set_version(&current)?;
        }
    }

    let mut pubd_dir = work_dir.clone();
    pubd_dir.push("pubd");
    if pubd_dir.exists() {
        let pubd_store: AggregateStore<RepositoryAccess> = AggregateStore::disk(work_dir, "pubd")?;
        if pubd_store.get_version()? != current {
            pubd_store.set_version(&current)?;
        }
    }

    info!("Upgraded Krill to version: {}", KRILL_VERSION);
    Ok(())
}

fn upgrade_0_9_0(config: Arc<Config>) -> Result<(), UpgradeError> {
    let mut pubd_dir = config.data_dir.clone();
    let mut repo_manager = None;
    pubd_dir.push("pubd");
    if pubd_dir.exists() {
        PubdObjectsMigration::migrate(config.clone())?;
        let signer = Arc::new(KrillSigner::build(&config.data_dir)?);
        repo_manager = Some(RepositoryManager::build(config.clone(), signer)?);
    }

    let mut cas_dir = config.data_dir.clone();
    cas_dir.push("cas");
    if cas_dir.exists() {
        CaObjectsMigration::migrate(config, repo_manager)?;
    }
    Ok(())
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::commons::util::file;
    use crate::test::tmp_dir;

    use super::*;

    #[test]
    fn test_upgrade_0_8_1() {
        let work_dir = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_8_1/");
        file::backup_dir(&source, &work_dir).unwrap();

        let config = Arc::new(Config::test(&work_dir));
        let _ = config.init_logging();

        upgrade_0_9_0(config).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn test_upgrade_0_6_0() {
        let work_dir = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_6_0/");
        file::backup_dir(&source, &work_dir).unwrap();

        let config = Arc::new(Config::test(&work_dir));
        let _ = config.init_logging();

        upgrade_0_9_0(config).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }
}
