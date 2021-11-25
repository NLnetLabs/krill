//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::{fmt, path::Path, str::FromStr, sync::Arc};

use serde::de::DeserializeOwned;

use crate::{
    commons::{
        api::Handle,
        crypto::KrillSigner,
        error::KrillIoError,
        eventsourcing::{AggregateStoreError, CommandKey, KeyStoreKey, KeyValueError, KeyValueStore},
        util::{file, KrillVersion},
    },
    daemon::{config::Config, krillserver::KrillServer},
    pubd::RepositoryManager,
    upgrades::v0_9_0::{CaObjectsMigration, PubdObjectsMigration},
};

pub mod v0_9_0;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

pub const MIGRATION_SCOPE: &str = "migration";

//------------ UpgradeError --------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum UpgradeError {
    AggregateStoreError(AggregateStoreError),
    KeyStoreError(KeyValueError),
    IoError(KrillIoError),
    Unrecognised(String),
    CannotLoadAggregate(Handle),
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

impl From<KrillIoError> for UpgradeError {
    fn from(e: KrillIoError) -> Self {
        UpgradeError::IoError(e)
    }
}

impl From<crate::commons::error::Error> for UpgradeError {
    fn from(e: crate::commons::error::Error) -> Self {
        UpgradeError::Custom(e.to_string())
    }
}

impl std::error::Error for UpgradeError {}

//------------ UpgradeStore --------------------------------------------------

/// Implement this for automatic upgrades to key stores
pub trait UpgradeStore {
    fn needs_migrate(&self) -> Result<bool, UpgradeError>;
    fn migrate(&self) -> Result<(), UpgradeError>;

    fn version_before(kv: &KeyValueStore, later: KrillVersion) -> Result<bool, UpgradeError> {
        kv.version_is_before(later).map_err(UpgradeError::KeyStoreError)
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
            .archive_to(key, MIGRATION_SCOPE)
            .map_err(UpgradeError::KeyStoreError)
    }

    fn drop_migration_scope(&self, scope: &str) -> Result<(), UpgradeError> {
        let scope = format!("{}/{}", scope, MIGRATION_SCOPE);
        self.store().drop_scope(&scope).map_err(UpgradeError::KeyStoreError)
    }
}

/// Should be called when Krill starts, before the KrillServer is initiated
pub fn pre_start_upgrade(config: Arc<Config>) -> Result<(), UpgradeError> {
    upgrade_data_to_0_9_0(config)
}

/// Should be called when the KrillServer is initiated, before the webserver is started
/// and operators can make changes.
pub async fn post_start_upgrade(config: &Config, server: &KrillServer) -> Result<(), UpgradeError> {
    if needs_upgrade(&config.data_dir, "cas", KrillVersion::candidate(0, 9, 3, 2)) {
        info!("Reissue ROAs on upgrade to force short EE certificate subjects in the objects");
        server.force_renew_roas().await.map_err(|e| e.into())
    } else {
        Ok(())
    }
}

pub async fn update_storage_version(work_dir: &Path) -> Result<(), UpgradeError> {
    let current = KrillVersion::current();

    if needs_v0_9_0_upgrade(work_dir, "cas") {
        debug!("Updating version file for cas");
        file::save_json(&current, &work_dir.join("cas/version"))?;
    }

    if needs_v0_9_0_upgrade(work_dir, "pubd") {
        debug!("Updating version file for pubd");
        file::save_json(&current, &work_dir.join("pubd/version"))?;
    }

    Ok(())
}

fn upgrade_data_to_0_9_0(config: Arc<Config>) -> Result<(), UpgradeError> {
    let work_dir = &config.data_dir;
    if needs_v0_9_0_upgrade(work_dir, "pubd") {
        PubdObjectsMigration::migrate(config.clone())?;
    }

    if needs_v0_9_0_upgrade(work_dir, "cas") {
        // TODO: should we use the configured signers here or an OpenSSL signer?
        // Will any signing actually be done using these signers?
        let signer = Arc::new(KrillSigner::build(
            work_dir,
            &config.signers,
            config.default_signer(),
            config.one_off_signer(),
        )?);
        let repo_manager = RepositoryManager::build(config.clone(), signer.clone())?;

        CaObjectsMigration::migrate(config, repo_manager, signer)?;
    }

    Ok(())
}

fn needs_v0_9_0_upgrade(work_dir: &Path, ns: &str) -> bool {
    needs_upgrade(work_dir, ns, KrillVersion::release(0, 9, 0))
}

fn needs_upgrade(work_dir: &Path, ns: &str, before: KrillVersion) -> bool {
    let keystore_path = work_dir.join(ns);
    if keystore_path.exists() {
        let version_path = keystore_path.join("version");
        let version_found = file::load_json(&version_path).unwrap_or_else(|_| KrillVersion::v0_5_0_or_before());
        version_found < before
    } else {
        false
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::commons::util::file;
    use crate::test::{init_config, tmp_dir};

    use super::*;

    #[test]
    fn test_upgrade_0_8_1() {
        let work_dir = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_8_1/");
        file::backup_dir(&source, &work_dir).unwrap();

        let mut config = Config::test(&work_dir, false, false, false, false);
        init_config(&mut config);

        upgrade_data_to_0_9_0(Arc::new(config)).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }

    #[test]
    fn test_upgrade_0_6_0() {
        let work_dir = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_6_0/");
        file::backup_dir(&source, &work_dir).unwrap();

        let mut config = Config::test(&work_dir, false, false, false, false);
        init_config(&mut config);

        upgrade_data_to_0_9_0(Arc::new(config)).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }
}
