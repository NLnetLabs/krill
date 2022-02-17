//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::{fmt, path::Path, str::FromStr, sync::Arc};

use rpki::repository::x509::Time;
use serde::de::DeserializeOwned;

use crate::{
    commons::{
        api::Handle,
        crypto::KrillSigner,
        error::{Error, KrillIoError},
        eventsourcing::{AggregateStoreError, CommandKey, KeyStoreKey, KeyValueError, KeyValueStore, StoredValueInfo},
        util::{file, KrillVersion},
        KrillResult,
    },
    constants::{CASERVER_DIR, CA_OBJECTS_DIR, PUBSERVER_CONTENT_DIR, PUBSERVER_DIR},
    daemon::{config::Config, krillserver::KrillServer},
    pubd::RepositoryManager,
    upgrades::v0_9_0::{CaObjectsMigration, PubdObjectsMigration},
};

pub mod v0_9_0;

pub type UpgradeResult<T> = Result<T, PrepareUpgradeError>;

pub const MIGRATION_SCOPE: &str = "migration";

//------------ KrillUpgradeReport --------------------------------------------

#[derive(Debug)]
pub struct UpgradeReport {
    data_migration: bool,
    versions: UpgradeVersions,
}

impl UpgradeReport {
    pub fn new(data_migration: bool, versions: UpgradeVersions) -> Self {
        UpgradeReport {
            data_migration,
            versions,
        }
    }
    pub fn data_migration(&self) -> bool {
        self.data_migration
    }

    pub fn versions(&self) -> &UpgradeVersions {
        &self.versions
    }
}

//------------ KrillUpgradeVersions ------------------------------------------

#[derive(Debug)]
pub struct UpgradeVersions {
    from: KrillVersion,
    to: KrillVersion,
}

impl UpgradeVersions {
    /// Returns a KrillUpgradeVersions if the krill code version is newer
    /// than the provided current version.
    pub fn for_current(current: KrillVersion) -> Option<Self> {
        let code_version = KrillVersion::code_version();
        if code_version > current {
            Some(UpgradeVersions {
                from: current,
                to: code_version,
            })
        } else {
            None
        }
    }

    pub fn from(&self) -> &KrillVersion {
        &self.from
    }

    pub fn to(&self) -> &KrillVersion {
        &self.to
    }
}

//------------ UpgradeError --------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PrepareUpgradeError {
    AggregateStoreError(AggregateStoreError),
    KeyStoreError(KeyValueError),
    IoError(KrillIoError),
    Unrecognised(String),
    CannotLoadAggregate(Handle),
    Custom(String),
}

impl fmt::Display for PrepareUpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error!("Upgrade preparation failed: {}", &self);

        write!(f, "Upgrade preparation failed. Your original data is unchanged. If you upgraded 'krill' rather than used 'krillup' for this process, then please downgrade to your previous version.")?;

        match self {
            PrepareUpgradeError::Unrecognised(s) => {
                write!(
                    f,
                    "Underlying issue was that an unrecognised command summary was found: {}",
                    s
                )?;
                write!(
                    f,
                    "Please create an issue here: https://github.com/NLnetLabs/krill/issues",
                )?;
            }
            PrepareUpgradeError::CannotLoadAggregate(handle) => {
                write!(f, "Underlying issue was that state for {} could not be loaded", handle)?;
                write!(
                    f,
                    "Please create an issue here: https://github.com/NLnetLabs/krill/issues",
                )?;
            }
            _ => {}
        }

        Ok(())
    }
}
impl PrepareUpgradeError {
    pub fn custom(msg: impl fmt::Display) -> Self {
        PrepareUpgradeError::Custom(msg.to_string())
    }

    pub fn unrecognised(msg: impl fmt::Display) -> Self {
        PrepareUpgradeError::Unrecognised(msg.to_string())
    }
}

impl From<AggregateStoreError> for PrepareUpgradeError {
    fn from(e: AggregateStoreError) -> Self {
        PrepareUpgradeError::AggregateStoreError(e)
    }
}

impl From<KeyValueError> for PrepareUpgradeError {
    fn from(e: KeyValueError) -> Self {
        PrepareUpgradeError::KeyStoreError(e)
    }
}

impl From<KrillIoError> for PrepareUpgradeError {
    fn from(e: KrillIoError) -> Self {
        PrepareUpgradeError::IoError(e)
    }
}

impl From<crate::commons::error::Error> for PrepareUpgradeError {
    fn from(e: crate::commons::error::Error) -> Self {
        PrepareUpgradeError::Custom(e.to_string())
    }
}

impl std::error::Error for PrepareUpgradeError {}

//------------ DataUpgradeInfo -----------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataUpgradeInfo {
    pub last_event: u64,
    pub last_command: u64,
    pub last_update: Time,
}

impl Default for DataUpgradeInfo {
    fn default() -> Self {
        Self {
            last_event: 0,
            last_command: 0,
            last_update: Time::now(), // will be overwritten to appropriate value
        }
    }
}

impl From<&DataUpgradeInfo> for StoredValueInfo {
    fn from(upgrade_info: &DataUpgradeInfo) -> Self {
        StoredValueInfo {
            snapshot_version: 0,
            last_event: upgrade_info.last_event,
            last_command: upgrade_info.last_command,
            last_update: upgrade_info.last_update,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UpgradeMode {
    PrepareOnly,
    PrepareToFinalise,
}

//------------ UpgradeStore --------------------------------------------------

/// Implement this for automatic upgrades to key stores
pub trait UpgradeStore {
    fn needs_migrate(&self) -> Result<bool, PrepareUpgradeError>;

    fn prepare_new_data(&self, mode: UpgradeMode) -> Result<(), PrepareUpgradeError>;

    fn version_before(&self, later: KrillVersion) -> Result<bool, PrepareUpgradeError> {
        self.deployed_store()
            .version_is_before(later)
            .map_err(PrepareUpgradeError::KeyStoreError)
    }

    fn deployed_store(&self) -> &KeyValueStore;

    fn preparation_store(&self) -> &KeyValueStore;

    fn data_upgrade_info_key(scope: &str) -> KeyStoreKey {
        KeyStoreKey::scoped(scope.to_string(), "upgrade_info.json".to_string())
    }

    /// Return the DataUpgradeInfo telling us to where we got to with this migration.
    fn data_upgrade_info(&self, scope: &str) -> UpgradeResult<DataUpgradeInfo> {
        self.preparation_store()
            .get(&Self::data_upgrade_info_key(scope))
            .map(|opt| match opt {
                None => DataUpgradeInfo::default(),
                Some(info) => info,
            })
            .map_err(PrepareUpgradeError::KeyStoreError)
    }

    /// Update the DataUpgradeInfo
    fn update_data_upgrade_info(&self, scope: &str, info: &DataUpgradeInfo) -> UpgradeResult<()> {
        self.preparation_store()
            .store(&Self::data_upgrade_info_key(scope), info)
            .map_err(PrepareUpgradeError::KeyStoreError)
    }

    /// Removed the DataUpgradeInfo
    fn remove_data_upgrade_info(&self, scope: &str) -> UpgradeResult<()> {
        self.preparation_store()
            .drop_key(&Self::data_upgrade_info_key(scope))
            .map_err(PrepareUpgradeError::KeyStoreError)
    }

    /// Find all command keys for the scope, starting from the provided sequence. Then sort them
    /// by sequence and turn them back into key store keys for further processing.
    fn command_keys(&self, scope: &str, from: u64) -> Result<Vec<KeyStoreKey>, PrepareUpgradeError> {
        let store = self.deployed_store();
        let keys = store.keys(Some(scope.to_string()), "command--")?;
        let mut cmd_keys: Vec<CommandKey> = vec![];
        for key in keys {
            let cmd_key = CommandKey::from_str(key.name()).map_err(|_| {
                PrepareUpgradeError::Custom(format!("Found invalid command key: {} for ca: {}", key.name(), scope))
            })?;
            if cmd_key.sequence > from {
                cmd_keys.push(cmd_key);
            }
        }
        cmd_keys.sort_by_key(|k| k.sequence);
        let cmd_keys = cmd_keys
            .into_iter()
            .map(|ck| KeyStoreKey::scoped(scope.to_string(), format!("{}.json", ck)))
            .collect();

        Ok(cmd_keys)
    }

    fn get<V: DeserializeOwned>(&self, key: &KeyStoreKey) -> Result<V, PrepareUpgradeError> {
        self.deployed_store()
            .get(key)?
            .ok_or_else(|| PrepareUpgradeError::Custom(format!("Cannot read key: {}", key)))
    }

    fn event_key(scope: &str, nr: u64) -> KeyStoreKey {
        KeyStoreKey::scoped(scope.to_string(), format!("delta-{}.json", nr))
    }
}

/// Prepares a Krill upgrade related data migration. If no data migration is needed
/// then this will simply be a no-op. Returns the [`KrillUpgradeVersions`] if the currently
/// deployed Krill version differs from the code version. Note that the version may
/// have increased even if there is no data migration needed.
///
/// In case data needs to be migrated, then new data will be prepared under
/// the directory returned by `config.data_dir()`. By design, this migration can be
/// executed while Krill is running as it does not affect any current state. It can
/// be called multiple times and it will resume the migration from the point it got
/// to earlier. The idea is that this will allow operators to prepare the work for
/// a migration and (a) verify that the migration worked, and (b) minimize the downtime
/// when Krill is restarted into a new version. When a new version Krill deamon is
/// started, it will call this again - to do the final preparation for a migration -
/// knowing that no changes are added to the event history at this time. After this,
/// the migration will be finalised.
pub async fn prepare_upgrade_data_migrations(
    mode: UpgradeMode,
    config: Arc<Config>,
) -> UpgradeResult<Option<UpgradeReport>> {
    match upgrade_versions(config.as_ref()) {
        None => Ok(None),
        Some(versions) => {
            if versions.from < KrillVersion::release(0, 6, 0) {
                let msg = "Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to any version ranging from 0.6.0 to 0.8.1 first, and then upgrade to this version.";
                error!("{}", msg);
                Err(PrepareUpgradeError::custom(msg))
            } else if versions.from < KrillVersion::release(0, 9, 0) {
                let upgrade_data_dir = config.upgrade_data_dir();
                if !upgrade_data_dir.exists() {
                    file::create_dir(&upgrade_data_dir)?;
                }

                // Get a lock to ensure that only one process can run this migration
                // at any one time (for a given config).
                let _lock = {
                    // Create upgrade dir if it did not yet exist.
                    let lock_file_path = upgrade_data_dir.join("upgrade.lock");
                    fslock::LockFile::open(&lock_file_path).map_err(|_| {
                        PrepareUpgradeError::custom(
                            "Cannot get upgrade lock, it seems that another process is running a krill upgrade",
                        )
                    })?
                };

                // We need to prepare pubd first, because if there were any CAs using
                // an embedded repository then they will need to be updated to use the
                // RFC 8181 protocol (using localhost) instead, and this can only be
                // *after* the publication server data is migrated.
                PubdObjectsMigration::prepare(mode, config.clone())?;

                // We fool a repository manager for the CA migration to use the upgrade
                // data directory as its base dir. This repository manager will be used
                // to get the repository response XML for any (if any) CAs that were
                // using an embedded repository.
                let mut repo_manager_migration_config = (*config).clone();
                repo_manager_migration_config.data_dir = upgrade_data_dir;

                // We need a signer because it's required by the repo manager, although
                // we will not actually use it during the migration. Let it use the
                // config using the upgrade_data_dir as base dir to ensure that it
                // cannot - even unintendedly - affect any of they keys.
                let signer = Arc::new(KrillSigner::build(&repo_manager_migration_config.data_dir)?);
                let repo_manager = RepositoryManager::build(Arc::new(repo_manager_migration_config), signer)?;

                CaObjectsMigration::prepare(mode, config, repo_manager)?;

                Ok(Some(UpgradeReport::new(true, versions)))
            } else {
                Ok(Some(UpgradeReport::new(false, versions)))
            }
        }
    }
}

/// Finalise the data migration for an upgrade. I.e. move the prepared data and archive
/// the old data if applicable to this upgrade, and otherwise (in any event) update the
/// the current versions for the "cas" and "pubd" store where applicable.
pub fn finalise_data_migration(upgrade: &UpgradeVersions, config: &Config) -> KrillResult<()> {
    // Move directories - if applicable (servers can have cas, repo server or both)

    let from = upgrade.from();
    let current = upgrade.to();
    let data_dir = &config.data_dir;
    let upgrade_dir = config.upgrade_data_dir();

    // cas -> arch-cas-{old-version}
    // upgrade-data/cas -> cas
    // upgrade-data/ca_objects -> ca_objects
    // set cas/version

    let cas = data_dir.join(CASERVER_DIR);
    let cas_version = cas.join("version");
    let cas_arch = data_dir.join(format!("arch-{}-{}", CASERVER_DIR, from));
    let cas_upg = upgrade_dir.join(CASERVER_DIR);
    let ca_objects = data_dir.join(CA_OBJECTS_DIR);
    let ca_objects_upg = upgrade_dir.join(CA_OBJECTS_DIR);

    move_dir_if_exists(&cas, &cas_arch)?;
    move_dir_if_exists(&cas_upg, &cas)?;
    move_dir_if_exists(&ca_objects_upg, &ca_objects)?;
    file::save_json(&current, &cas_version)
        .map_err(|e| Error::Custom(format!("Could not update version file: {}", e)))?;

    // pubd -> arch-pubd-{old-version}
    // upgrade-data/pubd -> pubd
    // upgrade-data/pubd_objects -> pubd_objects
    // set pubd/version

    let pubd = data_dir.join(PUBSERVER_DIR);
    let pubd_version = pubd.join("version");
    let pubd_arch = data_dir.join(format!("arch-{}-{}", PUBSERVER_DIR, from));
    let pubd_upg = upgrade_dir.join(PUBSERVER_DIR);
    let pubd_objects = data_dir.join(PUBSERVER_CONTENT_DIR);
    let pubd_objects_upg = upgrade_dir.join(PUBSERVER_CONTENT_DIR);

    move_dir_if_exists(&pubd, &pubd_arch)?;
    move_dir_if_exists(&pubd_upg, &pubd)?;
    move_dir_if_exists(&pubd_objects_upg, &pubd_objects)?;
    file::save_json(&current, &pubd_version)
        .map_err(|e| Error::Custom(format!("Could not update version file: {}", e)))?;

    // done, clean out the migration dir
    file::remove_dir_all(&upgrade_dir)
        .map_err(|e| Error::Custom(format!("Could not delete migration directory: {}", e)))?;

    // move the dirs
    fn move_dir_if_exists(from: &Path, to: &Path) -> KrillResult<()> {
        if from.exists() {
            std::fs::rename(from, to).map_err(|e| {
                let context = format!(
                    "Could not rename directory from: {} to: {}.",
                    from.to_string_lossy(),
                    to.to_string_lossy()
                );
                Error::IoError(KrillIoError::new(context, e))
            })
        } else {
            Ok(())
        }
    }

    Ok(())
}

/// Should be called after the KrillServer is started, but before the web server is started
/// and operators can make changes.
pub async fn post_start_upgrade(
    upgrade_versions: &UpgradeVersions,
    server: &KrillServer,
) -> Result<(), PrepareUpgradeError> {
    if upgrade_versions.from() < &KrillVersion::candidate(0, 9, 3, 2) {
        info!("Reissue ROAs on upgrade to force short EE certificate subjects in the objects");
        server.force_renew_roas().await.map_err(|e| e.into())
    } else {
        Ok(())
    }
}

/// Returns the KrillUpgradeVersion by comparing the versions of the data used by
/// the "cas" and "pubd" of the current Krill version to the code version. In the
/// unlikely event that the "cas" and "pubd" stores are in disagreement, then the
/// highest of the two version is used as the 'current' version. This can only happen
/// in practice in case one of the two did not have their version updated in the past,
/// as there can be only one version running.
fn upgrade_versions(config: &Config) -> Option<UpgradeVersions> {
    let cas_version = upgrade_versions_ns(&config.data_dir, CASERVER_DIR);
    let pubd_version = upgrade_versions_ns(&config.data_dir, PUBSERVER_DIR);

    match (cas_version, pubd_version) {
        (None, None) => None,
        (Some(upgrade), None) | (None, Some(upgrade)) => Some(upgrade),
        (Some(upgrade_cas), Some(upgrade_pubd)) => {
            if upgrade_cas.from() >= upgrade_pubd.from() {
                Some(upgrade_cas)
            } else {
                Some(upgrade_pubd)
            }
        }
    }
}

fn upgrade_versions_ns(work_dir: &Path, ns: &str) -> Option<UpgradeVersions> {
    let keystore_path = work_dir.join(ns);
    if keystore_path.exists() {
        let version_path = keystore_path.join("version");
        let current = file::load_json(&version_path).unwrap_or_else(|_| KrillVersion::v0_5_0_or_before());
        UpgradeVersions::for_current(current)
    } else {
        None
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::commons::util::file;
    use crate::test::tmp_dir;

    use super::*;

    async fn test_upgrade(source: PathBuf) {
        let work_dir = tmp_dir();
        file::backup_dir(&source, &work_dir).unwrap();

        let config = Config::test(&work_dir, false, false, false);
        let _ = config.init_logging();

        let _upgrade = prepare_upgrade_data_migrations(UpgradeMode::PrepareOnly, Arc::new(config.clone()))
            .await
            .unwrap()
            .unwrap();

        // and continue - immediately, but still tests that this can pick up again.
        let report = prepare_upgrade_data_migrations(UpgradeMode::PrepareToFinalise, Arc::new(config.clone()))
            .await
            .unwrap()
            .unwrap();

        finalise_data_migration(report.versions(), &config).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_8_1() {
        let source = PathBuf::from("test-resources/migrations/v0_8_1/");
        test_upgrade(source).await;
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_7_3_cas_only() {
        let source = PathBuf::from("test-resources/migrations/v0_7_3_cas_only/");
        test_upgrade(source).await;
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_8_1_pubd_only() {
        let source = PathBuf::from("test-resources/migrations/v0_8_1_pubd_only/");
        test_upgrade(source).await;
    }

    #[tokio::test]
    async fn test_upgrade_0_6_0() {
        let work_dir = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/v0_6_0/");
        file::backup_dir(&source, &work_dir).unwrap();

        let config = Arc::new(Config::test(&work_dir, false, false, false));
        let _ = config.init_logging();

        let report = prepare_upgrade_data_migrations(UpgradeMode::PrepareToFinalise, config.clone())
            .await
            .unwrap()
            .unwrap();

        finalise_data_migration(report.versions(), &config).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }
}
