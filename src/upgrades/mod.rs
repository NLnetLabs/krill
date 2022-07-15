//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::{fmt, path::Path, str::FromStr, sync::Arc, time::Duration};

use serde::de::DeserializeOwned;

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::{
    commons::{
        crypto::KrillSignerBuilder,
        error::{Error, KrillIoError},
        eventsourcing::{AggregateStoreError, CommandKey, KeyStoreKey, KeyValueError, KeyValueStore, StoredValueInfo},
        util::{file, KrillVersion},
        KrillResult,
    },
    constants::{CASERVER_DIR, CA_OBJECTS_DIR, PUBSERVER_CONTENT_DIR, PUBSERVER_DIR, UPGRADE_REISSUE_ROAS_CAS_LIMIT},
    daemon::{config::Config, krillserver::KrillServer},
    pubd::RepositoryManager,
};

#[cfg(feature = "hsm")]
use rpki::crypto::KeyIdentifier;

#[cfg(feature = "hsm")]
use crate::{
    commons::crypto::SignerHandle,
    constants::{KEYS_DIR, SIGNERS_DIR},
};

pub mod pre_0_10_0;
pub mod pre_0_9_0;

pub type UpgradeResult<T> = Result<T, PrepareUpgradeError>;

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
    CannotLoadAggregate(MyHandle),
    IdExchange(String),
    Custom(String),
}

impl fmt::Display for PrepareUpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cause = match &self {
            PrepareUpgradeError::AggregateStoreError(e) => format!("Aggregate Error: {}", e),
            PrepareUpgradeError::KeyStoreError(e) => format!("Keystore Error: {}", e),
            PrepareUpgradeError::IoError(e) => format!("I/O Error: {}", e),
            PrepareUpgradeError::Unrecognised(s) => format!("Unrecognised: {}", s),
            PrepareUpgradeError::CannotLoadAggregate(h) => format!("Cannot load: {}", h),
            PrepareUpgradeError::IdExchange(s) => format!("Could not use exchanged id info: {}", s),
            PrepareUpgradeError::Custom(s) => s.clone(),
        };

        write!(f, "Upgrade preparation failed because of: {}", cause)
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

impl From<rpki::ca::idexchange::Error> for PrepareUpgradeError {
    fn from(e: rpki::ca::idexchange::Error) -> Self {
        PrepareUpgradeError::IdExchange(e.to_string())
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

    /// Checks whether the preparation store is set up for the current code
    /// krill version. If it isn't the store will be wiped so that we can
    /// start over, and the version will be set to the current code version.
    fn preparation_store_prepare(&self) -> UpgradeResult<()> {
        if !self.preparation_store().version_is_current()? {
            warn!("Found prepared data for a different krill version, will remove it and start from scratch");
            self.preparation_store().wipe()?;
            self.preparation_store().version_set_current()?;
        }
        Ok(())
    }

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
pub fn prepare_upgrade_data_migrations(mode: UpgradeMode, config: Arc<Config>) -> UpgradeResult<Option<UpgradeReport>> {
    match upgrade_versions(config.as_ref()) {
        None => Ok(None),
        Some(versions) => {
            if versions.from < KrillVersion::release(0, 6, 0) {
                let msg = "Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to any version ranging from 0.6.0 to 0.8.1 first, and then upgrade to this version.";
                error!("{}", msg);
                Err(PrepareUpgradeError::custom(msg))
            } else if versions.from < KrillVersion::candidate(0, 10, 0, 1) {
                let upgrade_data_dir = config.upgrade_data_dir();
                if !upgrade_data_dir.exists() {
                    file::create_dir_all(&upgrade_data_dir)?;
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

                if versions.from < KrillVersion::release(0, 9, 0) {
                    // We will need an extensive migration because we found that the
                    // number of events related to (1) republishing manifests/CRLs in CAs,
                    // and (2) publishing objects for publishers in the repository resulted
                    // in excessive disk space usage.
                    //
                    // So, now we use a hybrid event sourcing model where all *other* changes
                    // are still tracked through events, but these high-churn publication
                    // changes are kept in dedicated stateful objects:
                    // - pubd_objects for objects published in a repository server
                    // - ca_objects for published objects for a CA.

                    #[cfg(feature = "hsm")]
                    record_preexisting_openssl_keys_in_signer_mapper(config.clone())?;

                    // We need to prepare pubd first, because if there were any CAs using
                    // an embedded repository then they will need to be updated to use the
                    // RFC 8181 protocol (using localhost) instead, and this can only be
                    // *after* the publication server data is migrated.
                    pre_0_9_0::PubdObjectsMigration::prepare(mode, config.clone())?;

                    // We need a signer because it's required by the repo manager, although
                    // we will not actually use it during the migration.
                    let probe_interval = Duration::from_secs(config.signer_probe_retry_seconds);
                    let signer = KrillSignerBuilder::new(&upgrade_data_dir, probe_interval, &config.signers)
                        .with_default_signer(config.default_signer())
                        .with_one_off_signer(config.one_off_signer())
                        .build()
                        .unwrap();
                    let signer = Arc::new(signer);

                    // We fool a repository manager for the CA migration to use the upgrade
                    // data directory as its base dir. This repository manager will be used
                    // to get the repository response XML for any (if any) CAs that were
                    // using an embedded repository.
                    let mut repo_manager_migration_config = (*config).clone();
                    repo_manager_migration_config.data_dir = upgrade_data_dir;

                    let repo_manager =
                        RepositoryManager::build(Arc::new(repo_manager_migration_config), signer.clone())?;

                    pre_0_9_0::CaObjectsMigration::prepare(mode, config, repo_manager, signer)?;
                } else {
                    pre_0_10_0::CasMigration::prepare(mode, &config)?;
                    pre_0_10_0::PublicationServerMigration::prepare(mode, &config)?;
                }

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
    let data_dir = &config.data_dir;
    let upgrade_dir = config.upgrade_data_dir();

    let cas = data_dir.join(CASERVER_DIR);
    let cas_arch = data_dir.join(format!("arch-{}-{}", CASERVER_DIR, from));
    let cas_upg = upgrade_dir.join(CASERVER_DIR);
    let ca_objects = data_dir.join(CA_OBJECTS_DIR);
    let ca_objects_arch = data_dir.join(format!("arch-{}-{}", CA_OBJECTS_DIR, from));
    let ca_objects_upg = upgrade_dir.join(CA_OBJECTS_DIR);

    // upgrade-data/cas exists
    if cas_upg.exists() {
        // cas -> arch-cas-{old-version}
        // upgrade-data/cas -> cas
        move_dir_if_exists(&cas, &cas_arch)?;
        move_dir_if_exists(&cas_upg, &cas)?;
    }

    // upgrade-data/ca_objects exists
    if ca_objects_upg.exists() {
        // ca_objects -> arch-ca_objects-{old-version}
        // upgrade-data/ca_objects -> ca_objects
        move_dir_if_exists(&ca_objects, &ca_objects_arch)?;
        move_dir_if_exists(&ca_objects_upg, &ca_objects)?;
    }

    let pubd = data_dir.join(PUBSERVER_DIR);
    let pubd_arch = data_dir.join(format!("arch-{}-{}", PUBSERVER_DIR, from));
    let pubd_upg = upgrade_dir.join(PUBSERVER_DIR);
    let pubd_objects = data_dir.join(PUBSERVER_CONTENT_DIR);
    let pubd_objects_arch = data_dir.join(format!("arch-{}-{}", PUBSERVER_CONTENT_DIR, from));
    let pubd_objects_upg = upgrade_dir.join(PUBSERVER_CONTENT_DIR);

    // upgrade-data/pubd exists
    if pubd_upg.exists() {
        // pubd -> arch-pubd-{old-version}
        // upgrade-data/pubd -> pubd
        move_dir_if_exists(&pubd, &pubd_arch)?;
        move_dir_if_exists(&pubd_upg, &pubd)?
    }

    // upgrade-data/pubd_objects exists
    if pubd_objects_upg.exists() {
        // pubd_objects -> arch-pubd_objects-{old-version}
        // upgrade-data/pubd_objects -> pubd_objects
        move_dir_if_exists(&pubd_objects, &pubd_objects_arch)?;
        move_dir_if_exists(&pubd_objects_upg, &pubd_objects)?;
    }

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

/// Prior to Krill having HSM support there was no signer mapper as it wasn't needed, keys were just created by OpenSSL
/// and stored in files on disk in KEYS_DIR named by the string form of their Krill KeyIdentifier. If Krill had created
/// such keys and then the operator upgrades to a version of Krill with HSM support, the keys will become unusable
/// because Krill will not be able to find a mapping from KeyIdentifier to signer as the mappings for the keys were
/// never created. So we detect the case that the signer store SIGNERS_DIR directory has not yet been created, i.e. no
/// signers have been registered and no key mappings have been recorded, and then walk KEYS_DIR adding the keys one by
/// one to the mapping in the signer store, if any.
#[cfg(feature = "hsm")]
fn record_preexisting_openssl_keys_in_signer_mapper(config: Arc<Config>) -> Result<(), PrepareUpgradeError> {
    if !config.data_dir.join(SIGNERS_DIR).exists() {
        let mut num_recorded_keys = 0;
        let keys_dir = config.data_dir.join(KEYS_DIR);

        info!(
            "Scanning for not yet mapped OpenSSL signer keys in {} to record in the signer store",
            keys_dir.to_string_lossy()
        );

        let probe_interval = Duration::from_secs(config.signer_probe_retry_seconds);
        let krill_signer = KrillSignerBuilder::new(&config.data_dir, probe_interval, &config.signers)
            .with_default_signer(config.default_signer())
            .with_one_off_signer(config.one_off_signer())
            .build()
            .unwrap();

        // For every file (key) in the legacy OpenSSL signer keys directory
        if let Ok(dir_iter) = keys_dir.read_dir() {
            let mut openssl_signer_handle: Option<SignerHandle> = None;

            for entry in dir_iter {
                let entry = entry.map_err(|err| {
                    PrepareUpgradeError::IoError(KrillIoError::new(
                        format!(
                            "I/O error while looking for signer keys to register in: {}",
                            keys_dir.to_string_lossy()
                        ),
                        err,
                    ))
                })?;

                if entry.path().is_file() {
                    // Is it a key identifier?
                    if let Ok(key_id) = KeyIdentifier::from_str(&entry.file_name().to_string_lossy()) {
                        // Is the key already recorded in the mapper? It shouldn't be, but asking will cause the initial
                        // registration of the OpenSSL signer to occur and for it to be assigned a handle. We need the
                        // handle so that we can register keys with the mapper.
                        if !krill_signer.get_key_info(&key_id).is_ok() {
                            // No, record it

                            // Find out the handle of the OpenSSL signer used to create this key, if not yet known.
                            if openssl_signer_handle.is_none() {
                                // No, find it by asking each of the active signers if they have the key because one of
                                // them must have it and it should be the one and only OpenSSL signer that Krill was
                                // using previously. We can't just find and use the only OpenSSL signers as Krill may
                                // have been configured with more than one each with separate keys directories.
                                for (a_signer_handle, a_signer) in krill_signer.get_active_signers().iter() {
                                    if a_signer.get_key_info(&key_id).is_ok() {
                                        openssl_signer_handle = Some(a_signer_handle.clone());
                                        break;
                                    }
                                }
                            }

                            // Record the key in the signer mapper as being owned by the found signer handle.
                            if let Some(signer_handle) = &openssl_signer_handle {
                                let internal_key_id = key_id.to_string();
                                if let Some(mapper) = krill_signer.get_mapper() {
                                    mapper.add_key(&signer_handle, &key_id, &internal_key_id)?;
                                    num_recorded_keys += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("Recorded {} key identifiers in the signer store", num_recorded_keys);
    }

    Ok(())
}

/// Should be called after the KrillServer is started, but before the web server is started
/// and operators can make changes.
pub async fn post_start_upgrade(upgrade_versions: &UpgradeVersions, server: &KrillServer) -> KrillResult<()> {
    if upgrade_versions.from() < &KrillVersion::candidate(0, 9, 3, 2) {
        if server.ca_list(server.system_actor())?.as_ref().len() <= UPGRADE_REISSUE_ROAS_CAS_LIMIT {
            info!("Reissue ROAs on upgrade to force short EE certificate subjects in the objects");
            server.force_renew_roas().await
        } else {
            // We do not re-issue ROAs to avoid a load spike on the repository. Long ROA subjects
            // are accepted by all RPs and ROAs will be replaced by the system automatically. Using
            // default settings that are replaced 4 weeks before expiry and issued with a validity
            // of 52 weeks -> i.e. 48 weeks after issuance.
            //
            // If users want to force the ROAs are re-issued they can do a key roll.
            Ok(())
        }
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

        let config = Config::test(&work_dir, false, false, false, false);
        let _ = config.init_logging();

        let _upgrade = prepare_upgrade_data_migrations(UpgradeMode::PrepareOnly, Arc::new(config.clone()))
            .unwrap()
            .unwrap();

        // and continue - immediately, but still tests that this can pick up again.
        let report = prepare_upgrade_data_migrations(UpgradeMode::PrepareToFinalise, Arc::new(config.clone()))
            .unwrap()
            .unwrap();

        finalise_data_migration(report.versions(), &config).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_9_5() {
        let source = PathBuf::from("test-resources/migrations/v0_9_5/");
        test_upgrade(source).await;
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

        let config = Arc::new(Config::test(&work_dir, false, false, false, false));
        let _ = config.init_logging();

        let report = prepare_upgrade_data_migrations(UpgradeMode::PrepareToFinalise, config.clone())
            .unwrap()
            .unwrap();

        finalise_data_migration(report.versions(), &config).unwrap();

        let _ = fs::remove_dir_all(work_dir);
    }

    #[cfg(all(feature = "hsm", not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))))]
    fn unmapped_keys_test_core(do_upgrade: bool) {
        let expected_key_id = KeyIdentifier::from_str("5CBCAB14B810C864F3EEA8FD102B79F4E53FCC70").unwrap();

        // Place a key previously created by an OpenSSL signer in the KEYS_DIR under the Krill data dir.
        // Then run the upgrade. It should find the key and add it to the mapper.
        let work_dir = tmp_dir();
        let source = PathBuf::from("test-resources/migrations/unmapped_keys/");
        file::backup_dir(&source, &work_dir).unwrap();

        let mut config = Config::test(&work_dir, false, false, false, false);
        let _ = config.init_logging();
        config.process().unwrap();
        let config = Arc::new(config);

        if do_upgrade {
            record_preexisting_openssl_keys_in_signer_mapper(config.clone()).unwrap();
        }

        // Now test that a newly initialized `KrillSigner` with a default OpenSSL signer
        // is associated with the newly created mapper store and is thus able to use the
        // key that we placed on disk.
        let probe_interval = Duration::from_secs(config.signer_probe_retry_seconds);
        let krill_signer = KrillSignerBuilder::new(&work_dir, probe_interval, &config.signers)
            .with_default_signer(config.default_signer())
            .with_one_off_signer(config.one_off_signer())
            .build()
            .unwrap();

        // Trigger the signer to be bound to the one the migration just registered in the mapper
        krill_signer.random_serial().unwrap();

        // Verify that the mapper has a single registered signer
        let mapper = krill_signer.get_mapper().unwrap();
        let signer_handles = mapper.get_signer_handles().unwrap();
        assert_eq!(1, signer_handles.len());

        if do_upgrade {
            // Verify that the mapper has a record of the test key belonging to the signer
            mapper.get_signer_for_key(&expected_key_id).unwrap();
        } else {
            // Verify that the mapper does NOT have a record of the test key belonging to the signer
            assert!(mapper.get_signer_for_key(&expected_key_id).is_err());
        }

        let _ = fs::remove_dir_all(work_dir);
    }

    #[cfg(all(feature = "hsm", not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))))]
    #[test]
    fn test_key_not_found_error_if_unmapped_keys_are_not_mapped_on_upgrade() {
        unmapped_keys_test_core(false);
    }

    #[cfg(all(feature = "hsm", not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))))]
    #[test]
    fn test_upgrading_with_unmapped_keys() {
        unmapped_keys_test_core(true);
    }
}
