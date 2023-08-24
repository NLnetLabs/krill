//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::{convert::TryInto, fmt, fs, path::Path, str::FromStr, time::Duration};

use serde::{de::DeserializeOwned, Deserialize};

use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::{
    commons::{
        actor::Actor,
        crypto::KrillSignerBuilder,
        error::{Error, KrillIoError},
        eventsourcing::{
            segment, Aggregate, AggregateStore, AggregateStoreError, Key, KeyValueError, KeyValueStore, Scope, Segment,
            SegmentExt, Storable, StoredCommand, WalStore, WithStorableDetails,
        },
        util::{file, storage::data_dir_from_storage_uri, KrillVersion},
        KrillResult,
    },
    constants::{
        CASERVER_NS, CA_OBJECTS_NS, KEYS_NS, KRILL_VERSION, PUBSERVER_CONTENT_NS, PUBSERVER_NS, SIGNERS_NS, STATUS_NS,
        TA_PROXY_SERVER_NS, TA_SIGNER_SERVER_NS, UPGRADE_REISSUE_ROAS_CAS_LIMIT,
    },
    daemon::{config::Config, krillserver::KrillServer, properties::PropertiesManager},
    pubd,
};

#[cfg(feature = "hsm")]
use rpki::crypto::KeyIdentifier;

#[cfg(feature = "hsm")]
use crate::commons::crypto::SignerHandle;

use self::pre_0_13_0::OldRepositoryContent;

pub mod pre_0_10_0;

#[allow(clippy::mutable_key_type)]
pub mod pre_0_13_0;

mod pre_0_14_0;
pub use self::pre_0_14_0::*;

pub type UpgradeResult<T> = Result<T, UpgradeError>;

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

#[derive(Debug, Eq, PartialEq)]
pub struct UpgradeVersions {
    from: KrillVersion,
    to: KrillVersion,
}

impl UpgradeVersions {
    /// Returns a KrillUpgradeVersions if the krill code version is newer
    /// than the provided current version.
    pub fn for_current(current: KrillVersion) -> Result<Option<Self>, UpgradeError> {
        let code_version = KrillVersion::code_version();
        match code_version.cmp(&current) {
            std::cmp::Ordering::Greater => Ok(Some(UpgradeVersions {
                from: current,
                to: code_version,
            })),
            std::cmp::Ordering::Equal => Ok(None),
            std::cmp::Ordering::Less => Err(UpgradeError::CodeOlderThanData(code_version, current)),
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
pub enum UpgradeError {
    AggregateStoreError(AggregateStoreError),
    KeyStoreError(KeyValueError),
    IoError(KrillIoError),
    Unrecognised(String),
    CannotLoadAggregate(MyHandle),
    IdExchange(String),
    OldTaMigration,
    CodeOlderThanData(KrillVersion, KrillVersion),
    Custom(String),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cause = match &self {
            UpgradeError::AggregateStoreError(e) => format!("Aggregate Error: {}", e),
            UpgradeError::KeyStoreError(e) => format!("Keystore Error: {}", e),
            UpgradeError::IoError(e) => format!("I/O Error: {}", e),
            UpgradeError::Unrecognised(s) => format!("Unrecognised: {}", s),
            UpgradeError::CannotLoadAggregate(h) => format!("Cannot load: {}", h),
            UpgradeError::IdExchange(s) => format!("Could not use exchanged id info: {}", s),
            UpgradeError::OldTaMigration => "Your installation cannot be upgraded to Krill 0.13.0 or later because it includes a CA called \"ta\". These CAs were used for the preliminary Trust Anchor support needed by testbed and benchmark setups. They cannot be migrated to the production grade Trust Anchor support that was introduced in Krill 0.13.0. If you want to continue to use your existing installation we recommend that you downgrade to Krill 0.12.1 or earlier. If you want to operate a testbed using Krill 0.13.0 or later, then you can create a fresh testbed instead of migrating your existing testbed. If you believe that you should not have a CA called \"ta\" - i.e. it may have been left over from an abandoned testbed set up - then you can delete the \"ta\" directory under your krill data \"cas\" directory and restart Krill.".to_string(),
            UpgradeError::CodeOlderThanData(code, data) => format!("Krill version {} is older than data version {}. You will need to restore before you can downgrade.", code, data),
            UpgradeError::Custom(s) => s.clone(),
        };

        write!(f, "Upgrade preparation failed because of: {}", cause)
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

impl From<rpki::ca::idexchange::Error> for UpgradeError {
    fn from(e: rpki::ca::idexchange::Error) -> Self {
        UpgradeError::IdExchange(e.to_string())
    }
}

impl std::error::Error for UpgradeError {}

//------------ DataUpgradeInfo -----------------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataUpgradeInfo {
    pub to_krill_version: KrillVersion,
    pub last_command: Option<u64>,
}

impl DataUpgradeInfo {
    fn next_command(&self) -> u64 {
        self.last_command.map(|nr| nr + 1).unwrap_or(0)
    }

    fn increment_command(&mut self) {
        if let Some(last_command) = self.last_command {
            self.last_command = Some(last_command + 1);
        } else {
            self.last_command = Some(0)
        }
    }
}

impl Default for DataUpgradeInfo {
    fn default() -> Self {
        Self {
            to_krill_version: KrillVersion::code_version(),
            last_command: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UpgradeMode {
    PrepareOnly,
    PrepareToFinalise,
}

impl UpgradeMode {
    pub fn is_prepare_only(&self) -> bool {
        matches!(*self, UpgradeMode::PrepareOnly)
    }

    pub fn is_finalise(&self) -> bool {
        matches!(*self, UpgradeMode::PrepareToFinalise)
    }
}

//------------ UnconvertedEffect ---------------------------------------------

pub enum UnconvertedEffect<T> {
    Error { msg: String },
    Success { events: Vec<T> },
}

//------------ UpgradeStore --------------------------------------------------

/// Implement this for automatic upgrades to key stores
pub trait UpgradeAggregateStorePre0_14 {
    type Aggregate: Aggregate;

    type OldInitEvent: fmt::Display + Eq + PartialEq + Storable + 'static;
    type OldEvent: fmt::Display + Eq + PartialEq + Storable + 'static;
    type OldStorableDetails: WithStorableDetails;

    //--- Mandatory functions to implement

    fn store_name(&self) -> &str;

    fn deployed_store(&self) -> &KeyValueStore;

    fn preparation_key_value_store(&self) -> &KeyValueStore;

    fn preparation_aggregate_store(&self) -> &AggregateStore<Self::Aggregate>;

    /// Implement this to convert the old init event to a new
    /// StoredCommand for the init.
    fn convert_init_event(
        &self,
        old_init: Self::OldInitEvent,
        handle: MyHandle,
        actor: String,
        time: Time,
    ) -> UpgradeResult<StoredCommand<Self::Aggregate>>;

    /// Implement this to convert an old command and convert the
    /// included old events.
    ///
    /// Implementers may decide that the command does not need to
    /// be preserved - if it has become irrelevant (may be needed
    /// for the ASPA migration wrt AFI limit stuff in particular).
    ///
    /// The version for the new command is given, as it might differ
    /// from the old command sequence.
    fn convert_old_command(
        &self,
        old_command: OldStoredCommand<Self::OldStorableDetails>,
        old_effect: UnconvertedEffect<Self::OldEvent>,
        version: u64,
    ) -> UpgradeResult<Option<StoredCommand<Self::Aggregate>>>;

    /// Override this to get a call when the migration of commands for
    /// an aggregate is done.
    fn post_command_migration(&self, handle: &MyHandle) -> UpgradeResult<()> {
        trace!("default post migration hook called for '{handle}'");
        Ok(())
    }

    /// Upgrades pre 0.14.x AggregateStore.
    ///
    /// Expects implementers of this trait to provide function for converting
    /// old command/event/init types to the current types.
    fn upgrade(&self, mode: UpgradeMode) -> UpgradeResult<()> {
        // check existing version, wipe it if there is an unfinished upgrade
        // in progress for another Krill version.
        self.preparation_store_prepare()?;

        info!(
            "Prepare upgrading {} to Krill version {}",
            self.store_name(),
            KRILL_VERSION
        );

        // Migrate the event sourced data for each scope and create new snapshots
        for scope in self.deployed_store().scopes()? {
            // Getting the Handle should never fail, but if it does then we should bail out asap.
            let handle = MyHandle::from_str(&scope.to_string())
                .map_err(|_| UpgradeError::Custom(format!("Found invalid handle '{}'", scope)))?;

            // Get the upgrade info to see where we got to.
            // We may be continuing from an earlier migration, e.g. by krillup.

            let mut data_upgrade_info = self.data_upgrade_info(&scope)?;

            // Get the list of commands to prepare, starting with the last_command we got to (may be 0)
            let old_cmd_keys = self.command_keys(&scope, data_upgrade_info.last_command.unwrap_or(0))?;

            // Migrate the initialisation event, if not done in a previous run. This
            // is a special event that has no command, so we need to do this separately.
            if data_upgrade_info.last_command.is_none() {
                let old_init_key = Self::event_key(scope.clone(), 0);

                let old_init: OldStoredEvent<Self::OldInitEvent> = self.get(&old_init_key)?;
                let old_init = old_init.into_details();

                // From 0.14.x and up we will have command '0' for the init, where beforehand
                // we only had an event. We will have to make up some values for the actor and time.
                let actor = Actor::system_actor().to_string();

                // The time is tricky.. our best guess is to set this to the same
                // value as the first command, if there is any. In the very unlikely
                // case that there is no first command, then we might as well set
                // it to now.
                let time = if let Some(first_command) = old_cmd_keys.first() {
                    let cmd: OldStoredCommand<Self::OldStorableDetails> = self.get(first_command)?;
                    cmd.time()
                } else {
                    Time::now()
                };

                // We need to ask the implementer of this trait to convert the
                // init event we found to a StoredCommand that we can save.
                let command = self.convert_init_event(old_init, handle.clone(), actor, time)?;

                self.store_new_command(&scope, &command)?;
                data_upgrade_info.increment_command();
            }

            // Track commands migrated and time spent so we can report progress
            let mut total_migrated = 0;
            let total_commands = old_cmd_keys.len(); // excludes migrated commands
            let time_started = Time::now();

            // Report the amount of (remaining) work (old)
            Self::report_remaining_work(total_commands, &handle, &data_upgrade_info)?;

            // Process remaining commands
            for old_cmd_key in old_cmd_keys {
                // Read and parse the command.
                let old_command: OldStoredCommand<Self::OldStorableDetails> = self.get(&old_cmd_key)?;

                // And the unconverted effects
                let old_effect = match old_command.effect() {
                    OldStoredEffect::Success { events } => {
                        let mut full_events: Vec<Self::OldEvent> = vec![]; // We just had numbers, we need to include the full events
                        for v in events {
                            let event_key = Self::event_key(scope.clone(), *v);
                            trace!("  +- event: {}", event_key);
                            let evt: OldStoredEvent<Self::OldEvent> =
                                self.deployed_store().get(&event_key)?.ok_or_else(|| {
                                    UpgradeError::Custom(format!("Cannot parse old event: {}", event_key))
                                })?;
                            full_events.push(evt.into_details());
                        }
                        UnconvertedEffect::Success { events: full_events }
                    }
                    OldStoredEffect::Error { msg } => UnconvertedEffect::Error { msg: msg.clone() },
                };

                if let Some(command) =
                    self.convert_old_command(old_command, old_effect, data_upgrade_info.next_command())?
                {
                    self.store_new_command(&scope, &command)?;
                    data_upgrade_info.increment_command();
                }

                // Report progress and expected time to finish on every 100 commands evaluated.
                total_migrated += 1;
                if total_migrated % 100 == 0 {
                    // expected time: (total_migrated / (now - started)) * total

                    let mut time_passed = (Time::now().timestamp() - time_started.timestamp()) as usize;
                    if time_passed == 0 {
                        time_passed = 1; // avoid divide by zero.. we are doing approximate estimates here
                    }
                    let migrated_per_second: f64 = total_migrated as f64 / time_passed as f64;
                    let expected_seconds = (total_commands as f64 / migrated_per_second) as i64;
                    let eta = time_started + chrono::Duration::seconds(expected_seconds);
                    info!(
                        "  migrated {} commands, expect to finish: {}",
                        total_migrated,
                        eta.to_rfc3339()
                    );
                }
            }

            info!("Finished migrating commands for '{}'", scope);

            // Verify migration
            info!(
                "Will verify the migration by rebuilding '{}' from migrated commands",
                &scope
            );
            let latest = self.preparation_aggregate_store().get_latest(&handle).map_err(|e| {
                UpgradeError::Custom(format!(
                    "Could not rebuild state after migrating CA '{}'! Error was: {}.",
                    handle, e
                ))
            })?;

            // Store snapshot to avoid having to re-process the deltas again in future
            self.preparation_aggregate_store()
                .store_snapshot(&handle, latest.as_ref())
                .map_err(|e| {
                    UpgradeError::Custom(format!(
                        "Could not save snapshot for CA '{}' after migration! Disk full?!? Error was: {}.",
                        handle, e
                    ))
                })?;

            // Call the post command migration hook, this will do nothing
            // unless the implementer of this trait overrode it.
            self.post_command_migration(&handle)?;

            // Update the upgrade info as this could be a prepare only
            // run, and this migration could be resumed later after more
            // changes were applied.
            self.update_data_upgrade_info(&scope, &data_upgrade_info)?;

            info!("Verified migration of '{}'", handle);
        }

        match mode {
            UpgradeMode::PrepareOnly => {
                info!(
                    "Prepared migrating data to Krill version {}. Will save progress for final upgrade when Krill restarts.",
                    KRILL_VERSION
                );
            }
            UpgradeMode::PrepareToFinalise => {
                self.clean_migration_help_files()?;
                info!("Prepared migrating data to Krill version {}.", KRILL_VERSION);
            }
        }

        Ok(())
    }

    //-- Internal helper functions for this trait. Should not be used or
    //   overridden.

    /// Saves the version of the target upgrade. Wipes the store if there is another
    /// version set as the target.
    fn preparation_store_prepare(&self) -> UpgradeResult<()> {
        let code_version = KrillVersion::code_version();
        let version_key = Key::new_global(segment!("version"));

        if let Ok(Some(existing_migration_version)) =
            self.preparation_key_value_store().get::<KrillVersion>(&version_key)
        {
            if existing_migration_version != code_version {
                warn!("Found prepared data for Krill version {existing_migration_version}, will remove it and start from scratch for {code_version}");
                self.preparation_key_value_store().wipe()?;
            }
        }

        self.preparation_key_value_store().store(&version_key, &code_version)?;

        Ok(())
    }

    fn report_remaining_work(
        total_remaining: usize,
        handle: &MyHandle,
        data_upgrade_info: &DataUpgradeInfo,
    ) -> UpgradeResult<()> {
        // Unwrap is safe here, because if there was no last_command
        // then we would have converted the init event above, and would
        // have set this.
        let last_command = data_upgrade_info.last_command.ok_or(UpgradeError::custom(
            "called report_remaining_work before converting init event",
        ))?;

        if last_command == 0 {
            info!("Will migrate {} commands for '{}'", total_remaining, handle);
        } else {
            info!(
                "Will resume migration of {} remaining commands for '{}'",
                total_remaining, handle
            );
        }

        Ok(())
    }

    fn store_new_command(&self, scope: &Scope, command: &StoredCommand<Self::Aggregate>) -> UpgradeResult<()> {
        let key = Self::new_stored_command_key(scope.clone(), command.version());
        self.preparation_key_value_store()
            .store_new(&key, command)
            .map_err(UpgradeError::KeyStoreError)
    }

    fn data_upgrade_info_key(scope: Scope) -> Key {
        Key::new_scoped(scope, segment!("upgrade_info.json"))
    }

    /// Return the DataUpgradeInfo telling us to where we got to with this migration.
    fn data_upgrade_info(&self, scope: &Scope) -> UpgradeResult<DataUpgradeInfo> {
        self.preparation_key_value_store()
            .get(&Self::data_upgrade_info_key(scope.clone()))
            .map(|opt| match opt {
                None => DataUpgradeInfo::default(),
                Some(info) => info,
            })
            .map_err(UpgradeError::KeyStoreError)
    }

    /// Update the DataUpgradeInfo
    fn update_data_upgrade_info(&self, scope: &Scope, info: &DataUpgradeInfo) -> UpgradeResult<()> {
        self.preparation_key_value_store()
            .store(&Self::data_upgrade_info_key(scope.clone()), info)
            .map_err(UpgradeError::KeyStoreError)
    }

    /// Clean up keys used for tracking migration progress
    fn clean_migration_help_files(&self) -> UpgradeResult<()> {
        let version_key = Key::new_global(segment!("version"));
        self.preparation_key_value_store()
            .drop_key(&version_key)
            .map_err(UpgradeError::KeyStoreError)?;

        for scope in self.preparation_key_value_store().scopes()? {
            self.preparation_key_value_store()
                .drop_key(&Self::data_upgrade_info_key(scope))
                .map_err(UpgradeError::KeyStoreError)?;
        }
        Ok(())
    }

    /// Find all command keys for the scope, starting from the provided sequence. Then sort them
    /// by sequence and turn them back into key store keys for further processing.
    fn command_keys(&self, scope: &Scope, from: u64) -> Result<Vec<Key>, UpgradeError> {
        let keys = self.deployed_store().keys(scope, "command--")?;
        let mut cmd_keys: Vec<OldCommandKey> = vec![];
        for key in keys {
            let cmd_key = OldCommandKey::from_str(key.name().as_str()).map_err(|_| {
                UpgradeError::Custom(format!("Found invalid command key: {} for ca: {}", key.name(), scope))
            })?;
            if cmd_key.sequence > from {
                cmd_keys.push(cmd_key);
            }
        }
        cmd_keys.sort_by_key(|k| k.sequence);
        let cmd_keys = cmd_keys
            .into_iter()
            .map(|ck| Key::new_scoped(scope.clone(), Segment::parse_lossy(&format!("{}.json", ck)))) // ck should always be a valid Segment
            .collect();

        Ok(cmd_keys)
    }

    fn get<V: DeserializeOwned>(&self, key: &Key) -> Result<V, UpgradeError> {
        self.deployed_store()
            .get(key)?
            .ok_or_else(|| UpgradeError::Custom(format!("Cannot read key: {}", key)))
    }

    fn event_key(scope: Scope, nr: u64) -> Key {
        // cannot panic as a u64 cannot contain a Scope::SEPARATOR
        Key::new_scoped(scope, Segment::parse(&format!("delta-{nr}.json")).unwrap())
    }

    fn new_stored_command_key(scope: Scope, version: u64) -> Key {
        Key::new_scoped(scope, Segment::parse(&format!("command-{version}.json")).unwrap())
    }
}

/// Prepares a Krill upgrade related data migration. If no data migration is needed
/// then this will simply be a no-op. Returns the [`KrillUpgradeVersions`] if the currently
/// deployed Krill version differs from the code version. Note that the version may
/// have increased even if there is no data migration needed.
///
/// In case data needs to be migrated, then new data will be prepared under
/// the directory returned by `config.storage_uri()`. By design, this migration can be
/// executed while Krill is running as it does not affect any current state. It can
/// be called multiple times and it will resume the migration from the point it got
/// to earlier. The idea is that this will allow operators to prepare the work for
/// a migration and (a) verify that the migration worked, and (b) minimize the downtime
/// when Krill is restarted into a new version. When a new version Krill daemon is
/// started, it will call this again - to do the final preparation for a migration -
/// knowing that no changes are added to the event history at this time. After this,
/// the migration will be finalised.
pub fn prepare_upgrade_data_migrations(
    mode: UpgradeMode,
    config: &Config,
    properties_manager: &PropertiesManager,
) -> UpgradeResult<Option<UpgradeReport>> {
    // First of all ALWAYS check the existing keys if the hsm feature is enabled.
    // Remember that this feature - although enabled by default from 0.10.x - may be enabled by installing
    // a new krill binary of the same Krill version as the the previous binary. In other words, we cannot
    // rely on the KrillVersion to decide whether this is needed. On the other hand.. this is a fairly
    // cheap operation that we can just do at startup. It is done here, because in effect it *is* a data
    // migration.
    #[cfg(feature = "hsm")]
    record_preexisting_openssl_keys_in_signer_mapper(config)?;

    match upgrade_versions(config, properties_manager)? {
        None => Ok(None),
        Some(versions) => {
            info!("Preparing upgrade from {} to {}", versions.from(), versions.to());

            // Check if there is any CA named "ta". If so, then we are trying to upgrade a Krill testbed
            // or benchmark set up that uses the old deprecated trust anchor set up. These TAs cannot easily
            // be migrated to the new setup in 0.13.0. Well.. it could be done, if there would be a strong use
            // case to put in the effort, but there really isn't.
            let ca_kv_store = KeyValueStore::create(&config.storage_uri, CASERVER_NS)?;
            if ca_kv_store.has_scope(&Scope::from_segment(segment!("ta")))? {
                return Err(UpgradeError::OldTaMigration);
            }

            if versions.from < KrillVersion::release(0, 6, 0) {
                let msg = "Cannot upgrade Krill installations from before version 0.6.0. Please upgrade to 0.8.1 first, then upgrade to 0.12.3, and then upgrade to this version.";
                error!("{}", msg);
                Err(UpgradeError::custom(msg))
            } else if versions.from < KrillVersion::release(0, 9, 0) {
                let msg = "Cannot upgrade Krill installations from before version 0.9.0. Please upgrade to 0.12.3 first, and then upgrade to this version.";
                error!("{}", msg);
                Err(UpgradeError::custom(msg))
            } else if versions.from < KrillVersion::candidate(0, 10, 0, 1) {
                // Get a lock to ensure that only one process can run this migration
                // at any one time (for a given config).
                let _lock = {
                    // Note that all version before 0.14.0 were using disk based storage
                    // and we only support migration to database storage *after* upgrading.
                    // So.. it is safe to unwrap the storage_uri into a data dir here. We
                    // would not be here otherwise.
                    let data_dir = data_dir_from_storage_uri(&config.storage_uri).unwrap();

                    // Create upgrade dir if it did not yet exist.
                    let lock_file_path = data_dir.join("upgrade.lock");
                    fslock::LockFile::open(&lock_file_path).map_err(|_| {
                        UpgradeError::custom(
                            format!("Cannot get upgrade lock. Another process may be running a Krill upgrade. Or, perhaps you ran 'krillup' as root - in that case check the ownership of directory: {}", data_dir.to_string_lossy()),
                        )
                    })?
                };

                // Complex migrations involving command / event conversions
                pre_0_10_0::PublicationServerRepositoryAccessMigration::upgrade(mode, config, &versions)?;
                pre_0_10_0::CasMigration::upgrade(mode, config)?;

                // The way that pubd objects were stored was changed as well (since 0.13.0)
                migrate_pre_0_12_pubd_objects(config)?;

                // Migrate remaining aggregate stores used in < 0.10.0 to the new format
                // in 0.14.0 where we combine commands and events into a single key-value pair.
                pre_0_14_0::UpgradeAggregateStoreSignerInfo::upgrade(SIGNERS_NS, mode, config)?;

                Ok(Some(UpgradeReport::new(true, versions)))
            } else if versions.from < KrillVersion::candidate(0, 10, 0, 3) {
                Err(UpgradeError::custom(
                    "Cannot upgrade from 0.10.0 RC1 or RC2. Please contact rpki-team@nlnetlabs.nl",
                ))
            } else if versions.from < KrillVersion::candidate(0, 12, 0, 2) {
                info!(
                    "Krill upgrade from {} to {}. Check if publication server objects need migration.",
                    versions.from(),
                    versions.to()
                );

                // The pubd objects storage changed in 0.13.0
                migrate_pre_0_12_pubd_objects(config)?;

                // Migrate aggregate stores used in < 0.12.0 to the new format in 0.14.0 where
                // we combine commands and events into a single key-value pair.
                pre_0_14_0::UpgradeAggregateStoreSignerInfo::upgrade(SIGNERS_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreCertAuth::upgrade(CASERVER_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreRepositoryAccess::upgrade(PUBSERVER_NS, mode, config)?;

                Ok(Some(UpgradeReport::new(true, versions)))
            } else if versions.from < KrillVersion::candidate(0, 13, 0, 0) {
                migrate_0_12_pubd_objects(config)?;

                // Migrate aggregate stores used in < 0.13.0 to the new format in 0.14.0 where
                // we combine commands and events into a single key-value pair.
                pre_0_14_0::UpgradeAggregateStoreSignerInfo::upgrade(SIGNERS_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreCertAuth::upgrade(CASERVER_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreRepositoryAccess::upgrade(PUBSERVER_NS, mode, config)?;

                Ok(Some(UpgradeReport::new(true, versions)))
            } else if versions.from < KrillVersion::candidate(0, 14, 0, 0) {
                // Migrate aggregate stores used in < 0.14.0 to the new format in 0.14.0 where
                // we combine commands and events into a single key-value pair.
                pre_0_14_0::UpgradeAggregateStoreCertAuth::upgrade(CASERVER_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreRepositoryAccess::upgrade(PUBSERVER_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreSignerInfo::upgrade(SIGNERS_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreTrustAnchorSigner::upgrade(TA_SIGNER_SERVER_NS, mode, config)?;
                pre_0_14_0::UpgradeAggregateStoreTrustAnchorProxy::upgrade(TA_PROXY_SERVER_NS, mode, config)?;

                Ok(Some(UpgradeReport::new(true, versions)))
            } else {
                Ok(Some(UpgradeReport::new(false, versions)))
            }
        }
    }
}

/// Migrate v0.12.x RepositoryContent to the new 0.13.0+ format.
/// Apply any open WAL changes to the source first.
fn migrate_0_12_pubd_objects(config: &Config) -> KrillResult<bool> {
    let data_dir = data_dir_from_storage_uri(&config.storage_uri).unwrap();
    let old_repo_content_dir = data_dir.join(PUBSERVER_CONTENT_NS.as_str());
    if old_repo_content_dir.exists() {
        let old_store: WalStore<OldRepositoryContent> = WalStore::create(&config.storage_uri, PUBSERVER_CONTENT_NS)?;
        let repo_content_handle = MyHandle::new("0".into());

        if old_store.has(&repo_content_handle)? {
            let old_repo_content = old_store.get_latest(&repo_content_handle)?.as_ref().clone();
            let repo_content: pubd::RepositoryContent = old_repo_content.try_into()?;
            let new_key = Key::new_scoped(Scope::from_segment(segment!("0")), segment!("snapshot.json"));
            let upgrade_store = KeyValueStore::create_upgrade_store(&config.storage_uri, PUBSERVER_CONTENT_NS)?;
            upgrade_store.store(&new_key, &repo_content)?;
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        Ok(false)
    }
}

/// The format of the RepositoryContent did not change in 0.12, but
/// the location and way of storing it did. So, migrate if present.
fn migrate_pre_0_12_pubd_objects(config: &Config) -> KrillResult<()> {
    let data_dir = data_dir_from_storage_uri(&config.storage_uri).unwrap();
    let old_repo_content_dir = data_dir.join(PUBSERVER_CONTENT_NS.as_str());
    if old_repo_content_dir.exists() {
        let old_store = KeyValueStore::create(&config.storage_uri, PUBSERVER_CONTENT_NS)?;
        let old_key = Key::new_global(segment!("0.json"));
        if let Ok(Some(old_repo_content)) = old_store.get::<pre_0_13_0::OldRepositoryContent>(&old_key) {
            info!("Found pre 0.12.0 RC2 publication server data. Migrating..");
            let repo_content: pubd::RepositoryContent = old_repo_content.try_into()?;

            let new_key = Key::new_scoped(Scope::from_segment(segment!("0")), segment!("snapshot.json"));
            let upgrade_store = KeyValueStore::create_upgrade_store(&config.storage_uri, PUBSERVER_CONTENT_NS)?;
            upgrade_store.store(&new_key, &repo_content)?;
        }
    }
    Ok(())
}

/// Finalise the data migration for an upgrade.
///
/// If there is any prepared data, then:
/// - archive the current data
/// - make the prepared data current
pub fn finalise_data_migration(
    upgrade: &UpgradeVersions,
    config: &Config,
    properties_manager: &PropertiesManager,
) -> KrillResult<()> {
    if upgrade.from >= KrillVersion::candidate(0, 14, 0, 0) {
        // Not supported yet, we will need to implement changing the
        // namespace in kvx::KeyValueStore.
        //
        // When this is done then we can use the same logic for any
        // storage implementation used (disk/db).
        todo!("Support migrations from 0.14.x and higher migrations");
    } else {
        info!(
            "Finish data migrations for upgrade from {} to {}",
            upgrade.from(),
            upgrade.to()
        );

        // Krill versions before 0.14.x *always* used disk based storage.
        //
        // So, we should always get some data dir from the current config
        // when upgrading from a a version before 0.14.x.
        //
        // Furthermore, now that we are storing the version in one single
        // place, we can remove the "version" file from any directory that
        // remains after migration.
        if let Some(data_dir) = data_dir_from_storage_uri(&config.storage_uri) {
            let archive_base_dir = data_dir.join(&format!("archive-{}", upgrade.from()));
            let upgrade_base_dir = data_dir.join("upgrade-data");

            for ns in &[
                CASERVER_NS,
                CA_OBJECTS_NS,
                KEYS_NS,
                PUBSERVER_CONTENT_NS,
                PUBSERVER_NS,
                SIGNERS_NS,
                STATUS_NS,
                TA_PROXY_SERVER_NS,
                TA_SIGNER_SERVER_NS,
            ] {
                // Data structure is as follows:
                //
                //   data_dir/
                //            upgrade-data/      --> upgraded (may be missing)
                //                         ns1,
                //                         ns2,
                //                         etc
                //             ns1, --> current
                //             ns2,
                //             etc
                //
                //             archive-prev-v/   --> archived current dirs which were upgraded
                //
                let upgraded_dir = upgrade_base_dir.join(ns.as_str());
                let archive_dir = archive_base_dir.join(ns.as_str());
                let current_dir = data_dir.join(ns.as_str());

                if upgraded_dir.exists() {
                    // Data was prepared. So we archive the current data and
                    // then move the prepped data.
                    move_dir(&current_dir, &archive_dir)?;
                    move_dir(&upgraded_dir, &current_dir)?;
                } else if current_dir.exists() {
                    // There was no new data for this directory. But, we make a backup
                    // so that we can have a consistent data set to fall back to in case
                    // of a downgrade.
                    file::backup_dir(&current_dir, &archive_dir).map_err(|e| {
                        Error::Custom(format!(
                            "Could not backup directory {} to {} after migration: {}",
                            current_dir.to_string_lossy(),
                            archive_dir.to_string_lossy(),
                            e
                        ))
                    })?;
                }

                let version_file = current_dir.join("version");
                if version_file.exists() {
                    debug!(
                        "Removing (no longer used) version file: {}",
                        version_file.to_string_lossy()
                    );
                    std::fs::remove_file(&version_file).map_err(|e| {
                        let context = format!(
                            "Could not remove (no longer used) version file at: {}",
                            version_file.to_string_lossy(),
                        );
                        Error::IoError(KrillIoError::new(context, e))
                    })?;
                }
            }

            // remove the upgrade base dir - if it's empty - so ignore error.
            let _ = fs::remove_dir(&upgrade_base_dir);
        }

        // move the dirs
        fn move_dir(from: &Path, to: &Path) -> KrillResult<()> {
            if let Some(parent) = to.parent() {
                if !parent.exists() {
                    file::create_dir_all(parent).map_err(Error::IoError)?;
                }
            }
            std::fs::rename(from, to).map_err(|e| {
                let context = format!(
                    "Could not rename directory from: {} to: {}.",
                    from.to_string_lossy(),
                    to.to_string_lossy()
                );
                Error::IoError(KrillIoError::new(context, e))
            })
        }
    }

    // Remove version files that are no longer required
    if let Some(data_dir) = data_dir_from_storage_uri(&config.storage_uri) {
        for ns in &[
            CASERVER_NS,
            CA_OBJECTS_NS,
            KEYS_NS,
            PUBSERVER_CONTENT_NS,
            PUBSERVER_NS,
            SIGNERS_NS,
            STATUS_NS,
            TA_PROXY_SERVER_NS,
            TA_SIGNER_SERVER_NS,
        ] {
            let path = data_dir.join(ns.as_str()).join("version");
            if path.exists() {
                debug!("Removing version excess file: {}", path.to_string_lossy());
                std::fs::remove_file(&path).map_err(|e| {
                    let context = format!("Could not remove old version file at: {}", path.to_string_lossy(),);
                    Error::IoError(KrillIoError::new(context, e))
                })?;
            }
        }
    }

    // Set the current version of the store to that of the running code
    let code_version = KrillVersion::code_version();
    info!("Finished upgrading Krill to version: {code_version}");
    if properties_manager.is_initialized() {
        properties_manager.upgrade_krill_version(code_version)?;
    } else {
        properties_manager.init(code_version)?;
    }

    Ok(())
}

/// Prior to Krill having HSM support there was no signer mapper as it wasn't needed, keys were just created by OpenSSL
/// and stored in files on disk in KEYS_NS named by the string form of their Krill KeyIdentifier. If Krill had created
/// such keys and then the operator upgrades to a version of Krill with HSM support, the keys will become unusable
/// because Krill will not be able to find a mapping from KeyIdentifier to signer as the mappings for the keys were
/// never created. So we detect the case that the signer store SIGNERS_DIR directory has not yet been created, i.e. no
/// signers have been registered and no key mappings have been recorded, and then walk KEYS_NS adding the keys one by
/// one to the mapping in the signer store, if any.
#[cfg(feature = "hsm")]
fn record_preexisting_openssl_keys_in_signer_mapper(config: &Config) -> Result<(), UpgradeError> {
    match data_dir_from_storage_uri(&config.storage_uri) {
        None => Ok(()),
        Some(data_dir) => {
            if !data_dir.join(SIGNERS_NS.as_str()).exists() {
                let mut num_recorded_keys = 0;
                let keys_dir = data_dir.join(KEYS_NS.as_str());

                info!(
                    "Scanning for not yet mapped OpenSSL signer keys in {} to record in the signer store",
                    keys_dir.to_string_lossy()
                );

                let probe_interval = Duration::from_secs(config.signer_probe_retry_seconds);
                let krill_signer = KrillSignerBuilder::new(&config.storage_uri, probe_interval, &config.signers)
                    .with_default_signer(config.default_signer())
                    .with_one_off_signer(config.one_off_signer())
                    .build()
                    .unwrap();

                // For every file (key) in the legacy OpenSSL signer keys directory
                if let Ok(dir_iter) = keys_dir.read_dir() {
                    let mut openssl_signer_handle: Option<SignerHandle> = None;

                    for entry in dir_iter {
                        let entry = entry.map_err(|err| {
                            UpgradeError::IoError(KrillIoError::new(
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
                                if krill_signer.get_key_info(&key_id).is_err() {
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
                                            mapper.add_key(signer_handle, &key_id, &internal_key_id)?;
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
    }
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

/// Checks if we should upgrade:
///  - if the code is newer than the version used then we upgrade
///  - if the code is the same version then we do not upgrade
///  - if the code is older then we need to error out
fn upgrade_versions(
    config: &Config,
    properties_manager: &PropertiesManager,
) -> Result<Option<UpgradeVersions>, UpgradeError> {
    if let Ok(current) = properties_manager.current_krill_version() {
        // We found the KrillVersion stored in the properties manager
        // introduced in Krill 0.14.0.
        UpgradeVersions::for_current(current)
    } else if let Some(data_dir) = data_dir_from_storage_uri(&config.storage_uri) {
        // If the disk is used for storage, then we need to check
        // if there are any pre Krill 0.14.0 version files in the
        // usual places. If so, then this is an upgrade.
        //
        // If there are no such files, then we know that this is a
        // new clean installation. Otherwise, we would have found
        // the properties_manager.current_krill_version().
        let mut current = None;

        // So.. try to find the most recent version among those files
        // in as far as they exist.
        for ns in &[CASERVER_NS, PUBSERVER_NS, PUBSERVER_CONTENT_NS] {
            let path = data_dir.join(ns.as_str()).join("version");
            if let Ok(bytes) = file::read(&path) {
                if let Ok(new_version_seen_on_disk) = serde_json::from_slice::<KrillVersion>(&bytes) {
                    if let Some(previous_seen_on_disk) = current.clone() {
                        if new_version_seen_on_disk > previous_seen_on_disk {
                            current = Some(new_version_seen_on_disk);
                        }
                    } else {
                        current = Some(new_version_seen_on_disk);
                    }
                }
            }
        }

        match current {
            None => {
                info!("Clean installation for Krill version {}", KrillVersion::code_version());
                Ok(None)
            }
            Some(current) => UpgradeVersions::for_current(current),
        }
    } else {
        // No disk was used. We do not support upgrading from <0.14.0 to 0.14.0 or
        // above AND migrating to a database at the same time. If users want this
        // then they should first upgrade using disk based storage and then migrate
        // the data content to a new storage option. See issue #1079
        info!(
            "Clean installation using database storage for Krill version {}",
            KrillVersion::code_version()
        );
        info!("NOTE: if you meant to upgrade an existing Krill <0.14.0 installation");
        info!("      then you should stop this instance, clear the new database, then");
        info!("      upgrade your old installation using the disk as a storage option,");
        info!("      and then migrate your data to a database.");
        Ok(None)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        commons::util::{file, storage::storage_uri_from_data_dir},
        test::tmp_dir,
    };

    use super::*;

    async fn test_upgrade(source: PathBuf) {
        let (data_dir, cleanup) = tmp_dir();
        let storage_uri = storage_uri_from_data_dir(&data_dir).unwrap();
        file::backup_dir(&source, &data_dir).unwrap();

        let config = Config::test(&storage_uri, Some(&data_dir), false, false, false, false);
        let _ = config.init_logging();

        let properties_manager = PropertiesManager::create(&config.storage_uri, config.use_history_cache).unwrap();

        prepare_upgrade_data_migrations(UpgradeMode::PrepareOnly, &config, &properties_manager)
            .unwrap()
            .unwrap();

        // and continue - immediately, but still tests that this can pick up again.
        let report = prepare_upgrade_data_migrations(UpgradeMode::PrepareToFinalise, &config, &properties_manager)
            .unwrap()
            .unwrap();

        finalise_data_migration(report.versions(), &config, &properties_manager).unwrap();

        cleanup();
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_9_5() {
        let source = PathBuf::from("test-resources/migrations/v0_9_5/");
        test_upgrade(source).await;
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_12_1() {
        let source = PathBuf::from("test-resources/migrations/v0_12_1/");
        test_upgrade(source).await;
    }

    #[tokio::test]
    async fn prepare_then_upgrade_0_13_0() {
        let source = PathBuf::from("test-resources/migrations/v0_13_1/");
        test_upgrade(source).await;
    }

    #[test]
    fn parse_0_10_0_rc3_repository_content() {
        let json = include_str!("../../test-resources/migrations/v0_10_0/0.json");
        let _repo: pre_0_13_0::OldRepositoryContent = serde_json::from_str(json).unwrap();
    }

    #[cfg(all(feature = "hsm", not(any(feature = "hsm-tests-kmip", feature = "hsm-tests-pkcs11"))))]
    fn unmapped_keys_test_core(do_upgrade: bool) {
        let expected_key_id = KeyIdentifier::from_str("5CBCAB14B810C864F3EEA8FD102B79F4E53FCC70").unwrap();

        // Place a key previously created by an OpenSSL signer in the KEYS_NS under the Krill data dir.
        // Then run the upgrade. It should find the key and add it to the mapper.
        let (data_dir, cleanup) = tmp_dir();
        let storage_uri = storage_uri_from_data_dir(&data_dir).unwrap();
        let source = PathBuf::from("test-resources/migrations/unmapped_keys/");
        file::backup_dir(&source, &data_dir).unwrap();

        let mut config = Config::test(&storage_uri, Some(&data_dir), false, false, false, false);
        let _ = config.init_logging();
        config.process().unwrap();

        if do_upgrade {
            record_preexisting_openssl_keys_in_signer_mapper(&config).unwrap();
        }

        // Now test that a newly initialized `KrillSigner` with a default OpenSSL signer
        // is associated with the newly created mapper store and is thus able to use the
        // key that we placed on disk.
        let probe_interval = Duration::from_secs(config.signer_probe_retry_seconds);
        let krill_signer = KrillSignerBuilder::new(&storage_uri, probe_interval, &config.signers)
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
            assert!(mapper.get_signer_for_key(&expected_key_id).is_ok());
        } else {
            // Verify that the mapper does NOT have a record of the test key belonging to the signer
            assert!(mapper.get_signer_for_key(&expected_key_id).is_err());
        }

        cleanup();
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
