use std::{convert::TryInto, str::FromStr};

use chrono::Duration;
use rpki::{ca::idexchange::CaHandle, repository::x509::Time};

use crate::daemon::ca::CaObjects;
use crate::upgrades::OldStoredCommand;
use crate::{
    commons::{
        api::CertAuthStorableCommand,
        eventsourcing::{segment, AggregateStore, Key, KeyValueStore, Segment, SegmentExt, StoredValueInfo},
    },
    constants::{CASERVER_NS, CA_OBJECTS_NS, KRILL_VERSION},
    daemon::{
        ca::{CertAuth, CertAuthEvent, CertAuthInitEvent},
        config::Config,
    },
    upgrades::{
        pre_0_10_0::{Pre0_10CertAuthEvent, Pre0_10CertAuthInitEvent},
        PrepareUpgradeError, UpgradeMode, UpgradeResult, UpgradeStore,
    },
};

use super::OldCaObjects;

/// Migrates the CaObjects for a given CA.
///
/// i.e. the CA content which is NOT event-sourced.
struct CaObjectsMigration {
    current_store: KeyValueStore,
    new_store: KeyValueStore,
}

impl CaObjectsMigration {
    fn create(config: &Config) -> Result<Self, PrepareUpgradeError> {
        let current_store = KeyValueStore::create(&config.storage_uri, CA_OBJECTS_NS)?;
        let new_store = KeyValueStore::create(config.upgrade_storage_uri(), CA_OBJECTS_NS)?;
        Ok(CaObjectsMigration {
            current_store,
            new_store,
        })
    }

    fn prepare_new_data_for(&self, ca: &CaHandle) -> Result<(), PrepareUpgradeError> {
        let key = Key::new_global(Segment::parse_lossy(ca.as_str())); // ca should always be a valid Segment

        if let Some(old_objects) = self.current_store.get::<OldCaObjects>(&key)? {
            let converted: CaObjects = old_objects.try_into()?;
            self.new_store.store(&key, &converted)?;
        }

        Ok(())
    }
}

/// Migrates the CAs:
/// - The events, snapshots and info in the AggregateStore
/// - The mutable CaObjects structure
pub struct CasMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<CertAuth>,
    ca_objects_migration: CaObjectsMigration,
}

impl CasMigration {
    pub fn prepare(mode: UpgradeMode, config: &Config) -> UpgradeResult<()> {
        let current_kv_store = KeyValueStore::create(&config.storage_uri, CASERVER_NS)?;
        let new_kv_store = KeyValueStore::create(config.upgrade_storage_uri(), CASERVER_NS)?;
        let new_agg_store = AggregateStore::<CertAuth>::create(
            config.upgrade_storage_uri(),
            CASERVER_NS,
            config.disable_history_cache,
        )?;
        let ca_objects_migration = CaObjectsMigration::create(config)?;

        CasMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
            ca_objects_migration,
        }
        .prepare_new_data(mode)
    }
}

impl UpgradeStore for CasMigration {
    fn prepare_new_data(&self, mode: UpgradeMode) -> Result<(), PrepareUpgradeError> {
        // check existing version, wipe if needed
        self.preparation_store_prepare()?;

        info!(
            "Prepare upgrading CA command and event data to Krill version {}",
            KRILL_VERSION
        );

        // Migrate the event sourced data for each CA and create new snapshots
        for scope in self.current_kv_store.scopes()? {
            // Getting the Handle should never fail, but if it does then we should bail out asap.
            let handle = CaHandle::from_str(&scope.to_string())
                .map_err(|_| PrepareUpgradeError::Custom(format!("Found invalid CA handle '{}'", scope)))?;

            // Get the info from the current store to see where we are
            let mut data_upgrade_info = self.data_upgrade_info(&scope)?;

            // Migrate the initialisation event, if not done in a previous run. This
            // is a special event that has no command, so we need to do this separately.
            if data_upgrade_info.last_event == 0 {
                // Make a new init event.
                let init_key = Self::event_key(scope.clone(), 0);
                let old_init: Pre0_10CertAuthInitEvent = self.get(&init_key).unwrap();
                let old_ini_det = old_init.into_details();
                let ini = CertAuthInitEvent::new(old_ini_det.into());
                self.new_kv_store.store(&init_key, &ini)?;
            }

            // Get the list of commands to prepare, starting with the last_command we got to (may be 0)
            let old_cmd_keys = self.command_keys(&scope, data_upgrade_info.last_command)?;

            // Report the amount of (remaining) work
            let total_commands = old_cmd_keys.len();
            if data_upgrade_info.last_command == 0 {
                info!("Will migrate {} commands for CA '{}'", total_commands, handle);
            } else {
                info!(
                    "Will resume migration of {} remaining commands for CA '{}'",
                    total_commands, handle
                );
            }

            // Get the old info file. We will only migrate commands in the info file
            let info_key = Key::new_scoped(scope.clone(), segment!("info.json"));
            let old_info: StoredValueInfo = self
                .current_kv_store
                .get(&info_key)?
                .ok_or_else(|| PrepareUpgradeError::Custom(format!("Cannot parse old info file: {}", info_key)))?;

            // Track commands migrated and time spent so we can report progress
            let mut total_migrated = 0;
            let time_started = Time::now();

            for cmd_key in old_cmd_keys {
                // Read and parse the command. There is no need to change the command itself,
                // but we need to save it again and get the events from here.
                let cmd: OldStoredCommand<CertAuthStorableCommand> = self.get(&cmd_key)?;

                // Read and parse all events. Migrate the events that contain changed types.
                // In this case IdCert -> IdCertInfo for added publishers. Then save the event
                // again in the migration scope.
                if let Some(event_versions) = cmd.effect().events() {
                    for v in event_versions {
                        let event_key = Self::event_key(scope.clone(), *v);
                        trace!("  +- event: {}", event_key);
                        let evt: Pre0_10CertAuthEvent = self.current_kv_store.get(&event_key)?.ok_or_else(|| {
                            PrepareUpgradeError::Custom(format!("Cannot parse old event: {}", event_key))
                        })?;

                        // Migrate into the current event type and save
                        let old_details = evt.into_details();
                        let evt: CertAuthEvent = old_details.try_into()?;
                        self.new_kv_store.store(&event_key, &evt)?;

                        data_upgrade_info.last_event = *v;
                    }
                }

                // Save the command to the migration
                self.new_kv_store.store(&cmd_key, &cmd)?;

                // Update and save data_upgrade_info for progress tracking
                data_upgrade_info.last_command += 1;
                data_upgrade_info.last_update = cmd.time();
                self.update_data_upgrade_info(&scope, &data_upgrade_info)?;

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
                    let eta = time_started + Duration::seconds(expected_seconds);
                    info!(
                        "  migrated {} commands, expect to finish: {}",
                        total_migrated,
                        eta.to_rfc3339()
                    );
                }
            }

            info!("Finished migrating commands for CA '{}'", scope);

            // Create a new info file for the new aggregate repository
            {
                // Store a new info.json
                //
                // It should have been safe to just copy the old info.json, since
                // we do not exclude commands or event, but this way we can be sure
                // that it is *always* correct for the commands and events which
                // were migrated.
                let info = StoredValueInfo {
                    snapshot_version: data_upgrade_info.last_event + 1,
                    last_event: data_upgrade_info.last_event,
                    last_command: data_upgrade_info.last_command,
                    last_update: data_upgrade_info.last_update,
                };

                self.new_kv_store.store(&info_key, &info)?;

                if mode.is_finalise() {
                    // We expect that all commands and events are migrated without exception.
                    // Otherwise there is a bug in our migration code.
                    if info.last_command != old_info.last_command || info.last_event != old_info.last_event {
                        return Err(PrepareUpgradeError::custom(
                        format!("New info.json does not match old info.json when upgrading CA '{}'. Please downgrade to the previous version and provide a bug report to rpki-team@nlnetlabs.nl.", handle),
                    ));
                    }
                }
            }

            // Verify migration
            info!("Will verify the migration by rebuilding CA '{}' events", &scope);
            let ca = self.new_agg_store.get_latest(&handle).map_err(|e| {
                PrepareUpgradeError::Custom(format!(
                    "Could not rebuild state after migrating CA '{}'! Error was: {}.",
                    handle, e
                ))
            })?;

            // Store snapshot to avoid having to re-process the deltas again in future
            self.new_agg_store.store_snapshot(&handle, ca.as_ref()).map_err(|e| {
                PrepareUpgradeError::Custom(format!(
                    "Could not save snapshot for CA '{}' after migration! Disk full?!? Error was: {}.",
                    handle, e
                ))
            })?;

            // Load the CaObjects for this CA and convert it.
            info!("Will migrate the current repository objects for CA '{}'", handle);
            self.ca_objects_migration.prepare_new_data_for(&handle)?;

            info!("Verified migration of CA '{}'", handle);
        }

        match mode {
            UpgradeMode::PrepareOnly => {
                info!(
                    "Prepared migrating CAs to Krill version {}. Will save progress for final upgrade when Krill restarts.",
                    KRILL_VERSION
                );
            }
            UpgradeMode::PrepareToFinalise => {
                self.clean_migration_help_files()?;
                info!("Prepared migrating CAs to Krill version {}.", KRILL_VERSION);
            }
        }

        Ok(())
    }

    fn deployed_store(&self) -> &KeyValueStore {
        &self.current_kv_store
    }

    fn preparation_store(&self) -> &KeyValueStore {
        &self.new_kv_store
    }
}
