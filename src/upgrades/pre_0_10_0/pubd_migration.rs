use std::str::FromStr;

use chrono::Duration;
use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::{
    commons::{
        api::StorableRepositoryCommand,
        eventsourcing::{AggregateStore, KeyStoreKey, KeyValueStore, StoredCommand, StoredEvent, StoredValueInfo},
        util::KrillVersion,
    },
    constants::{KRILL_VERSION, PUBSERVER_DIR},
    daemon::config::Config,
    pubd::{RepositoryAccess, RepositoryAccessEvent, RepositoryAccessInitDetails},
    upgrades::{pre_0_10_0::OldRepositoryAccessEvent, PrepareUpgradeError, UpgradeMode, UpgradeResult, UpgradeStore},
};

use super::OldRepositoryAccessIni;

/// Migrates the events, snapshots and info for the event-sourced RepositoryAccess.
/// There is no need to migrate the mutable RepositoryContent structure for this migration.
pub struct PublicationServerMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<RepositoryAccess>,
}

impl PublicationServerMigration {
    pub fn prepare(mode: UpgradeMode, config: &Config) -> UpgradeResult<()> {
        let upgrade_data_dir = config.upgrade_data_dir();

        let current_kv_store = KeyValueStore::disk(&config.data_dir, PUBSERVER_DIR)?;
        let new_kv_store = KeyValueStore::disk(&upgrade_data_dir, PUBSERVER_DIR)?;
        let new_agg_store = AggregateStore::disk(&upgrade_data_dir, PUBSERVER_DIR)?;

        PublicationServerMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
        }
        .prepare_new_data(mode)
    }
}

impl UpgradeStore for PublicationServerMigration {
    fn needs_migrate(&self) -> Result<bool, crate::upgrades::PrepareUpgradeError> {
        Ok(self.current_kv_store.version_is_after(KrillVersion::release(0, 9, 0))?
            && self
                .current_kv_store
                .version_is_before(KrillVersion::candidate(0, 10, 0, 1))?)
    }

    fn prepare_new_data(&self, mode: crate::upgrades::UpgradeMode) -> Result<(), crate::upgrades::PrepareUpgradeError> {
        // check existing version, wipe if needed
        self.preparation_store_prepare()?;

        // we only have 1 pubserver '0'
        let scope = "0";
        let handle = MyHandle::from_str(scope).unwrap(); // "0" is always safe

        // Get the info from the current store to see where we are
        let mut data_upgrade_info = self.data_upgrade_info(scope)?;

        // Get the list of commands to prepare, starting with the last_command we got to (may be 0)
        let old_cmd_keys = self.command_keys(scope, data_upgrade_info.last_command)?;

        // Migrate the initialisation event, if not done in a previous run. This
        // is a special event that has no command, so we need to do this separately.
        if data_upgrade_info.last_event == 0 {
            let init_key = Self::event_key(scope, 0);

            let old_init: OldRepositoryAccessIni = self
                .current_kv_store
                .get(&init_key)?
                .ok_or_else(|| PrepareUpgradeError::custom("Cannot read Publication Server init event"))?;

            let (_, _, old_init) = old_init.unpack();
            let init: RepositoryAccessInitDetails = old_init.into();
            let init = StoredEvent::new(&handle, 0, init);
            self.new_kv_store.store(&init_key, &init)?;
        }

        // Report the amount of (remaining) work
        let total_commands = old_cmd_keys.len();
        if data_upgrade_info.last_command == 0 {
            info!("Will migrate {} commands for Publication Server", total_commands);
        } else {
            info!(
                "Will resume migration of {} remaining commands for Publication Server",
                total_commands
            );
        }

        // Get the old info file. We will only migrate commands in the info file
        let info_key = KeyStoreKey::scoped(scope.to_string(), "info.json".to_string());
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
            let cmd: StoredCommand<StorableRepositoryCommand> = self.get(&cmd_key)?;

            // If we encounter a command which is not (yet) covered by the old info file,
            // then we are done for now. This most likely happens in case we are preparing
            // an upgrade with krillup while krill is running.
            //
            // This may also happen in case there was an incomplete transaction, most likely
            // because the old krill was shutdown in the middle.
            if cmd.sequence() > old_info.last_command {
                break;
            }

            // Read and parse all events. Migrate the events that contain changed types.
            // In this case IdCert -> IdCertInfo for added publishers. Then save the event
            // again in the migration scope.
            if let Some(event_versions) = cmd.effect().events() {
                for v in event_versions {
                    let event_key = Self::event_key(scope, *v);
                    trace!("  +- event: {}", event_key);
                    let evt: OldRepositoryAccessEvent = self
                        .current_kv_store
                        .get(&event_key)?
                        .ok_or_else(|| PrepareUpgradeError::Custom(format!("Cannot parse old event: {}", event_key)))?;

                    // Migrate into the current event type and save
                    let evt: RepositoryAccessEvent = evt.into();
                    self.new_kv_store.store(&event_key, &evt)?;

                    data_upgrade_info.last_event = *v;
                }
            }

            // Save the command to the migration
            self.new_kv_store.store(&cmd_key, &cmd)?;

            // Update and save data_upgrade_info for progress tracking
            data_upgrade_info.last_command += 1;
            data_upgrade_info.last_update = cmd.time();
            self.update_data_upgrade_info(scope, &data_upgrade_info)?;

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

        info!("Finished migrating Publication Server commands");

        {
            // Store a new info.json
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
                        "New info.json does not match old info.json when upgrading Publication Server. Please downgrade to the previous version and provide a bug report to rpki-team@nlnetlabs.nl.",
                    ));
                }
            }
        }

        // Verify migration
        info!("Will verify the migration by rebuilding the Publication Server from events");
        let repo_access = self.new_agg_store.get_latest(&handle).map_err(|e| {
            PrepareUpgradeError::Custom(format!(
                "Could not rebuild state after migrating Publication Server! Error was: {}.",
                e
            ))
        })?;

        // Store snapshot to avoid having to re-process the deltas again in future
        self.new_agg_store
            .store_snapshot(&handle, repo_access.as_ref())
            .map_err(|e| {
                PrepareUpgradeError::Custom(format!(
                    "Could not save snapshot after migration! Disk full?!? Error was: {}.",
                    e
                ))
            })?;

        match mode {
            UpgradeMode::PrepareOnly => {
                info!(
                    "Prepared Publication Server data migration to version {}. Will save progress for final upgrade when Krill restarts.",
                    KRILL_VERSION
                );
            }
            UpgradeMode::PrepareToFinalise => {
                info!(
                    "Prepared Publication Server data migration to version {}.",
                    KRILL_VERSION
                );
                self.remove_data_upgrade_info(scope)?;
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
