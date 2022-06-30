use std::convert::TryInto;
use std::str::FromStr;

use chrono::Duration;
use rpki::{ca::idexchange::CaHandle, repository::x509::Time};

use crate::{
    commons::{
        api::StorableCaCommand,
        eventsourcing::{AggregateStore, KeyStoreKey, KeyValueStore, StoredCommand, StoredValueInfo},
        util::KrillVersion,
    },
    constants::{CASERVER_DIR, KRILL_VERSION},
    daemon::{
        ca::{CaEvt, CertAuth, IniDet},
        config::Config,
    },
    upgrades::{
        pre_0_10_0::{OldCaEvt, OldCaIni},
        PrepareUpgradeError, UpgradeMode, UpgradeResult, UpgradeStore,
    },
};

pub struct CasStoreMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<CertAuth>,
}

impl CasStoreMigration {
    pub fn prepare(mode: UpgradeMode, config: &Config) -> UpgradeResult<()> {
        let current_kv_store = KeyValueStore::disk(&config.data_dir, CASERVER_DIR)?;
        let new_kv_store = KeyValueStore::disk(&config.upgrade_data_dir(), CASERVER_DIR)?;
        let new_agg_store = AggregateStore::<CertAuth>::disk(&config.upgrade_data_dir(), CASERVER_DIR)?;

        CasStoreMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
        }
        .prepare_new_data(mode)
    }
}

impl UpgradeStore for CasStoreMigration {
    fn needs_migrate(&self) -> Result<bool, PrepareUpgradeError> {
        Ok(self.current_kv_store.version_is_after(KrillVersion::release(0, 9, 0))?
            && self
                .current_kv_store
                .version_is_before(KrillVersion::candidate(0, 10, 0, 1))?)
    }

    fn prepare_new_data(&self, mode: UpgradeMode) -> Result<(), PrepareUpgradeError> {
        // check existing version, wipe if needed
        self.preparation_store_prepare()?;

        info!(
            "Prepare upgrading CA command and event data to Krill version {}",
            KRILL_VERSION
        );

        // For each CA:
        for scope in self.current_kv_store.scopes()? {
            // Getting the Handle should never fail, but if it does then we should bail out asap.
            let handle = CaHandle::from_str(&scope)
                .map_err(|_| PrepareUpgradeError::Custom(format!("Found invalid CA handle '{}'", scope)))?;

            // Get the info from the current store to see where we are
            let mut data_upgrade_info = self.data_upgrade_info(&scope)?;

            // Migrate the initialisation event, if not done in a previous run. This
            // is a special event that has no command, so we need to do this separately.
            if data_upgrade_info.last_event == 0 {
                // Make a new init event.
                let init_key = Self::event_key(&scope, 0);
                let old_init: OldCaIni = self.get(&init_key)?;
                let (id, _, old_ini_det) = old_init.unpack();
                let ini = IniDet::new(&id, old_ini_det.into());
                self.new_kv_store.store(&init_key, &ini)?;
            }

            // Get the list of commands to prepare, starting with the last_command we got to (may be 0)
            let old_cmd_keys = self.command_keys(&scope, data_upgrade_info.last_command)?;

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

            // Track commands migrated and time spent so we can report progress
            let mut total_migrated = 0;
            let time_started = Time::now();

            for cmd_key in old_cmd_keys {
                // Read and parse the command. There is no need to change the command itself,
                // but we need to save it again and get the events from here.
                let cmd: StoredCommand<StorableCaCommand> = self.get(&cmd_key)?;

                // Read and parse all events. Migrate the events that contain changed types.
                // In this case IdCert -> IdCertInfo for added publishers. Then save the event
                // again in the migration scope.
                if let Some(event_versions) = cmd.effect().events() {
                    for v in event_versions {
                        let event_key = Self::event_key(&scope, *v);
                        trace!("  +- event: {}", event_key);
                        let evt: OldCaEvt = self.current_kv_store.get(&event_key)?.ok_or_else(|| {
                            PrepareUpgradeError::Custom(format!("Cannot parse old event: {}", event_key))
                        })?;

                        // Migrate into the current event type and save
                        let evt: CaEvt = evt.try_into()?;
                        self.new_kv_store.store(&event_key, &evt)?;
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
                let info = StoredValueInfo::from(&data_upgrade_info);
                let info_key = KeyStoreKey::scoped(scope.clone(), "info.json".to_string());
                self.new_kv_store.store(&info_key, &info)?;
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
                info!("Prepared migrating CAs to Krill version {}.", KRILL_VERSION);

                // For each CA clean up the saved data upgrade info file.
                for scope in self.current_kv_store.scopes()? {
                    self.remove_data_upgrade_info(&scope)?;
                }
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
