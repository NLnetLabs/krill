use std::str::FromStr;

use chrono::Duration;
use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::{
    commons::{
        actor::Actor,
        api::StorableRepositoryCommand,
        eventsourcing::{segment, AggregateStore, KeyValueStore, Scope, Segment, StoredCommandBuilder},
        util::KrillVersion,
    },
    constants::{KRILL_VERSION, PUBSERVER_NS},
    daemon::config::Config,
    pubd::{RepositoryAccess, RepositoryAccessEvent, RepositoryAccessInitEvent},
    upgrades::{
        pre_0_10_0::Pre0_10RepositoryAccessEvent, OldStoredCommand, OldStoredEffect, PrepareUpgradeError, UpgradeMode,
        UpgradeResult, UpgradeStore, UpgradeVersions,
    },
};

use super::Pre0_10RepositoryAccessIni;

/// Migrates the events, snapshots and info for the event-sourced RepositoryAccess.
/// There is no need to migrate the mutable RepositoryContent structure for this migration.
pub struct PublicationServerRepositoryAccessMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<RepositoryAccess>,
}

impl PublicationServerRepositoryAccessMigration {
    pub fn prepare(mode: UpgradeMode, config: &Config, versions: &UpgradeVersions) -> UpgradeResult<()> {
        let current_kv_store = KeyValueStore::create(&config.storage_uri, PUBSERVER_NS)?;
        let new_kv_store = KeyValueStore::create(config.upgrade_storage_uri(), PUBSERVER_NS)?;
        let new_agg_store =
            AggregateStore::create(config.upgrade_storage_uri(), PUBSERVER_NS, config.disable_history_cache)?;

        let store_migration = PublicationServerRepositoryAccessMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
        };

        if store_migration
            .current_kv_store
            .has_scope(&Scope::from_segment(segment!("0")))?
            && versions.from > KrillVersion::release(0, 9, 0)
            && versions.from < KrillVersion::candidate(0, 10, 0, 1)
        {
            store_migration.prepare_new_data(mode)
        } else {
            Ok(())
        }
    }
}

impl UpgradeStore for PublicationServerRepositoryAccessMigration {
    fn prepare_new_data(&self, mode: crate::upgrades::UpgradeMode) -> Result<(), crate::upgrades::PrepareUpgradeError> {
        // check existing version, wipe if needed
        self.preparation_store_prepare()?;

        // we only have 1 pubserver '0'
        let segment = segment!("0");
        let scope = Scope::from_segment(segment);
        let handle = MyHandle::from_str(segment.as_str()).unwrap(); // "0" is always safe

        // Get the info from the current store to see where we are
        let mut data_upgrade_info = self.data_upgrade_info(&scope)?;

        // Get the list of commands to prepare, starting with the last_command we got to (may be 0)
        let old_cmd_keys = self.command_keys(&scope, data_upgrade_info.last_command)?;

        // Migrate the initialisation event, if not done in a previous run. This
        // is a special event that has no command, so we need to do this separately.
        if data_upgrade_info.last_event == 0 {
            let init_key = Self::event_key(scope.clone(), 0);

            let old_init: Pre0_10RepositoryAccessIni = self
                .current_kv_store
                .get(&init_key)?
                .ok_or_else(|| PrepareUpgradeError::custom("Cannot read Publication Server init event"))?;

            let (_, _, old_init) = old_init.unpack();
            let init_event: RepositoryAccessInitEvent = old_init.into();

            // From 0.14.x and up we will have command '0' for the init, where beforehand
            // we only had an event. We will have to make up some values for the actor and time.
            let actor = Actor::system_actor();

            // The time is tricky.. our best guess is to set this to the same
            // value as the first command, if there is any. In the very unlikely
            // case that there is no first command, then we might as well set
            // it to now.
            let time = if let Some(first_command) = old_cmd_keys.first() {
                let cmd: OldStoredCommand<StorableRepositoryCommand> = self.get(first_command)?;
                cmd.time()
            } else {
                Time::now()
            };

            let details = StorableRepositoryCommand::Initialise;

            let builder =
                StoredCommandBuilder::<RepositoryAccess>::new(actor.to_string(), time, handle.clone(), 0, details);
            let stored_command = builder.finish_with_init_event(init_event);

            let command_key = Self::new_stored_command_key(scope.clone(), 0);

            self.new_kv_store.store(&command_key, &stored_command)?;
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

        // Track commands migrated and time spent so we can report progress
        let mut total_migrated = 0;
        let time_started = Time::now();

        for cmd_key in old_cmd_keys {
            // Read and parse the command. There is no need to change the command itself,
            // but we need to save it again and get the events from here.
            let old_cmd: OldStoredCommand<StorableRepositoryCommand> = self.get(&cmd_key)?;

            let new_command_builder = StoredCommandBuilder::<RepositoryAccess>::new(
                old_cmd.actor().clone(),
                old_cmd.time(),
                handle.clone(),
                old_cmd.sequence(),
                old_cmd.details().clone(),
            );

            // Read and parse all events. Migrate the events that contain changed types.
            // In this case IdCert -> IdCertInfo for added publishers. Then save the event
            // again in the migration scope.
            let new_command = match old_cmd.effect() {
                OldStoredEffect::Error { msg } => new_command_builder.finish_with_error(msg),
                OldStoredEffect::Success { events } => {
                    let mut full_events: Vec<RepositoryAccessEvent> = vec![]; // We just had numbers, we need to include the full events

                    for v in events {
                        let event_key = Self::event_key(scope.clone(), *v);
                        trace!("  +- event: {}", event_key);
                        let evt: Pre0_10RepositoryAccessEvent =
                            self.current_kv_store.get(&event_key)?.ok_or_else(|| {
                                PrepareUpgradeError::Custom(format!("Cannot parse old event: {}", event_key))
                            })?;

                        // Migrate into the current event type and save
                        let evt: RepositoryAccessEvent = evt.into_details().into();
                        full_events.push(evt);

                        data_upgrade_info.last_event = *v;
                    }

                    new_command_builder.finish_with_events(full_events)
                }
            };

            // Save the command to the migration
            let new_command_key = Self::new_stored_command_key(scope.clone(), new_command.version());
            self.new_kv_store.store(&new_command_key, &new_command)?;

            // Update and save data_upgrade_info for progress tracking
            data_upgrade_info.last_command += 1;
            data_upgrade_info.last_update = old_cmd.time();
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

        info!("Finished migrating Publication Server commands");

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
                self.clean_migration_help_files()?;
                info!(
                    "Prepared Publication Server data migration to version {}.",
                    KRILL_VERSION
                );
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
