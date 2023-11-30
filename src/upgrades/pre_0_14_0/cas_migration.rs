use rpki::ca::idexchange::MyHandle;
use rpki::repository::x509::Time;

use crate::commons::api::ProviderAsn;
use crate::commons::eventsourcing::StoredCommandBuilder;
use crate::upgrades::pre_0_14_0::Pre0_14_0CertAuthStorableCommand;
use crate::upgrades::{
    AspaMigrationConfigUpdates, AspaMigrationConfigs, CommandMigrationEffect, UnconvertedEffect,
    UpgradeAggregateStorePre0_14, UpgradeMode,
};
use crate::{
    commons::{
        api::CertAuthStorableCommand,
        eventsourcing::{AggregateStore, KeyValueStore},
    },
    constants::CASERVER_NS,
    daemon::{
        ca::{CertAuth, CertAuthEvent, CertAuthInitEvent},
        config::Config,
    },
    upgrades::UpgradeResult,
};

use super::{OldStoredCommand, Pre0_14_0CertAuthEvent};

/// Migrates the CAs:
/// - The events, snapshots and info in the AggregateStore
/// - The mutable CaObjects structure
pub struct CasMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<CertAuth>,
}

impl CasMigration {
    pub fn upgrade(mode: UpgradeMode, config: &Config) -> UpgradeResult<AspaMigrationConfigs> {
        let current_kv_store = KeyValueStore::create(&config.storage_uri, CASERVER_NS)?;
        let new_kv_store = KeyValueStore::create_upgrade_store(&config.storage_uri, CASERVER_NS)?;

        let new_agg_store = AggregateStore::<CertAuth>::create_upgrade_store(
            &config.storage_uri,
            CASERVER_NS,
            config.use_history_cache,
        )?;

        CasMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
        }
        .upgrade(mode)
    }
}

impl UpgradeAggregateStorePre0_14 for CasMigration {
    type Aggregate = CertAuth;

    type OldInitEvent = CertAuthInitEvent;
    type OldEvent = Pre0_14_0CertAuthEvent;
    type OldStorableDetails = Pre0_14_0CertAuthStorableCommand;

    fn store_name(&self) -> &str {
        "CAs"
    }

    fn convert_init_event(
        &self,
        old_init: Self::OldInitEvent,
        handle: MyHandle,
        actor: String,
        time: Time,
    ) -> UpgradeResult<crate::commons::eventsourcing::StoredCommand<Self::Aggregate>> {
        let details = CertAuthStorableCommand::Init;
        let init_event = old_init;

        let builder = StoredCommandBuilder::<CertAuth>::new(actor, time, handle, 0, details);

        Ok(builder.finish_with_init_event(init_event))
    }

    fn deployed_store(&self) -> &KeyValueStore {
        &self.current_kv_store
    }

    fn preparation_key_value_store(&self) -> &KeyValueStore {
        &self.new_kv_store
    }

    fn preparation_aggregate_store(&self) -> &AggregateStore<Self::Aggregate> {
        &self.new_agg_store
    }

    fn convert_old_command(
        &self,
        old_command: OldStoredCommand<Self::OldStorableDetails>,
        old_effect: UnconvertedEffect<Self::OldEvent>,
        version: u64,
    ) -> UpgradeResult<CommandMigrationEffect<Self::Aggregate>> {
        match old_command.details() {
            Pre0_14_0CertAuthStorableCommand::AspaRemove { .. }
            | Pre0_14_0CertAuthStorableCommand::AspasUpdate { .. }
            | Pre0_14_0CertAuthStorableCommand::AspasUpdateExisting { .. } => {
                if let Some(events) = old_effect.into_events() {
                    for old_event in events {
                        match old_event {
                            Pre0_14_0CertAuthEvent::AspaObjectsUpdated { updates, .. } => {
                                let ca = old_command.handle().clone();
                                let removed = updates.removed;
                                let added_or_updated = updates
                                    .updated
                                    .into_iter()
                                    .map(|info| {
                                        let customer = info.definition.customer;
                                        let providers: Vec<ProviderAsn> =
                                            info.definition.providers.into_iter().map(|p| p.provider).collect();
                                        (customer, providers)
                                    })
                                    .collect();
                                let updates = AspaMigrationConfigUpdates {
                                    ca,
                                    added_or_updated,
                                    removed,
                                };
                                // There is never more than one AspaObjectsUpdated event for each
                                // command processed, so we can just return now.
                                return Ok(CommandMigrationEffect::AspaObjectsUpdates(updates));
                            }
                            _ => {
                                // ignored for migration
                            }
                        }
                    }
                }
                Ok(CommandMigrationEffect::Nothing)
            }
            _ => {
                let new_command_builder = StoredCommandBuilder::<CertAuth>::new(
                    old_command.actor().clone(),
                    old_command.time(),
                    old_command.handle().clone(),
                    version,
                    old_command.details().clone().into(),
                );

                let new_command = match old_effect {
                    UnconvertedEffect::Error { msg } => new_command_builder.finish_with_error(msg),
                    UnconvertedEffect::Success { events } => {
                        let mut full_events: Vec<CertAuthEvent> = vec![]; // We just had numbers, we need to include the full events
                        for old_event in events {
                            match old_event {
                                Pre0_14_0CertAuthEvent::AspaConfigAdded { .. }
                                | Pre0_14_0CertAuthEvent::AspaConfigRemoved { .. }
                                | Pre0_14_0CertAuthEvent::AspaConfigUpdated { .. }
                                | Pre0_14_0CertAuthEvent::AspaObjectsUpdated { .. } => {
                                    // we only expect AspaObjectsUpdated to be possible outside of
                                    // Aspa related commands, e.g. because of a key rollover, but
                                    // to be sure.. we do not migrate any of the ASPA events in
                                    // this migration.
                                }
                                _ => {
                                    full_events.push(old_event.into());
                                }
                            }
                        }
                        new_command_builder.finish_with_events(full_events)
                    }
                };

                // if the new command would be a no-op because no events are actually migrated,
                // then return CommandMigrationEffect::Nothing
                if let Some(events) = new_command.events() {
                    if events.is_empty() {
                        return Ok(CommandMigrationEffect::Nothing);
                    }
                }

                Ok(CommandMigrationEffect::StoredCommand(new_command))
            }
        }
    }
}
