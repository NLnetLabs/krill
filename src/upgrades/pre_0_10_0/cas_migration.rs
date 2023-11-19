use std::convert::TryInto;

use rpki::{
    ca::idexchange::{CaHandle, MyHandle},
    repository::x509::Time,
};

use crate::{
    commons::{
        api::{CertAuthStorableCommand, ProviderAsn},
        eventsourcing::{AggregateStore, StoredCommandBuilder},
        storage::{Key, KeyValueStore, SegmentBuf},
    },
    constants::{CASERVER_NS, CA_OBJECTS_NS},
    daemon::{
        ca::{CaObjects, CertAuth, CertAuthEvent, CertAuthInitEvent},
        config::Config,
    },
    upgrades::pre_0_10_0::{OldCaObjects, Pre0_10_0CertAuthStorableCommand},
    upgrades::{
        pre_0_10_0::{Pre0_10CertAuthEvent, Pre0_10CertAuthInitEvent},
        pre_0_14_0::OldStoredCommand,
        UpgradeAggregateStorePre0_14, UpgradeError, UpgradeMode, UpgradeResult,
    },
    upgrades::{AspaMigrationConfigUpdates, AspaMigrationConfigs, CommandMigrationEffect, UnconvertedEffect},
};

/// Migrates the CaObjects for a given CA.
///
/// i.e. the CA content which is NOT event-sourced.
struct CaObjectsMigration {
    current_store: KeyValueStore,
    new_store: KeyValueStore,
}

impl CaObjectsMigration {
    fn create(config: &Config) -> Result<Self, UpgradeError> {
        let current_store = KeyValueStore::create(&config.storage_uri, CA_OBJECTS_NS)?;
        let new_store = KeyValueStore::create_upgrade_store(&config.storage_uri, CA_OBJECTS_NS)?;
        Ok(CaObjectsMigration {
            current_store,
            new_store,
        })
    }

    async fn prepare_new_data_for(&self, ca: &CaHandle) -> Result<(), UpgradeError> {
        let key = Key::new_global(SegmentBuf::parse_lossy(&format!("{}.json", ca))); // ca should always be a valid Segment

        if let Some(old_objects) = self.current_store.get::<OldCaObjects>(&key).await? {
            let converted: CaObjects = old_objects.try_into()?;
            self.new_store.store(&key, &converted).await?;
            debug!("Stored updated objects for CA {} in {}", ca, self.new_store);
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
    pub async fn upgrade(mode: UpgradeMode, config: &Config) -> UpgradeResult<AspaMigrationConfigs> {
        let current_kv_store = KeyValueStore::create(&config.storage_uri, CASERVER_NS)?;
        let new_kv_store = KeyValueStore::create_upgrade_store(&config.storage_uri, CASERVER_NS)?;

        let new_agg_store = AggregateStore::<CertAuth>::create_upgrade_store(
            &config.storage_uri,
            CASERVER_NS,
            config.use_history_cache,
        )?;
        let ca_objects_migration = CaObjectsMigration::create(config)?;

        CasMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
            ca_objects_migration,
        }
        .upgrade(mode)
        .await
    }
}

#[async_trait::async_trait]
impl UpgradeAggregateStorePre0_14 for CasMigration {
    type Aggregate = CertAuth;

    type OldInitEvent = Pre0_10CertAuthInitEvent;
    type OldEvent = Pre0_10CertAuthEvent;
    type OldStorableDetails = Pre0_10_0CertAuthStorableCommand;

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
        let init_event = CertAuthInitEvent::new(old_init.into());

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
            Pre0_10_0CertAuthStorableCommand::AspaRemove { .. }
            | Pre0_10_0CertAuthStorableCommand::AspasUpdate { .. }
            | Pre0_10_0CertAuthStorableCommand::AspasUpdateExisting { .. } => {
                if let Some(events) = old_effect.into_events() {
                    for old_event in events {
                        match old_event {
                            Pre0_10CertAuthEvent::AspaObjectsUpdated { updates, .. } => {
                                let ca = old_command.handle().clone();
                                let removed = updates.removed;
                                let added_or_updated = updates
                                    .updated
                                    .into_iter()
                                    .map(|info| {
                                        // strange mapping is correct, we re-use the Pre0_14_0ProviderAsn
                                        // for the customer AS because of the string, rather than u32, mapping
                                        // that was used in the pre <0.10 json.
                                        let customer = info.definition.customer.provider;
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
                            full_events.push(old_event.try_into()?);
                        }
                        new_command_builder.finish_with_events(full_events)
                    }
                };

                Ok(CommandMigrationEffect::StoredCommand(new_command))
            }
        }
    }

    /// Override post migration, we need to do extra stuff.
    async fn post_command_migration(&self, handle: &MyHandle) -> UpgradeResult<()> {
        info!("Will migrate the current repository objects for CA '{}'", handle);
        self.ca_objects_migration.prepare_new_data_for(handle).await
    }
}
