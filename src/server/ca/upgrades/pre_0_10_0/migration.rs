//! Data mgigration for CAs from versions before 0.10.0.

use log::{debug, info};
use rpki::ca::idexchange::{CaHandle, MyHandle};
use rpki::repository::x509::Time;
use crate::api::aspa::ProviderAsn;
use crate::commons::eventsourcing::{
    AggregateStore, StoredCommand, StoredCommandBuilder
};
use crate::commons::storage::{
    Ident, KeyValueStore, OpenStoreError, StorageSystem
};
use crate::constants::{CASERVER_NS, CA_OBJECTS_NS};
use crate::server::ca::certauth::CertAuth;
use crate::server::ca::commands::CertAuthStorableCommand;
use crate::server::ca::events::{CertAuthEvent, CertAuthInitEvent};
use crate::server::ca::publishing::CaObjects;
use crate::upgrades::{
    AspaMigrationConfigUpdates, AspaMigrationConfigs, CommandMigrationEffect,
    UpgradeAggregateStorePre0_14, UpgradeError, UpgradeMode, UpgradeResult,
    UnconvertedEffect,
};
use crate::upgrades::pre_0_14_0::OldStoredCommand;
use super::old_events::{
    OldCaObjects, Pre0_10CertAuthEvent, Pre0_10CertAuthInitEvent
};
use super::old_commands::Pre0_10_0CertAuthStorableCommand;


//------------ CaMigration ---------------------------------------------------

/// Migrates the CAs.
///
/// It migrates both the `CertAuth` aggregates and the CA objects stored
/// separatedly..
pub struct CasMigration {
    /// The old key-value store for the aggregate.
    current_kv_store: KeyValueStore,

    /// The new key-value store for the aggregate.
    new_kv_store: KeyValueStore,

    /// The new `CertAuth` aggregate store.
    new_agg_store: AggregateStore<CertAuth>,

    /// The mogrations for the CA object store.
    ca_objects_migration: CaObjectsMigration,
}

impl CasMigration {
    /// Upgrades the CAs based on the upgrade mode and config.
    pub fn upgrade(
        mode: UpgradeMode,
        storage: &StorageSystem,
    ) -> UpgradeResult<AspaMigrationConfigs> {
        Self {
            current_kv_store: storage.open(CASERVER_NS)?,
            new_kv_store: storage.open_upgrade(CASERVER_NS)?,
            new_agg_store: AggregateStore::<CertAuth>::create_upgrade_store(
                storage,
                CASERVER_NS,
                false,
            )?,
            ca_objects_migration: CaObjectsMigration::create(storage)?,
        }
        .upgrade(mode)
    }
}

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
    ) -> UpgradeResult<StoredCommand<Self::Aggregate>> {
        let details = CertAuthStorableCommand::Init;
        let init_event = CertAuthInitEvent { id: old_init.into() };

        let builder = StoredCommandBuilder::<CertAuth>::new(
            actor, time, handle, 0, details,
        );

        Ok(builder.finish_with_init_event(init_event))
    }

    fn deployed_store(&self) -> &KeyValueStore {
        &self.current_kv_store
    }

    fn preparation_key_value_store(&self) -> &KeyValueStore {
        &self.new_kv_store
    }

    fn preparation_aggregate_store(
        &self,
    ) -> &AggregateStore<Self::Aggregate> {
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
            | Pre0_10_0CertAuthStorableCommand::AspasUpdateExisting {
                ..
            } => {
                if let Some(events) = old_effect.into_events() {
                    for old_event in events {
                        match old_event {
                            Pre0_10CertAuthEvent::AspaObjectsUpdated {
                                updates,
                                ..
                            } => {
                                let ca = old_command.handle().clone();
                                let removed = updates
                                    .removed
                                    .into_iter()
                                    .map(rpki::resources::Asn::from)
                                    .collect();
                                let added_or_updated = updates
                                    .updated
                                    .into_iter()
                                    .map(|info| {
                                        // strange mapping is correct, we
                                        // re-use the Pre0_14_0ProviderAsn
                                        // for the customer AS because of the
                                        // string, rather than u32, mapping
                                        // that was used in the pre <0.10
                                        // json.
                                        let customer =
                                            info.definition.customer.provider;
                                        let providers: Vec<ProviderAsn> =
                                            info.definition
                                                .providers
                                                .into_iter()
                                                .map(|p| p.provider)
                                                .collect();
                                        (customer, providers)
                                    })
                                    .collect();
                                let updates = AspaMigrationConfigUpdates {
                                    ca,
                                    added_or_updated,
                                    removed,
                                };
                                // There is never more than one
                                // AspaObjectsUpdated event for each
                                // command processed, so we can just return
                                // now.
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
                let new_command_builder =
                    StoredCommandBuilder::<CertAuth>::new(
                        old_command.actor().clone(),
                        old_command.time(),
                        old_command.handle().clone(),
                        version,
                        old_command.details().clone().into(),
                    );

                let new_command = match old_effect {
                    UnconvertedEffect::Error { msg } => {
                        new_command_builder.finish_with_error(msg)
                    }
                    UnconvertedEffect::Success { events } => {
                        let mut full_events: Vec<CertAuthEvent> = vec![]; // We just had numbers, we need to include the full
                                                                          // events
                        for old_event in events {
                            match old_event {
                                Pre0_10CertAuthEvent::AspaConfigAdded { .. }
                                | Pre0_10CertAuthEvent::AspaConfigRemoved { .. }
                                | Pre0_10CertAuthEvent::AspaConfigUpdated { .. }
                                | Pre0_10CertAuthEvent::AspaObjectsUpdated { .. } => {
                                    // we only expect AspaObjectsUpdated to be possible outside of
                                    // Aspa related commands, e.g. because of a key rollover, but
                                    // to be sure.. we do not migrate any of the ASPA events in
                                    // this migration.
                                }
                                _ => {
                                    full_events.push(old_event.try_into()?);
                                }
                            }
                        }
                        new_command_builder.finish_with_events(full_events)
                    }
                };

                // if the new command would be a no-op because no events are
                // actually migrated, then return
                // CommandMigrationEffect::Nothing
                if let Some(events) = new_command.events() {
                    if events.is_empty() {
                        return Ok(CommandMigrationEffect::Nothing);
                    }
                }

                Ok(CommandMigrationEffect::StoredCommand(new_command))
            }
        }
    }

    /// Override post migration, we need to do extra stuff.
    fn post_command_migration(&self, handle: &MyHandle) -> UpgradeResult<()> {
        info!(
            "Will migrate the current repository objects for CA '{handle}'"
        );
        self.ca_objects_migration.prepare_new_data_for(handle)
    }
}


//------------ CaObjectMigration ---------------------------------------------

/// Migrates the CA objects store for a given CA.
struct CaObjectsMigration {
    /// The store with the old data.
    current_store: KeyValueStore,

    /// The store with the converted data.
    new_store: KeyValueStore,
}

impl CaObjectsMigration {
    /// Creates a new migration from the configuration.
    fn create(storage: &StorageSystem) -> Result<Self, OpenStoreError> {
        Ok(CaObjectsMigration {
            current_store: storage.open(CA_OBJECTS_NS)?,
            new_store: storage.open_upgrade(CA_OBJECTS_NS)?
        })
    }

    fn prepare_new_data_for(
        &self,
        ca: &CaHandle,
    ) -> Result<(), UpgradeError> {
        let key = Ident::builder(
            Ident::from_handle(ca).into_owned()
        ).finish_with_extension( const { Ident::make("json") });

        if let Some(old_objects) =
            self.current_store.get::<OldCaObjects>(None, &key)?
        {
            let converted: CaObjects = old_objects.try_into()?;
            self.new_store.store(None, &key, &converted)?;
            debug!(
                "Stored updated objects for CA {} in {:?}",
                ca, self.new_store
            );
        }

        Ok(())
    }
}

