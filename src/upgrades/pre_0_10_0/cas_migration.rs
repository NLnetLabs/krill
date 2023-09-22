use std::convert::TryInto;

use rpki::ca::idexchange::MyHandle;
use rpki::{ca::idexchange::CaHandle, repository::x509::Time};

use crate::commons::eventsourcing::{StoredCommand, StoredCommandBuilder};
use crate::daemon::ca::CaObjects;
use crate::upgrades::UnconvertedEffect;
use crate::{
    commons::{
        api::CertAuthStorableCommand,
        eventsourcing::{AggregateStore, Key, KeyValueStore, Segment, SegmentExt},
    },
    constants::{CASERVER_NS, CA_OBJECTS_NS},
    daemon::{
        ca::{CertAuth, CertAuthEvent, CertAuthInitEvent},
        config::Config,
    },
    upgrades::{
        pre_0_10_0::{Pre0_10CertAuthEvent, Pre0_10CertAuthInitEvent},
        pre_0_14_0::OldStoredCommand,
        UpgradeAggregateStorePre0_14, UpgradeError, UpgradeMode, UpgradeResult,
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
    fn create(config: &Config) -> Result<Self, UpgradeError> {
        let current_store = KeyValueStore::create(&config.storage_uri, CA_OBJECTS_NS)?;
        let new_store = KeyValueStore::create_upgrade_store(&config.storage_uri, CA_OBJECTS_NS)?;
        Ok(CaObjectsMigration {
            current_store,
            new_store,
        })
    }

    fn prepare_new_data_for(&self, ca: &CaHandle) -> Result<(), UpgradeError> {
        let key = Key::new_global(Segment::parse_lossy(&format!("{}.json", ca))); // ca should always be a valid Segment

        if let Some(old_objects) = self.current_store.get::<OldCaObjects>(&key)? {
            let converted: CaObjects = old_objects.try_into()?;
            self.new_store.store(&key, &converted)?;
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
    pub fn upgrade(mode: UpgradeMode, config: &Config) -> UpgradeResult<()> {
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
    }
}

impl UpgradeAggregateStorePre0_14 for CasMigration {
    type Aggregate = CertAuth;

    type OldInitEvent = Pre0_10CertAuthInitEvent;
    type OldEvent = Pre0_10CertAuthEvent;
    type OldStorableDetails = CertAuthStorableCommand;

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
    ) -> UpgradeResult<Option<StoredCommand<Self::Aggregate>>> {
        let new_command_builder = StoredCommandBuilder::<CertAuth>::new(
            old_command.actor().clone(),
            old_command.time(),
            old_command.handle().clone(),
            version,
            old_command.details().clone(),
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

        Ok(Some(new_command))
    }

    /// Override post migration, we need to do extra stuff.
    fn post_command_migration(&self, handle: &MyHandle) -> UpgradeResult<()> {
        info!("Will migrate the current repository objects for CA '{}'", handle);
        self.ca_objects_migration.prepare_new_data_for(handle)
    }
}
