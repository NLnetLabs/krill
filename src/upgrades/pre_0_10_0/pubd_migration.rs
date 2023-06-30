use rpki::{ca::idexchange::MyHandle, repository::x509::Time};

use crate::{
    commons::{
        api::StorableRepositoryCommand,
        eventsourcing::{segment, AggregateStore, KeyValueStore, Scope, Segment, StoredCommand, StoredCommandBuilder},
        util::KrillVersion,
    },
    constants::PUBSERVER_NS,
    daemon::config::Config,
    pubd::{RepositoryAccess, RepositoryAccessEvent, RepositoryAccessInitEvent},
    upgrades::{
        OldRepositoryAccessEvent, OldRepositoryAccessInitEvent, OldStoredCommand, UnconvertedEffect,
        UpgradeAggregateStorePre0_14, UpgradeMode, UpgradeResult, UpgradeVersions,
    },
};

/// Migrates the events, snapshots and info for the event-sourced RepositoryAccess.
/// There is no need to migrate the mutable RepositoryContent structure for this migration.
pub struct PublicationServerRepositoryAccessMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<RepositoryAccess>,
}

impl PublicationServerRepositoryAccessMigration {
    pub fn upgrade(mode: UpgradeMode, config: &Config, versions: &UpgradeVersions) -> UpgradeResult<()> {
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
            store_migration.upgrade(mode)
        } else {
            Ok(())
        }
    }
}

impl UpgradeAggregateStorePre0_14 for PublicationServerRepositoryAccessMigration {
    type Aggregate = RepositoryAccess;

    type OldInitEvent = OldRepositoryAccessInitEvent;
    type OldEvent = OldRepositoryAccessEvent;
    type OldStorableDetails = StorableRepositoryCommand;

    fn store_name(&self) -> &str {
        "Repository Access"
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

    fn convert_init_event(
        &self,
        old_init: Self::OldInitEvent,
        handle: MyHandle,
        actor: String,
        time: Time,
    ) -> UpgradeResult<crate::commons::eventsourcing::StoredCommand<Self::Aggregate>> {
        let details = StorableRepositoryCommand::Initialise;
        let builder = StoredCommandBuilder::<RepositoryAccess>::new(actor, time, handle, 0, details);
        let init_event: RepositoryAccessInitEvent = old_init.into_details();

        Ok(builder.finish_with_init_event(init_event))
    }

    fn convert_old_command(
        &self,
        old_command: OldStoredCommand<Self::OldStorableDetails>,
        old_effect: UnconvertedEffect<Self::OldEvent>,
        version: u64,
    ) -> UpgradeResult<Option<StoredCommand<Self::Aggregate>>> {
        let new_command_builder = StoredCommandBuilder::<RepositoryAccess>::new(
            old_command.actor().clone(),
            old_command.time(),
            old_command.handle().clone(),
            version,
            old_command.details().clone(),
        );

        let new_command = match old_effect {
            UnconvertedEffect::Error { msg } => new_command_builder.finish_with_error(msg),
            UnconvertedEffect::Success { events } => {
                let full_events: Vec<RepositoryAccessEvent> =
                    events.into_iter().map(|old| old.into_details()).collect();
                new_command_builder.finish_with_events(full_events)
            }
        };

        Ok(Some(new_command))
    }
}
