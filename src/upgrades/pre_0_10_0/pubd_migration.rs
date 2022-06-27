use std::str::FromStr;

use rpki::ca::idexchange::MyHandle;

use crate::{
    commons::{
        eventsourcing::{AggregateStore, KeyValueStore, StoredEvent},
        util::KrillVersion,
    },
    constants::{KRILL_VERSION, PUBSERVER_DIR},
    daemon::config::Config,
    pubd::{RepositoryAccess, RepositoryAccessInitDetails},
    upgrades::{PrepareUpgradeError, UpgradeMode, UpgradeResult, UpgradeStore},
};

use super::OldRepositoryAccessIni;

pub struct PubdStoreMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
    new_agg_store: AggregateStore<RepositoryAccess>,
}

impl PubdStoreMigration {
    pub fn prepare(mode: UpgradeMode, config: &Config) -> UpgradeResult<()> {
        let upgrade_data_dir = config.upgrade_data_dir();

        let current_kv_store = KeyValueStore::disk(&config.data_dir, PUBSERVER_DIR)?;
        let new_kv_store = KeyValueStore::disk(&upgrade_data_dir, PUBSERVER_DIR)?;
        let new_agg_store = AggregateStore::disk(&upgrade_data_dir, PUBSERVER_DIR)?;

        PubdStoreMigration {
            current_kv_store,
            new_kv_store,
            new_agg_store,
        }
        .prepare_new_data(mode)
    }
}

impl UpgradeStore for PubdStoreMigration {
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
                .ok_or_else(|| PrepareUpgradeError::custom("Cannot read pubd init event"))?;

            let (_, _, old_init) = old_init.unpack();
            let init: RepositoryAccessInitDetails = old_init.into();
            let init = StoredEvent::new(&handle, 0, init);
            self.new_kv_store.store(&init_key, &init)?;
        }

        todo!("migrate")
    }

    fn deployed_store(&self) -> &KeyValueStore {
        &self.current_kv_store
    }

    fn preparation_store(&self) -> &KeyValueStore {
        &self.new_kv_store
    }
}
