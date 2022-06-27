use std::str::FromStr;

use rpki::ca::idexchange::CaHandle;

use crate::{
    commons::{eventsourcing::KeyValueStore, util::KrillVersion},
    constants::{CASERVER_DIR, KRILL_VERSION},
    daemon::{ca::IniDet, config::Config},
    upgrades::{pre_0_10_0::OldCaIni, PrepareUpgradeError, UpgradeMode, UpgradeResult, UpgradeStore},
};

pub struct CasStoreMigration {
    current_kv_store: KeyValueStore,
    new_kv_store: KeyValueStore,
}

impl CasStoreMigration {
    pub fn prepare(mode: UpgradeMode, config: &Config) -> UpgradeResult<()> {
        let current_kv_store = KeyValueStore::disk(&config.data_dir, CASERVER_DIR)?;
        let new_kv_store = KeyValueStore::disk(&config.upgrade_data_dir(), CASERVER_DIR)?;

        CasStoreMigration {
            current_kv_store,
            new_kv_store,
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

        let dflt_actor = "krill".to_string();

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

            // Note:
            //  - so we can start looping over all commands that have not yet been migrated
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
