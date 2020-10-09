//------------ Fix errors in info.json  ------------------------------------

use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};

use rpki::x509::Time;

use crate::commons::eventsourcing::{CommandKey, KeyStoreKey, KeyStoreVersion, KeyValueStore, StoredValueInfo};
use crate::upgrades::{UpgradeError, UpgradeStore};

pub struct FixInfoFiles;

impl UpgradeStore for FixInfoFiles {
    fn needs_migrate(&self, store: &KeyValueStore) -> Result<bool, UpgradeError> {
        Self::version_same_or_before(store, KeyStoreVersion::V0_7)
    }

    fn migrate(&self, kv: &KeyValueStore) -> Result<(), UpgradeError> {
        if self.needs_migrate(kv)? {
            info!("Krill will now fix pre-0.8.0-rc1 meta data");
            // Fix the info file in each scope (aggregate)
            //   -> leave the snapshot version as it was, or set it to 0 if there was no info
            //   -> set the sequence number of the highest command
            //   -> set the version of the last event
            //   -> set the time
            for scope in kv.scopes()? {
                let info_key = KeyStoreKey::scoped(scope.clone(), "info.json".to_string());
                let mut info: StoredValueInfo = match kv.get(&info_key) {
                    Ok(Some(info)) => info,
                    _ => StoredValueInfo::default(),
                };

                // reset last event and command, we will find the new (higher) versions.
                info.last_event = 0;
                info.last_command = 0;

                let keys = kv.keys(Some(scope.clone()), "")?;

                for key in keys {
                    if key.name().starts_with("delta-") && key.name().ends_with(".json") {
                        let nr_str = &key.name()[6..key.name().len() - 5];
                        if let Ok(version) = u64::from_str(nr_str) {
                            if version > info.last_event {
                                info.last_event = version;
                            }
                        }
                    } else if let Ok(command_key) = CommandKey::from_str(key.name()) {
                        if command_key.sequence > info.last_command {
                            info.last_command = command_key.sequence;
                            let time = NaiveDateTime::from_timestamp(command_key.timestamp_secs, 0);
                            info.last_update = Time::new(DateTime::from_utc(time, Utc));
                        }
                    } // else do nothing
                }

                kv.store(&info_key, &info)?;
                debug!("Updated info.json for '{}'", scope)
            }
        }
        Ok(())
    }
}
