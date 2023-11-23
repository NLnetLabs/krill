//! Find and remove any incompletely written files due to issue #1160

use kvx::{segment, Namespace, ReadStore, Scope, Segment, WriteStore};
use rpki::ca::idexchange::MyHandle;

use crate::{
    commons::eventsourcing::{Aggregate, AggregateStore, KeyValueStore, StoredCommand, WalSet, WalStore, WalSupport},
    constants::{STATUS_NS, TASK_QUEUE_NS},
    daemon::{ca::StatusStore, config::Config},
    upgrades::UpgradeResult,
};

use super::UpgradeError;

/// This function is used to recover from corrupt command files resulting
/// from issue #1160 - if needed.
///
/// In case the store has no apparent issues in "warming" the entities, then
/// no migration is started.
///
/// If any issue is found, then we replay all commands for each entity (aggregate)
/// starting from the init command, in as far as they can be parsed and applied,
/// into new migrated aggregate store.
///
/// Note that this code can also serve as a starting point for future upgrades,
/// e.g. when the RTA support is removed, we may need to replay the entire
/// history and leave out any RTA related commands and events, renumbering the
/// commands in the upgraded store.
///
/// With regards to RTA specifically, even though it is unlikely that people
/// really used RTA in production, it would still be in their CA history if they
/// did, meaning that simply removing the code for that would leave their CAs
/// unusable. So, a migration should be done to ensure that everyone can upgrade.
pub fn upgrade_agg<A: Aggregate>(name: &Namespace, config: &Config) -> UpgradeResult<bool> {
    let current_agg_store = AggregateStore::<A>::create(&config.storage_uri, name, false)?;
    if current_agg_store.warm().is_ok() {
        info!("No need to migrate store {name}");
        Ok(false)
    } else {
        info!("Issue found in store {name}. Will attempt to fix it in upgrade.");

        let cur_kv = KeyValueStore::create(&config.storage_uri, name)?;
        let new_kv = KeyValueStore::create_upgrade_store(&config.storage_uri, name)?;

        for handle in current_agg_store.list()? {
            // Try to get an initialised aggregate. This can only error out in
            // case there is a valid init command but it cannot be saved in the
            // new store.
            match migrate_agg_init::<A>(&handle, &cur_kv, &new_kv)? {
                None => continue, // Cannot migrate this one.
                Some(mut agg) => {
                    // Apply and migrate each next command. This will error out
                    // only if we cannot store the next command in the new store.
                    while migrate_next_agg_command(&handle, &mut agg, &cur_kv, &new_kv)? {
                        debug!("migrated command for {handle}, now at version: {}", agg.version());
                    }
                    let snapshot_key = AggregateStore::<A>::key_for_snapshot(&handle);
                    new_kv.store(&snapshot_key, &agg)?;
                    info!("Migrated {handle} in store {name}");
                }
            }
        }

        Ok(true)
    }
}

/// This function is used to recover from corrupt command files resulting
/// from issue #1160 - if needed for Write Ahead Log (WAL) stores.
///
/// In case the store has no apparent issues in "warming" the entities, then
/// no migration is started.
///
/// If any issue is found, then we replay all commands for each entity (aggregate)
/// starting from the last snapshot, in as far as they can be parsed and applied,
/// into new migrated aggregate store.
pub fn upgrade_wal<W: WalSupport>(name: &Namespace, config: &Config) -> UpgradeResult<bool> {
    let current_wal_store = WalStore::<W>::create(&config.storage_uri, name)?;
    if current_wal_store.warm().is_ok() {
        info!("No need to migrate store {name}");
        Ok(false)
    } else {
        info!("Issue found in store {name}. Will attempt to fix it in upgrade.");

        let cur_kv = KeyValueStore::create(&config.storage_uri, name)?;
        let new_kv = KeyValueStore::create_upgrade_store(&config.storage_uri, name)?;

        for handle in current_wal_store.list()? {
            // Try to get an initialised wal support type. This can only error out in
            // case there is a valid snapshot but it cannot be saved in the new store.
            match migrate_wal_snapshot::<W>(&handle, &cur_kv, &new_kv)? {
                None => continue, // Cannot migrate this one.
                Some(mut wal) => {
                    // Apply and migrate each next command. This will error out
                    // only if we cannot store the next command in the new store.
                    while migrate_next_wal_command(&handle, &mut wal, &cur_kv, &new_kv)? {
                        debug!("migrated change set for {handle}, now at version: {}", wal.revision());
                    }
                    info!("Migrated {handle} in store {name}");
                }
            }
        }

        Ok(true)
    }
}

/// Check the task store for corrupted tasks due to issue #1160, and if present
/// drop them in place. This is safe to do because missing tasks are re-added at start up.
pub fn upgrade_tasks(config: &Config) -> UpgradeResult<()> {
    let task_store = kvx::KeyValueStore::new(&config.storage_uri, TASK_QUEUE_NS)
        .map_err(|e| UpgradeError::Custom(format!("Cannot create task store: {}", e)))?;

    let pending_scope = Scope::from_segment(segment!("pending"));
    let running_scope = Scope::from_segment(segment!("running"));

    for pending_key in task_store
        .list_keys(&pending_scope)
        .map_err(|e| UpgradeError::Custom(format!("Cannot read pending tasks: {}", e)))?
    {
        if task_store.get(&pending_key).is_err() {
            warn!("Pending task could not be parsed. Dropping: {}", pending_key);
            task_store.delete(&pending_key).map_err(|e| {
                UpgradeError::Custom(format!("Cannot delete corrupt task: {}. Error: {}", pending_key, e))
            })?;
        }
    }

    for running_key in task_store
        .list_keys(&running_scope)
        .map_err(|e| UpgradeError::Custom(format!("Cannot read running tasks: {}", e)))?
    {
        if task_store.get(&running_key).is_err() {
            warn!("Running task could not be parsed. Dropping: {}", running_key);
            task_store.delete(&running_key).map_err(|e| {
                UpgradeError::Custom(format!("Cannot delete corrupt task: {}. Error: {}", running_key, e))
            })?;
        }
    }

    Ok(())
}

/// Check the status store for corruption due to issue #1160. If there is an issue, just wipe
/// the entire store. The status store is used for convenience and will be rebuild on startup
/// and on demand.
pub fn upgrade_status(config: &Config) -> UpgradeResult<()> {
    if StatusStore::create(&config.storage_uri, STATUS_NS).is_err() {
        let status_kv_store = KeyValueStore::create(&config.storage_uri, STATUS_NS)?;
        status_kv_store.wipe()?;
    }

    Ok(())
}

fn migrate_wal_snapshot<W: WalSupport>(
    handle: &MyHandle,
    current_store: &KeyValueStore,
    new_store: &KeyValueStore,
) -> UpgradeResult<Option<W>> {
    let snapshot_key = WalStore::<W>::key_for_snapshot(handle);

    match current_store.get::<W>(&snapshot_key) {
        Ok(Some(wal)) => {
            new_store.store(&snapshot_key, &wal)?;
            Ok(Some(wal))
        }
        Ok(None) => {
            debug!("Empty entity scope found for {handle}");
            Ok(None)
        }
        Err(e) => {
            warn!("The initialisation command for {handle} is corrupt. Will not migrate it. Error was: {e}");
            Ok(None)
        }
    }
}

fn migrate_agg_init<A: Aggregate>(
    handle: &MyHandle,
    current_store: &KeyValueStore,
    new_store: &KeyValueStore,
) -> UpgradeResult<Option<A>> {
    let init_key = AggregateStore::<A>::key_for_command(handle, 0);

    match current_store.get::<StoredCommand<A>>(&init_key) {
        Ok(Some(init_command)) => match init_command.clone().into_init() {
            Some(init_event) => {
                new_store.store(&init_key, &init_command)?;
                Ok(Some(A::init(handle.clone(), init_event)))
            }
            None => {
                warn!("The initialisation command for {handle} cannot be used. Will not migrate it");
                Ok(None)
            }
        },
        Ok(None) => {
            debug!("Empty entity scope found for {handle}");
            Ok(None)
        }
        Err(e) => {
            warn!("The initialisation command for {handle} is corrupt. Will not migrate it. Error was: {e}");
            Ok(None)
        }
    }
}

fn migrate_next_agg_command<A: Aggregate>(
    handle: &MyHandle,
    agg: &mut A,
    current_store: &KeyValueStore,
    new_store: &KeyValueStore,
) -> UpgradeResult<bool> {
    let next_command_key = AggregateStore::<A>::key_for_command(handle, agg.version());

    match current_store.get::<StoredCommand<A>>(&next_command_key) {
        Ok(Some(command)) => {
            new_store.store(&next_command_key, &command)?;
            agg.apply_command(command);
            Ok(true)
        }
        Ok(None) => {
            debug!("No more commands for aggregate: {handle}");
            Ok(false)
        }
        Err(e) => {
            warn!(
                "Cannot parse command: {}. Stopping migration at this point. Error was: {}",
                next_command_key, e
            );
            Ok(false)
        }
    }
}

fn migrate_next_wal_command<W: WalSupport>(
    handle: &MyHandle,
    wal: &mut W,
    current_store: &KeyValueStore,
    new_store: &KeyValueStore,
) -> UpgradeResult<bool> {
    let next_wal_set_key = WalStore::<W>::key_for_wal_set(handle, wal.revision());

    match current_store.get::<WalSet<W>>(&next_wal_set_key) {
        Ok(Some(set)) => {
            new_store.store(&next_wal_set_key, &set)?;
            wal.apply(set);
            Ok(true)
        }
        Ok(None) => {
            debug!("No more commands for aggregate: {handle}");
            Ok(false)
        }
        Err(e) => {
            warn!(
                "Cannot parse command: {}. Stopping migration at this point. Error was: {}",
                next_wal_set_key, e
            );
            Ok(false)
        }
    }
}
