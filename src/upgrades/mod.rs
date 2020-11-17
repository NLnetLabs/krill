//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::path::PathBuf;
use std::{fmt, fs, io};

use crate::commons::api::Handle;
use crate::commons::eventsourcing::{
    AggregateStore, AggregateStoreError, KeyStoreKey, KeyStoreVersion, KeyValueError, KeyValueStore,
};
use crate::commons::util::file;
use crate::constants::KRILL_VERSION;
use crate::daemon::ca::CertAuth;
use crate::daemon::krillserver::KrillServer;
use crate::pubd::Repository;
use crate::upgrades::fix_info_last_event_0_8_0::FixInfoFiles;
use crate::upgrades::roa_cleanup_0_8_0::RoaCleanupError;

pub mod fix_info_last_event_0_8_0;
pub mod pre_0_6_0;
pub mod roa_cleanup_0_8_0;

//------------ UpgradeError --------------------------------------------------

#[derive(Debug)]
pub enum UpgradeError {
    AggregateStoreError(AggregateStoreError),
    KeyStoreError(KeyValueError),
    IoError(io::Error),
    Unrecognised(String),
    CannotLoadAggregate(Handle),
    RoaCleanup(RoaCleanupError),
    Custom(String),
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UpgradeError::AggregateStoreError(e) => e.fmt(f),
            UpgradeError::KeyStoreError(e) => e.fmt(f),
            UpgradeError::IoError(e) => e.fmt(f),
            UpgradeError::Unrecognised(s) => write!(f, "Unrecognised command summary: {}", s),
            UpgradeError::CannotLoadAggregate(handle) => write!(f, "Cannot load: {}", handle),
            UpgradeError::RoaCleanup(e) => write!(f, "Cannot clean up redundant roas: {}", e),
            UpgradeError::Custom(s) => s.fmt(f),
        }
    }
}
impl UpgradeError {
    pub fn custom(msg: impl fmt::Display) -> Self {
        UpgradeError::Custom(msg.to_string())
    }

    pub fn unrecognised(msg: impl fmt::Display) -> Self {
        UpgradeError::Unrecognised(msg.to_string())
    }
}

impl From<AggregateStoreError> for UpgradeError {
    fn from(e: AggregateStoreError) -> Self {
        UpgradeError::AggregateStoreError(e)
    }
}

impl From<KeyValueError> for UpgradeError {
    fn from(e: KeyValueError) -> Self {
        UpgradeError::KeyStoreError(e)
    }
}

impl From<file::Error> for UpgradeError {
    fn from(e: file::Error) -> Self {
        UpgradeError::IoError(e.into())
    }
}

impl From<io::Error> for UpgradeError {
    fn from(e: io::Error) -> Self {
        UpgradeError::IoError(e)
    }
}

impl From<RoaCleanupError> for UpgradeError {
    fn from(e: RoaCleanupError) -> Self {
        UpgradeError::RoaCleanup(e)
    }
}

//------------ UpgradeStore --------------------------------------------------

/// Implement this for automatic upgrades to key stores
pub trait UpgradeStore {
    fn needs_migrate(&self, store: &KeyValueStore) -> Result<bool, UpgradeError>;
    fn migrate(&self, store: &KeyValueStore) -> Result<(), UpgradeError>;

    fn version_same_or_before(kv: &KeyValueStore, up_to: KeyStoreVersion) -> Result<bool, UpgradeError> {
        let key = KeyStoreKey::simple("version".to_string());
        match kv.get::<KeyStoreVersion>(&key) {
            Err(e) => Err(UpgradeError::KeyStoreError(e)),
            Ok(None) => Ok(true),
            Ok(Some(current_version)) => Ok(current_version <= up_to),
        }
    }
}

/// Should be called when Krill starts, before the KrillServer is initiated
pub fn pre_start_upgrade(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    upgrade_pre_0_6_0_cas_commands(work_dir)?;
    upgrade_pre_0_6_0_pubd_commands(work_dir)?;
    upgrade_pre_fix_info_0_8_0(work_dir)
}

/// Should be called right after the KrillServer is initiated.
pub async fn post_start_upgrade(work_dir: &PathBuf, server: &KrillServer) -> Result<(), UpgradeError> {
    let ca_store: AggregateStore<CertAuth> = AggregateStore::new(work_dir, "cas")?;
    if ca_store.get_version()? < KeyStoreVersion::V0_8_0_RC1 {
        info!("Will clean up redundant ROAs for all CAs and update version of storage dirs");
        roa_cleanup_0_8_0::roa_cleanup(server).await?;
    }

    Ok(())
}

pub async fn update_storage_version(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    let ca_store: AggregateStore<CertAuth> = AggregateStore::new(work_dir, "cas")?;
    let pubd_store: AggregateStore<Repository> = AggregateStore::new(work_dir, "pubd")?;
    let current = KeyStoreVersion::current();
    ca_store.set_version(&current)?;
    pubd_store.set_version(&current)?;
    info!("Upgraded Krill to version: {}", KRILL_VERSION);
    Ok(())
}

fn upgrade_pre_0_6_0_cas_commands(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    let pre_0_6_0_ca_commands = pre_0_6_0::UpgradeCas;

    // Prepare to do the work on the real "cas" directory
    let mut cas_dir = work_dir.clone();
    cas_dir.push("cas");
    let kv = KeyValueStore::disk(work_dir, "cas")?;

    // bail out if there is nothing to do
    if !pre_0_6_0_ca_commands.needs_migrate(&kv)? {
        return Ok(());
    }

    info!("Krill will now upgrade pre-0.6.0 CA data");

    // Make a back-up directory first, so that we can fall back to it in case
    // the upgrade fails
    let mut backup_dir = work_dir.clone();
    backup_dir.push("cas_bk");
    file::backup_dir(&cas_dir, &backup_dir)?;

    if let Err(e) = pre_0_6_0_ca_commands.migrate(&kv) {
        // If the upgrade failed, then rename the now broken directory for inspection,
        // and restore the backup directory by renaming it.
        let mut failed = work_dir.clone();
        failed.push("cas-failed-upgrade");
        fs::rename(&cas_dir, &failed)?;
        fs::rename(&backup_dir, &cas_dir)?;

        // Return the error so that the krill startup can be aborted.
        Err(e)
    } else {
        // Upgrade successful
        let _ = fs::remove_dir_all(&backup_dir); // ignore if removing backup fails
        Ok(())
    }
}

fn upgrade_pre_0_6_0_pubd_commands(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    let pre_0_6_0_pubd_commands = pre_0_6_0::UpgradePubd;

    // Prepare to do the work on the real directory
    let mut pubd_dir = work_dir.clone();
    pubd_dir.push("pubd");
    let kv = KeyValueStore::disk(work_dir, "pubd")?;

    // bail out if there is nothing to do
    if !pre_0_6_0_pubd_commands.needs_migrate(&kv)? {
        return Ok(());
    }

    info!("Krill will now upgrade pre-0.6.0 Publication Server data");

    // Make a back-up directory first, so that we can fall back to it in case
    // the upgrade fails
    let mut backup_dir = work_dir.clone();
    backup_dir.push("pubd_bk");
    file::backup_dir(&pubd_dir, &backup_dir)?;

    if let Err(e) = pre_0_6_0_pubd_commands.migrate(&kv) {
        // If the upgrade failed, then rename the now broken directory for inspection,
        // and restore the backup directory by renaming it.
        let mut failed = work_dir.clone();
        failed.push("pubd-failed-upgrade");
        fs::rename(&pubd_dir, &failed)?;
        fs::rename(&backup_dir, &pubd_dir)?;

        // Return the error so that the krill startup can be aborted.
        Err(e)
    } else {
        // Upgrade successful
        let _ = fs::remove_dir_all(&backup_dir); // ignore if removing backup fails
        Ok(())
    }
}

fn upgrade_pre_fix_info_0_8_0(workdir: &PathBuf) -> Result<(), UpgradeError> {
    let migration = FixInfoFiles;

    let ca_kv = KeyValueStore::disk(workdir, "cas")?;
    let pubd_kv = KeyValueStore::disk(workdir, "pubd")?;

    migration.migrate(&ca_kv)?;
    migration.migrate(&pubd_kv)
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use crate::test;

    use crate::commons::eventsourcing::AggregateStore;
    use crate::constants::PUBSERVER_DFLT;
    use crate::daemon::ca::CertAuth;
    use crate::pubd::Repository;

    use super::*;

    #[test]
    fn upgrade_commands_0_6() {
        test::test_under_tmp(|tmp| {
            let cas_source = PathBuf::from("test-resources/api/regressions/v0_6_0/commands/migration/cas");
            let mut cas_test = tmp.clone();
            cas_test.push("cas");
            file::backup_dir(&cas_source, &cas_test).unwrap();

            let pubd_source = PathBuf::from("test-resources/api/regressions/v0_6_0/commands/migration/pubd");
            let mut pubd_test = tmp.clone();
            pubd_test.push("pubd");
            file::backup_dir(&pubd_source, &pubd_test).unwrap();

            pre_start_upgrade(&tmp).unwrap();
        })
    }

    /// This tests that we can understand all events as they have been implemented since 0.4.0,
    /// in order to guarantee that upgrades will work.
    ///
    /// The `test-resources/events` directory contains old event files that we will need to keep
    /// supporting in future versions.
    ///
    /// They are typically generated by the functional tests in the `tests` dir, and then copied and
    /// preserved here for testing. Because, programmatically generating the json and then parsing
    /// would of course not work for this purpose, new code would understand what it generates itself,
    /// we want to be sure that new code understands old code json.
    ///
    /// So, for each release of krill that may have introduced new event types and/or ways of serializing
    /// them, you will find a directory here with the events that were generated by those tests, and you
    /// will find a test that will attempt to create `CertAuth` and `Repository` instances by replaying
    /// them.
    ///
    /// Directory lay-out is as follows:
    ///
    /// test-resources/
    ///   events/
    ///     0.4.0/
    ///       ca_keyroll_under_rfc6492_ta/
    ///          /cas
    ///             /ta
    ///             /ca
    ///                .. CertAuth events for each instance
    ///          /pubd
    ///             .. Repository events and snapshot
    ///       other tests.
    ///     new versions
    #[test]
    fn upgrades_events_0_4_0() {
        since_0_4_0("ca_embedded", &["ta", "child"]);
        since_0_4_0("ca_grandchildren", &["ta", "CA1", "CA2", "CA3", "CA4"]);
        since_0_4_0("ca_keyroll_rfc6492", &["ta", "rfc6492"]);
        since_0_4_0("ca_rfc6492", &["ta", "rfc6492"]);
        since_0_4_0("ca_roas", &["ta", "child"]);
        publication_since_0_4_0();
    }

    fn since_0_4_0(scenario: &str, cas: &[&str]) {
        let work_dir = PathBuf::from(format!("test-resources/api/regressions/0.4.0/events/{}/", scenario));
        test_cas(&work_dir, cas);
        test_repo(&work_dir, "pubd");
    }

    fn publication_since_0_4_0() {
        let work_dir = PathBuf::from("test-resources/api/regressions/0.4.0/events/remote_publication/");
        test_cas(&work_dir, &["ta", "child"]);
        test_repo(&work_dir, "pubd");
        test_repo(&work_dir, "remote-pubd");
    }

    fn test_cas(work_dir: &PathBuf, cas: &[&str]) {
        let ca_store = AggregateStore::<CertAuth>::new(&work_dir, "cas").unwrap();

        for ca in cas {
            assert_no_snapshot(work_dir, &format!("cas/{}", ca));
            let ca_handle = Handle::from_str(ca).unwrap();
            if let Err(e) = ca_store.get_latest(&ca_handle) {
                panic!("Could not rebuild state for ca '{}', error: {}", ca, e);
            }
        }
    }

    fn test_repo(work_dir: &PathBuf, repo: &str) {
        let repo_store = AggregateStore::<Repository>::new(&work_dir, repo).unwrap();
        assert_no_snapshot(work_dir, &format!("{}/{}", repo, PUBSERVER_DFLT));
        let handle = Handle::from_str(PUBSERVER_DFLT).unwrap();
        if let Err(e) = repo_store.get_latest(&handle) {
            panic!("Could not rebuild state for repository: {}", e)
        }
    }

    fn assert_no_snapshot(workdir: &PathBuf, rel: &str) {
        let mut snapshot_file = workdir.clone();
        snapshot_file.push(rel);
        snapshot_file.push("snapshot.json");
        if snapshot_file.exists() {
            panic!(
                "Snapshot file should not exist for this test, remove: {}",
                snapshot_file.to_string_lossy().to_string()
            );
        }
    }
}
