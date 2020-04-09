//! Support Krill upgrades, e.g.:
//! - Updating the format of commands or events
//! - Export / Import data

use std::path::PathBuf;
use std::{fmt, fs, io};

use crate::commons::api::Handle;
use crate::commons::eventsourcing::{DiskKeyStore, KeyStore, KeyStoreError};
use crate::commons::util::file;

pub mod pre_0_6_0;

//------------ UpgradeError --------------------------------------------------

#[derive(Debug, Display)]
pub enum UpgradeError {
    #[display(fmt = "{}", _0)]
    KeyStoreError(KeyStoreError),

    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "Unrecognised command summary: {}", _0)]
    Unrecognised(String),

    #[display(fmt = "Cannot load: {}", _0)]
    CannotLoadAggregate(Handle),

    #[display(fmt = "{}", _0)]
    Custom(String),
}

impl UpgradeError {
    pub fn custom(msg: impl fmt::Display) -> Self {
        UpgradeError::Custom(msg.to_string())
    }

    pub fn unrecognised(msg: impl fmt::Display) -> Self {
        UpgradeError::Unrecognised(msg.to_string())
    }
}

impl From<KeyStoreError> for UpgradeError {
    fn from(e: KeyStoreError) -> Self {
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

//------------ UpgradeStore --------------------------------------------------

/// Implement this for automatic upgrades to key stores
pub trait UpgradeStore {
    fn needs_migrate<S: KeyStore>(&self, store: &S) -> Result<bool, UpgradeError>;
    fn migrate<S: KeyStore>(&self, store: &S) -> Result<(), UpgradeError>;
}

/// Should be called when Krill starts
pub fn upgrade(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    upgrade_pre_0_6_0_cas_commands(work_dir)
}

fn upgrade_pre_0_6_0_cas_commands(work_dir: &PathBuf) -> Result<(), UpgradeError> {
    let pre_0_6_0_ca_commands = pre_0_6_0::UpgradeCas;

    // Prepare to do the work on the real "cas" directory
    let mut cas_dir = work_dir.clone();
    cas_dir.push("cas");
    let ca_store = DiskKeyStore::new(work_dir, "cas");

    // bail out if there is nothing to do
    if !pre_0_6_0_ca_commands.needs_migrate(&ca_store)? {
        return Ok(());
    }

    // Make a back-up directory first, so that we can fall back to it in case
    // the upgrade fails
    let mut backup_dir = work_dir.clone();
    backup_dir.push("cas_bk");
    file::backup_dir(&cas_dir, &backup_dir)?;

    if let Err(e) = pre_0_6_0_ca_commands.migrate(&ca_store) {
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

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test;

    use super::*;

    #[test]
    fn upgrade_pre_0_6() {
        test::test_under_tmp(|tmp| {
            let base_path = PathBuf::from("test-resources/upgrades/v0_6_0/before/cas");
            let mut target = tmp.clone();
            target.push("cas");
            file::backup_dir(&base_path, &target).unwrap();

            upgrade(&tmp).unwrap();
        })
    }

    #[test]
    fn upgrade_pre_0_6_nlnetlabs_prod() {
        test::test_under_tmp(|tmp| {
            let base_path = PathBuf::from("test-resources/upgrades/v0_6_0/before/cas-prod");
            let mut target = tmp.clone();
            target.push("cas");
            file::backup_dir(&base_path, &target).unwrap();

            upgrade(&tmp).unwrap();
        })
    }
}
