use std::any::Any;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::{fs, io};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::commons::api::{CommandHistoryCriteria, Handle};
use crate::commons::eventsourcing::{
    CommandKey, KeyStore, KeyStoreError, KeyStoreVersion, StoredCommand, WithStorableDetails,
};
use crate::commons::util::file;

/// This type can store and retrieve values to/from disk, using json
/// serialization.
pub struct DiskKeyStore {
    dir: PathBuf,
}

impl KeyStore for DiskKeyStore {
    type Key = PathBuf;

    fn get_version(&self) -> Result<KeyStoreVersion, KeyStoreError> {
        if !self.dir.exists() {
            Err(KeyStoreError::NotInitialised)
        } else {
            let path = self.version_path();
            if path.exists() {
                let f = File::open(path)?;

                match serde_json::from_reader(f) {
                    Err(e) => {
                        error!("Could not read current version of keystore");
                        Err(KeyStoreError::JsonError(e))
                    }
                    Ok(v) => Ok(v),
                }
            } else {
                Ok(KeyStoreVersion::Pre0_6)
            }
        }
    }

    fn set_version(&self, version: &KeyStoreVersion) -> Result<(), KeyStoreError> {
        let path = self.version_path();
        let mut f = file::create_file_with_path(&path)?;
        let json = serde_json::to_string_pretty(version)?;
        f.write_all(json.as_ref())?;
        Ok(())
    }

    fn key_for_info() -> PathBuf {
        PathBuf::from("info.json")
    }

    fn key_for_snapshot() -> PathBuf {
        PathBuf::from("snapshot.json")
    }

    fn key_for_backup_snapshot() -> PathBuf {
        PathBuf::from("snapshot-bk.json")
    }

    fn key_for_event(version: u64) -> PathBuf {
        PathBuf::from(format!("delta-{}.json", version))
    }

    fn key_for_command<S: WithStorableDetails>(command: &StoredCommand<S>) -> CommandKey {
        CommandKey::new(command.sequence(), command.time(), command.details().summary().label)
    }

    fn key_for_archived(key: &PathBuf) -> PathBuf {
        PathBuf::from("archived").join(key)
    }

    fn key_for_corrupt(key: &PathBuf) -> PathBuf {
        PathBuf::from("corrupt").join(key)
    }

    fn key_for_surplus(key: &PathBuf) -> PathBuf {
        PathBuf::from("surplus").join(key)
    }

    fn keys(&self, id: &Handle, matching: &str) -> Vec<PathBuf> {
        let mut res = vec![];
        let dir = self.dir_for_aggregate(id);
        if let Ok(entry_results) = fs::read_dir(dir) {
            for entry_result in entry_results {
                if let Ok(dir_entry) = entry_result {
                    let file_name = dir_entry.file_name();
                    if file_name.to_string_lossy().contains(matching) {
                        res.push(PathBuf::from(file_name));
                    }
                }
            }
        }

        res
    }

    fn keys_ascending(&self, id: &Handle, matching: &str) -> Vec<PathBuf> {
        let mut res = self.keys(id, matching);
        #[allow(clippy::unnecessary_sort_by)]
        res.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        res
    }

    fn command_keys_ascending(&self, id: &Handle, crit: &CommandHistoryCriteria) -> Vec<CommandKey> {
        let mut command_keys = vec![];

        for key in self.keys(id, "command--") {
            if let Ok(command_key) = CommandKey::try_from(key) {
                if command_key.matches_crit(crit) {
                    command_keys.push(command_key);
                }
            }
        }

        command_keys.sort_by(|a, b| a.sequence.cmp(&b.sequence));
        command_keys
    }

    fn has_key(&self, id: &Handle, key: &PathBuf) -> bool {
        self.file_path(id, key).exists()
    }

    fn has_aggregate(&self, id: &Handle) -> bool {
        self.dir_for_aggregate(id).exists()
    }

    fn aggregates(&self) -> Vec<Handle> {
        let mut res: Vec<Handle> = Vec::new();

        if let Ok(dir) = fs::read_dir(&self.dir) {
            for d in dir {
                if let Ok(d) = d {
                    let path = d.path();
                    if path.is_dir() {
                        if let Ok(id) = Handle::try_from(&path) {
                            res.push(id);
                        }
                    }
                }
            }
        }

        res
    }

    fn store<V: Any + Serialize>(&self, id: &Handle, key: &PathBuf, value: &V) -> Result<(), KeyStoreError> {
        let mut f = file::create_file_with_path(&self.file_path(id, key))?;
        let json = serde_json::to_string_pretty(value)?;
        f.write_all(json.as_ref())?;
        Ok(())
    }

    fn get<V: DeserializeOwned>(&self, id: &Handle, key: &PathBuf) -> Result<Option<V>, KeyStoreError> {
        let path = self.file_path(id, key);
        let path_str = path.to_string_lossy().into_owned();

        if path.exists() {
            let f = File::open(path)?;
            match serde_json::from_reader(f) {
                Err(e) => {
                    warn!("Ignoring file '{}', could not deserialize json: '{}'.", path_str, e);
                    Ok(None)
                }
                Ok(v) => {
                    trace!("Deserialized json at: {}", path_str);
                    Ok(Some(v))
                }
            }
        } else {
            trace!("Could not find file at: {}", path_str);
            Ok(None)
        }
    }

    /// Delete a key-value pair
    fn drop(&self, id: &Handle, key: &PathBuf) -> Result<(), KeyStoreError> {
        let path = self.file_path(id, key);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn move_key(&self, id: &Handle, from: &PathBuf, to: &PathBuf) -> Result<(), KeyStoreError> {
        let from = self.file_path(id, from);
        let to = self.file_path(id, to);

        if let Ok(bytes) = file::read(&from) {
            file::save(bytes.as_ref(), &to)?;
            fs::remove_file(&from)?;
        }

        Ok(())
    }
}

impl DiskKeyStore {
    pub fn new(work_dir: &PathBuf, name_space: &str) -> Self {
        let mut dir = work_dir.clone();
        dir.push(name_space);
        DiskKeyStore { dir }
    }

    /// Creates a directory for the name_space under the work_dir.
    pub fn under_work_dir(work_dir: &PathBuf, name_space: &str) -> Result<Self, io::Error> {
        let mut path = work_dir.clone();
        path.push(name_space);
        if !path.is_dir() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self::new(work_dir, name_space))
    }

    fn version_path(&self) -> PathBuf {
        let mut path = self.dir.clone();
        path.push("version");
        path
    }

    fn file_path(&self, id: &Handle, key: &<Self as KeyStore>::Key) -> PathBuf {
        let mut file_path = self.dir_for_aggregate(id);
        file_path.push(key);
        file_path
    }

    fn dir_for_aggregate(&self, id: &Handle) -> PathBuf {
        let mut dir_path = self.dir.clone();
        dir_path.push(id.to_path_buf());
        dir_path
    }
}
