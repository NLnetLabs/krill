use std::{
    fmt::Display,
    fs,
    fs::{File, OpenOptions},
    ops::{Deref, DerefMut},
    path::{Component, Path, PathBuf},
    thread,
    time::Duration,
};

use futures_util::Future;
use serde_json::Value;

use crate::commons::{
    error::KrillIoError,
    storage::{Key, KeyValueError, KeyValueStoreDispatcher, NamespaceBuf, Scope, SegmentBuf, StorageResult},
};

pub const LOCK_FILE_NAME: &str = "lockfile.lock";
pub const LOCK_FILE_DIR: &str = ".locks";

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Disk {
    root: PathBuf,
    tmp: PathBuf,
}

impl Disk {
    /// This will create a disk based store for the given (base) path and namespace.
    ///
    /// Under the hood this uses two directories: path/namespace and path/tmp.
    /// The latter is used for temporary files for new values for existing keys. Such
    /// values are written first and then renamed (moved) to avoid issues with partially
    /// written files because of I/O issues (disk full) or concurrent reads of the key
    /// as its value is being updated.
    ///
    /// Different instances of this disk based storage that use different namespaces,
    /// but share the same (base) path will all use the same tmp directory. This is
    /// not an issue as the temporary files will have unique names.
    pub fn new(path: &str, namespace: &str) -> StorageResult<Self> {
        let root = PathBuf::from(path).join(namespace);
        let tmp = PathBuf::from(path).join("tmp");

        if !tmp.exists() {
            fs::create_dir_all(&tmp).map_err(|e| {
                KeyValueError::IoError(KrillIoError::new(
                    format!("Cannot create directory for tmp files: {}", tmp.display()),
                    e,
                ))
            })?;
        }

        Ok(Disk { root, tmp })
    }
}

impl Display for Disk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local://{}", self.root.display())
    }
}

impl Disk {
    pub fn is_empty(&self) -> StorageResult<bool> {
        if let Ok(entries) = self.root.read_dir() {
            for e in entries.into_iter().flatten() {
                if !e.path().ends_with(LOCK_FILE_DIR) {
                    return Ok(false);
                }
            }
        }
        // non existent dir counts as empty
        Ok(true)
    }

    pub fn has(&self, key: &Key) -> StorageResult<bool> {
        let exists = key.as_path(&self.root).exists();
        Ok(exists)
    }

    pub fn has_scope(&self, scope: &Scope) -> StorageResult<bool> {
        let exists = scope.as_path(&self.root).try_exists().map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(format!("cannot get path for scope: {}", scope), e))
        })?;
        Ok(exists)
    }

    pub fn get(&self, key: &Key) -> StorageResult<Option<Value>> {
        let path = key.as_path(&self.root);
        if path.exists() {
            let value =
                fs::read_to_string(key.as_path(&self.root)).map_err(|_| KeyValueError::UnknownKey(key.clone()))?;

            let value: Value = serde_json::from_str(&value)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    pub fn list_keys(&self, scope: &Scope) -> StorageResult<Vec<Key>> {
        let path = scope.as_path(&self.root);
        if !path.exists() {
            return Ok(vec![]);
        }

        let lock_file_segment = SegmentBuf::parse_lossy(LOCK_FILE_NAME);

        list_files_recursive(scope.as_path(&self.root))?
            .into_iter()
            .map(|path| path.as_key(&self.root))
            .filter(|key_res| match key_res {
                Ok(key) => key.name() != lock_file_segment.as_ref(),
                _ => true,
            })
            .collect()
    }

    pub fn list_scopes(&self) -> StorageResult<Vec<Scope>> {
        list_dirs_recursive(Scope::global().as_path(&self.root))?
            .into_iter()
            .map(|path| path.as_scope(&self.root))
            .collect()
    }
}

impl Disk {
    /// Stores a value on disk. We always write the entire value into
    /// a tempfile first, to ensure that it is written completely, before
    /// renaming it to the actual file for the key.
    pub fn store(&self, key: &Key, value: Value) -> StorageResult<()> {
        let path = key.as_path(&self.root);
        let dir = key.scope().as_path(&self.root);

        if key.scope().to_string().starts_with(LOCK_FILE_DIR) {
            return Err(KeyValueError::InvalidKey(key.clone()));
        }

        if !dir.try_exists().unwrap_or_default() {
            fs::create_dir_all(&dir).map_err(|e| {
                KeyValueError::IoError(KrillIoError::new(
                    format!("cannot create dir for path: {}", dir.display()),
                    e,
                ))
            })?;
        }

        // We use a tempfile to prevent that we can have half-written files in
        // case Krill is suddenly stopped, e.g. because of a reboot or server
        // crash. Or in case the file system runs out of space during writing.
        // See issue #1160.
        //
        // After the file is completely written, we rename (move) it.
        //
        // We use the tempfile crate, because it ensures that the temporary file
        // is cleaned up in case we encounter an error in this function.
        let tmp_file = tempfile::NamedTempFile::new_in(&self.tmp).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(
                format!(
                    "Issue writing tmp file for key: {}. Check permissions and space on disk.",
                    key
                ),
                e,
            ))
        })?;

        fs::write(&tmp_file, format!("{:#}", value).as_bytes()).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(
                format!(
                    "Issue writing tmp file: {} for key: {}. Check permissions and space on disk.",
                    tmp_file.as_ref().display(),
                    key
                ),
                e,
            ))
        })?;

        // Persist the tempfile at the target path. On linux this will use
        // an (atomic) move to rename the file. If an old file exists, it
        // is replaced.
        tmp_file.persist(&path).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(
                format!(
                    "Cannot rename temp file {} to {}.",
                    e.file.path().display(),
                    path.display()
                ),
                e.error,
            ))
        })?;

        Ok(())
    }

    pub fn move_value(&self, from: &Key, to: &Key) -> StorageResult<()> {
        let from_path = from.as_path(&self.root);
        let to_path = to.as_path(&self.root);

        let dir = to.scope().as_path(&self.root);
        if !dir.try_exists().unwrap_or_default() {
            fs::create_dir_all(&dir).map_err(|e| {
                KeyValueError::IoError(KrillIoError::new(format!("cannot create dir for {}", dir.display()), e))
            })?;
        }

        fs::rename(&from_path, &to_path).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(
                format!(
                    "cannot rename file from {} to {}",
                    from_path.display(),
                    to_path.display()
                ),
                e,
            ))
        })?;
        remove_empty_parent_dirs(from_path.parent().ok_or(KeyValueError::Other(format!(
            "cannot get parent for path: {}",
            from_path.display()
        )))?);

        Ok(())
    }

    pub fn delete(&self, key: &Key) -> StorageResult<()> {
        let path = key.as_path(&self.root);

        fs::remove_file(&path).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(format!("cannot remove file: {}", path.display()), e))
        })?;
        remove_empty_parent_dirs(path.parent().ok_or(KeyValueError::Other(format!(
            "cannot get parent dir for: {}",
            path.display()
        )))?);

        Ok(())
    }

    pub fn delete_scope(&self, scope: &Scope) -> StorageResult<()> {
        let path = scope.as_path(&self.root);

        fs::remove_dir_all(&path).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(
                format!("cannot remove dir for {}", path.display()),
                e,
            ))
        })?;
        remove_empty_parent_dirs(path);

        Ok(())
    }

    pub fn clear(&self) -> StorageResult<()> {
        if self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }

        Ok(())
    }

    pub fn migrate_namespace(&mut self, namespace: NamespaceBuf) -> StorageResult<()> {
        let root_parent = self.root.parent().ok_or(KeyValueError::Other(format!(
            "cannot get parent dir for: {}",
            self.root.display()
        )))?;

        let new_root = root_parent.join(namespace.as_str());

        if new_root.exists() {
            // If the target directory already exists, then it must be empty.
            if new_root
                .read_dir()
                .map_err(|e| {
                    KeyValueError::Other(format!("cannot read directory '{}'. Error: {}", new_root.display(), e,))
                })?
                .next()
                .is_some()
            {
                return Err(KeyValueError::Other(format!(
                    "target dir {} already exists and is not empty",
                    new_root.display(),
                )));
            }
        }

        fs::rename(&self.root, &new_root).map_err(|e| {
            KeyValueError::Other(format!(
                "cannot rename dir from {} to {}. Error: {}",
                self.root.display(),
                new_root.display(),
                e
            ))
        })?;
        self.root = new_root;
        Ok(())
    }
}

impl Disk {
    pub async fn execute<'f, F, T, Ret>(&self, scope: &Scope, op: F) -> Result<T, KeyValueError>
    where
        F: FnOnce(KeyValueStoreDispatcher) -> Ret,
        Ret: Future<Output = Result<T, KeyValueError>>,
    {
        let lock_file_dir = self.root.join(LOCK_FILE_DIR);

        let _lock = FileLock::lock(scope.as_path(lock_file_dir))?;

        let dispatcher = KeyValueStoreDispatcher::Disk(self.clone());

        op(dispatcher).await
    }
}

trait AsPath {
    fn as_path(&self, root: impl AsRef<Path>) -> PathBuf;
}

impl AsPath for Key {
    fn as_path(&self, root: impl AsRef<Path>) -> PathBuf {
        let mut path = root.as_ref().to_path_buf();
        for segment in self.scope() {
            path.push(segment.as_str());
        }
        path.push(self.name().as_str());
        path
    }
}

impl AsPath for Scope {
    fn as_path(&self, root: impl AsRef<Path>) -> PathBuf {
        let mut path = root.as_ref().to_path_buf();
        for segment in self {
            path.push(segment.as_str());
        }
        path
    }
}

trait PathBufExt {
    fn as_key(&self, root: impl AsRef<Path>) -> StorageResult<Key>;

    fn as_scope(&self, root: impl AsRef<Path>) -> StorageResult<Scope>;
}

impl PathBufExt for PathBuf {
    fn as_key(&self, root: impl AsRef<Path>) -> StorageResult<Key> {
        let file_name = self
            .file_name()
            .ok_or(KeyValueError::Other(format!(
                "cannot get file name from path: {}",
                self.display()
            )))?
            .to_string_lossy()
            .to_string();

        let name: SegmentBuf = file_name.parse().map_err(|e| {
            KeyValueError::Other(format!(
                "Cannot get key segments from path '{}'. Error: {}",
                file_name, e
            ))
        })?;

        let scope = self
            .parent()
            .ok_or(KeyValueError::Other(format!(
                "Cannot get parent path for {}",
                self.display()
            )))?
            .to_path_buf()
            .as_scope(root)?;

        Ok(Key::new_scoped(scope, name))
    }

    fn as_scope(&self, root: impl AsRef<Path>) -> StorageResult<Scope> {
        let segments = self
            .strip_prefix(root)
            .map_err(|e| KeyValueError::Other(format!("cannot strip prefix: {}", e)))?
            .components()
            .map(|component| match component {
                Component::Prefix(_) | Component::RootDir | Component::CurDir | Component::ParentDir => {
                    Err(KeyValueError::Other(format!(
                        "unexpected path component: {}",
                        component.as_os_str().to_string_lossy()
                    )))
                }
                Component::Normal(segment) => {
                    let segment: SegmentBuf = segment.to_string_lossy().parse().map_err(|e| {
                        KeyValueError::Other(format!(
                            "cannot convert path component '{}' to segment. Error: {}",
                            segment.to_string_lossy(),
                            e
                        ))
                    })?;
                    Ok(segment)
                }
            })
            .collect::<StorageResult<_>>()?;

        Ok(Scope::new(segments))
    }
}

#[derive(Debug)]
struct FileLock {
    file: File,
    lock_path: PathBuf,
}

impl FileLock {
    const POLL_LOCK_INTERVAL: Duration = Duration::from_millis(10);

    pub fn lock(path: impl AsRef<Path>) -> StorageResult<Self> {
        let path = path.as_ref();

        let lock_path = path.join(LOCK_FILE_NAME);
        if !path.try_exists().unwrap_or_default() {
            fs::create_dir_all(path).map_err(|e| {
                KeyValueError::IoError(KrillIoError::new(
                    format!("cannot create dir for lockfile {}", lock_path.display()),
                    e,
                ))
            })?;
        }

        let file = loop {
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&lock_path);

            match file {
                Ok(file) => break file,
                _ => thread::sleep(Self::POLL_LOCK_INTERVAL),
            };
        };

        let lock = FileLock { file, lock_path };

        Ok(lock)
    }

    pub fn unlock(&self) -> StorageResult<()> {
        fs::remove_file(&self.lock_path).map_err(|e| {
            KeyValueError::IoError(KrillIoError::new(
                format!("cannot remove lock file {}", self.lock_path.display()),
                e,
            ))
        })?;
        Ok(())
    }
}

impl Deref for FileLock {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl DerefMut for FileLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        self.unlock().ok();
    }
}

fn list_files_recursive(dir: impl AsRef<Path>) -> StorageResult<Vec<PathBuf>> {
    let mut files = Vec::new();

    for result in fs::read_dir(&dir).map_err(|e| {
        KeyValueError::IoError(KrillIoError::new(
            format!("cannot read dir {}", dir.as_ref().display()),
            e,
        ))
    })? {
        let path = result
            .map_err(|e| {
                KeyValueError::IoError(KrillIoError::new(
                    format!("cannot read entry in dir {}", dir.as_ref().display()),
                    e,
                ))
            })?
            .path();

        if path.is_dir() {
            files.extend(list_files_recursive(path)?);
        } else {
            files.push(path);
        }
    }

    Ok(files)
}

fn list_dirs_recursive(dir: impl AsRef<Path>) -> StorageResult<Vec<PathBuf>> {
    let mut dirs = Vec::new();

    for result in fs::read_dir(&dir).map_err(|e| {
        KeyValueError::IoError(KrillIoError::new(
            format!("cannot read dir {}", dir.as_ref().display()),
            e,
        ))
    })? {
        let path = result
            .map_err(|e| {
                KeyValueError::IoError(KrillIoError::new(
                    format!("cannot get entry in dir {}", dir.as_ref().display()),
                    e,
                ))
            })?
            .path();
        if path.is_dir()
            && !path.ends_with(LOCK_FILE_DIR)
            && path
                .read_dir()
                .map_err(|e| {
                    KeyValueError::IoError(KrillIoError::new(
                        format!("cannot read dir {}", dir.as_ref().display()),
                        e,
                    ))
                })?
                .next()
                .is_some()
        {
            // a non-empty directory exists for the scope, recurse and add
            dirs.extend(list_dirs_recursive(&path)?);
            dirs.push(path);
        }
    }

    Ok(dirs)
}

/// Removes the given directory and all empty parent directories. This function
/// only works on empty directories and will do nothing for files.
fn remove_empty_parent_dirs(path: impl AsRef<Path>) {
    let mut ancestors = path.as_ref().ancestors();
    while ancestors.next().and_then(|path| fs::remove_dir(path).ok()).is_some() {}
}
