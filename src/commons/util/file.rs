use std::{
    borrow::Cow,
    fmt, fs,
    fs::File,
    io::{self, Read, Write},
    path::Path,
    path::PathBuf,
    str::FromStr,
};

use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};

use rpki::uri;

use crate::commons::{
    api::{Base64, HexEncodedHash, ListElement, Publish, Update, Withdraw},
    error::KrillIoError,
};

/// Creates a sub dir if needed, return full path to it
pub fn sub_dir(base: &Path, name: &str) -> Result<PathBuf, KrillIoError> {
    let mut full_path = base.to_path_buf();
    full_path.push(name);
    create_dir(&full_path)?;
    Ok(full_path)
}

pub fn create_dir(dir: &Path) -> Result<(), KrillIoError> {
    if !dir.is_dir() {
        fs::create_dir_all(dir)
            .map_err(|e| KrillIoError::new(format!("could not create dir: {}", dir.to_string_lossy()), e))?;
    }
    Ok(())
}

pub fn remove_dir_all(dir: &Path) -> Result<(), KrillIoError> {
    if dir.exists() {
        fs::remove_dir_all(dir)
            .map_err(|e| KrillIoError::new(format!("could not remove-all dir: {}", dir.to_string_lossy()), e))?;
    }
    Ok(())
}

pub fn create_file_with_path(path: &Path) -> Result<File, KrillIoError> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            trace!("Creating path: {}", parent.to_string_lossy());
            fs::create_dir_all(parent).map_err(|e| {
                KrillIoError::new(
                    format!("Could not create dir path for: {}", parent.to_string_lossy()),
                    e,
                )
            })?;
        }
    }
    File::create(path).map_err(|e| KrillIoError::new(format!("Could not create file: {}", path.to_string_lossy()), e))
}

/// Derive the path for this file.
pub fn file_path(base_path: &Path, file_name: &str) -> PathBuf {
    let mut path = base_path.to_path_buf();
    path.push(file_name);
    path
}

/// Saves a file, creating parent dirs as needed
pub fn save(content: &[u8], full_path: &Path) -> Result<(), KrillIoError> {
    let mut f = create_file_with_path(full_path)?;
    f.write_all(content)
        .map_err(|e| KrillIoError::new(format!("Could not write to: {}", full_path.to_string_lossy()), e))?;

    trace!("Saved file: {}", full_path.to_string_lossy());
    Ok(())
}

/// Saves an object to json - unwraps any json errors!
pub fn save_json<O: Serialize>(object: &O, full_path: &Path) -> Result<(), KrillIoError> {
    let json = serde_json::to_string(object).unwrap();
    save(&Bytes::from(json), full_path)
}

/// Loads a files and deserializes as json for the expected type. Maps json errors to KrillIoError
pub fn load_json<O: DeserializeOwned>(full_path: &Path) -> Result<O, KrillIoError> {
    let bytes = read(full_path)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        KrillIoError::new(
            format!("Could not load json for file: {}", full_path.to_string_lossy()),
            io::Error::new(io::ErrorKind::Other, format!("could not deserialize json: {}", e)),
        )
    })
}

/// Saves a file, creating parent dirs as needed
pub fn save_in_dir(content: &Bytes, base_path: &Path, name: &str) -> Result<(), KrillIoError> {
    let mut full_path = base_path.to_path_buf();
    full_path.push(name);
    save(content, &full_path)
}

/// Saves a file under a base directory, using the rsync uri to create
/// sub-directories preserving the rsync authority and module in dir names.
pub fn save_with_rsync_uri(content: &Bytes, base_path: &Path, uri: &uri::Rsync) -> Result<(), KrillIoError> {
    let path = path_with_rsync(base_path, uri);
    save(content, &path)
}

/// Reads a file to Bytes
pub fn read(path: &Path) -> Result<Bytes, KrillIoError> {
    let mut f =
        File::open(path).map_err(|e| KrillIoError::new(format!("Could not open: '{}'", path.to_string_lossy()), e))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|e| KrillIoError::new(format!("Could not read: {}", path.to_string_lossy()), e))?;
    Ok(Bytes::from(bytes))
}

pub fn read_with_rsync_uri(base_path: &Path, uri: &uri::Rsync) -> Result<Bytes, KrillIoError> {
    let path = path_with_rsync(base_path, uri);
    read(&path)
}

pub fn delete_with_rsync_uri(base_path: &Path, uri: &uri::Rsync) -> Result<(), KrillIoError> {
    delete_file(&path_with_rsync(base_path, uri))
}

pub fn delete_in_dir(base_path: &Path, name: &str) -> Result<(), KrillIoError> {
    let mut full_path = base_path.to_path_buf();
    full_path.push(name);
    delete_file(&full_path)
}

/// Deletes a file, but does not touch the parent directories. See [`clean_file_and_path`] for an alternative
/// that does.
pub fn delete_file(full_path: &Path) -> Result<(), KrillIoError> {
    trace!("Removing file: {}", full_path.to_string_lossy());
    fs::remove_file(full_path)
        .map_err(|e| KrillIoError::new(format!("Could not remove file: {}", full_path.to_string_lossy()), e))
}

/// Removes the file and any **empty** directories on the path after removing it.
pub fn clean_file_and_path(path: &Path) -> Result<(), KrillIoError> {
    if path.exists() {
        delete_file(path)?;

        let mut parent_opt = path.parent();

        while parent_opt.is_some() {
            let parent = parent_opt.unwrap();
            if parent
                .read_dir()
                .map_err(|e| KrillIoError::new(format!("Could not read directory: '{}'", parent.to_string_lossy()), e))?
                .count()
                == 0
            {
                trace!("Will delete {}", parent.to_string_lossy().to_string());
                fs::remove_dir(parent)
                    .map_err(|e| KrillIoError::new(format!("Could not remove dir: {}", parent.to_string_lossy()), e))?;
            }

            parent_opt = parent.parent();
        }
    }
    Ok(())
}

fn path_with_rsync(base_path: &Path, uri: &uri::Rsync) -> PathBuf {
    let mut path = base_path.to_path_buf();
    path.push(uri.authority());
    path.push(uri.module_name());
    path.push(uri.path());
    path
}

/// Recurses a path on disk and returns all files found as ['CurrentFile'],
/// using the provided rsync_base URI as the rsync prefix.
/// Allows a publication client to publish the contents below some base
/// dir, in their own designated rsync URI name space.
pub fn crawl_incl_rsync_base(base_path: &Path, rsync_base: &uri::Rsync) -> Result<Vec<CurrentFile>, Error> {
    crawl_disk(base_path, base_path, Some(rsync_base))
}

/// Recurses a path on disk and returns all files found as ['CurrentFile'],
/// deriving the rsync_base URI from the directory structure. This is
/// useful when reading ['CurrentFile'] instances that were saved in some
/// base directory as is done by the ['FileStore'].
pub fn crawl_derive_rsync_uri(base_path: &Path) -> Result<Vec<CurrentFile>, Error> {
    crawl_disk(base_path, base_path, None)
}

fn crawl_disk(base_path: &Path, path: &Path, rsync_base: Option<&uri::Rsync>) -> Result<Vec<CurrentFile>, Error> {
    let mut res = Vec::new();

    for entry in fs::read_dir(path).map_err(|_| Error::cannot_read(path))? {
        let entry = entry.map_err(|_| Error::cannot_read(path))?;
        let path = entry.path();
        if path.is_dir() {
            let mut other = crawl_disk(base_path, &path, rsync_base)?;
            res.append(&mut other);
        } else {
            let uri = derive_uri(base_path, &path, rsync_base)?;
            let content = read(&path).map_err(|_| Error::cannot_read(&path))?;
            let current_file = CurrentFile::new(uri, &content);

            res.push(current_file);
        }
    }

    Ok(res)
}

fn derive_uri(base_path: &Path, path: &Path, rsync_base: Option<&uri::Rsync>) -> Result<uri::Rsync, Error> {
    let rel = path.strip_prefix(base_path).map_err(|_| Error::PathOutsideBasePath)?;

    let rel_string = rel.to_string_lossy().to_string();

    let uri_string = match rsync_base {
        Some(rsync_base) => format!("{}{}", rsync_base.to_string(), rel_string),
        None => format!("rsync://{}", rel_string),
    };

    let uri = uri::Rsync::from_str(&uri_string).map_err(|_| Error::UnsupportedFileName(uri_string))?;
    Ok(uri)
}

/// Recursively copy a base_path (if it's a dir that is), and preserve the permissions
/// timestamps and all that goodness..
///
/// This is needed when making a back-up copy when we need to do upgrades on data, which
/// could in theory fail, in which case we want to leave teh old data in place.
pub fn backup_dir(base_path: &Path, target_path: &Path) -> Result<(), Error> {
    if base_path.to_string_lossy() == Cow::Borrowed("/") || target_path.to_string_lossy() == Cow::Borrowed("/") {
        Err(Error::BackupExcessive)
    } else if base_path.is_file() {
        let mut target = target_path.to_path_buf();
        target.push(base_path.file_name().unwrap());

        if target.exists() {
            Err(Error::backup_target_exists(target_path))
        } else {
            fs::copy(base_path, target_path).map_err(|e| {
                KrillIoError::new(
                    format!(
                        "Could not back up file from '{}' to '{}'",
                        base_path.to_string_lossy(),
                        target_path.to_string_lossy()
                    ),
                    e,
                )
            })?;
            Ok(())
        }
    } else if base_path.is_dir() {
        for entry in fs::read_dir(base_path).map_err(|e| {
            KrillIoError::new(
                format!("Could not read dir '{}' for backup", base_path.to_string_lossy()),
                e,
            )
        })? {
            let path = entry
                .map_err(|e| {
                    KrillIoError::new(
                        format!(
                            "Could not read entry for dir '{}' for backup",
                            base_path.to_string_lossy()
                        ),
                        e,
                    )
                })?
                .path();
            let mut target = target_path.to_path_buf();
            target.push(path.file_name().unwrap());
            if path.is_dir() {
                backup_dir(&path, &target)?;
            } else if path.is_file() {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        KrillIoError::new(
                            format!("Could not create dir(s) '{}' for backup", parent.to_string_lossy()),
                            e,
                        )
                    })?;
                }
                fs::copy(&path, &target).map_err(|e| {
                    KrillIoError::new(
                        format!(
                            "Could not backup '{}' to '{}'",
                            path.to_string_lossy(),
                            target.to_string_lossy()
                        ),
                        e,
                    )
                })?;
            } else {
                return Err(Error::backup_cannot_read(&path));
            }
        }
        Ok(())
    } else {
        Err(Error::backup_cannot_read(base_path))
    }
}

//------------ CurrentFile ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentFile {
    /// The full uri for this file.
    uri: uri::Rsync,

    /// The actual file content. Note that we may want to store this
    /// only on disk in future (look up by sha256 hash), to save memory.
    content: Base64,

    /// The sha-256 hash of the file (as is used on the RPKI manifests and
    /// in the publication protocol for list, update and withdraw). Saving
    /// this rather than calculating on demand seems a small price for some
    /// performance gain.
    hash: HexEncodedHash,
}

impl CurrentFile {
    pub fn new(uri: uri::Rsync, content: &Bytes) -> Self {
        let content = Base64::from_content(content);
        let hash = content.to_encoded_hash();
        CurrentFile { uri, content, hash }
    }

    /// Saves this file under a base directory, based on the (rsync) uri of
    /// this file.
    pub fn save(&self, base_path: &Path) -> Result<(), KrillIoError> {
        save_with_rsync_uri(&self.content.to_bytes(), base_path, &self.uri)
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn content(&self) -> &Base64 {
        &self.content
    }

    pub fn to_bytes(&self) -> Bytes {
        self.content.to_bytes()
    }

    pub fn hash(&self) -> &HexEncodedHash {
        &self.hash
    }

    pub fn as_publish(&self) -> Publish {
        let tag = Some(self.hash.to_string());
        let uri = self.uri.clone();
        let content = self.content.clone();
        Publish::new(tag, uri, content)
    }

    pub fn as_update(&self, old_hash: &HexEncodedHash) -> Update {
        let tag = None;
        let uri = self.uri.clone();
        let content = self.content.clone();
        let hash = old_hash.clone();
        Update::new(tag, uri, content, hash)
    }

    pub fn as_withdraw(&self) -> Withdraw {
        let tag = None;
        let uri = self.uri.clone();
        let hash = self.hash.clone();
        Withdraw::new(tag, uri, hash)
    }

    pub fn into_list_element(self) -> ListElement {
        ListElement::new(self.uri, self.hash)
    }
}

impl PartialEq for CurrentFile {
    fn eq(&self, other: &CurrentFile) -> bool {
        self.uri == other.uri && self.hash == other.hash && self.content == other.content
    }
}

impl Eq for CurrentFile {}

//------------ Error ---------------------------------------------------------
#[derive(Debug)]
pub enum Error {
    CannotRead(String),
    UnsupportedFileName(String),
    PathOutsideBasePath,
    BackupExcessive,
    BackupCannotReadSource(String),
    BackupTargetExists(String),
    Io(KrillIoError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::CannotRead(s) => write!(f, "Cannot read: {}", s),
            Error::UnsupportedFileName(name) => write!(f, "Unsupported characters: {}", name),
            Error::PathOutsideBasePath => write!(f, "Cannot use path outside of rsync jail"),
            Error::BackupExcessive => write!(f, "Do not ever use '/' as the source or target for backups"),
            Error::BackupCannotReadSource(e) => write!(f, "Source for backup cannot be read: {}", e),
            Error::BackupTargetExists(e) => write!(f, "Target for backup already exists: {}", e),
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl Error {
    pub fn cannot_read(path: &Path) -> Error {
        let str = path.to_string_lossy().to_string();
        Error::CannotRead(str)
    }

    fn backup_cannot_read(path: &Path) -> Error {
        let str = path.to_string_lossy().to_string();
        Error::BackupCannotReadSource(str)
    }

    fn backup_target_exists(path: &Path) -> Error {
        let str = path.to_string_lossy().to_string();
        Error::BackupTargetExists(str)
    }
}

impl std::error::Error for Error {}

impl From<KrillIoError> for Error {
    fn from(e: KrillIoError) -> Self {
        Error::Io(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::test;

    use super::*;

    #[test]
    fn should_scan_disk() {
        test::test_under_tmp(|base_dir| {
            let file_1 = CurrentFile::new(
                test::rsync("rsync://host:10873/module/alice/file1.txt"),
                &Bytes::from("content 1"),
            );
            let file_2 = CurrentFile::new(
                test::rsync("rsync://host:10873/module/alice/file2.txt"),
                &Bytes::from("content 2"),
            );
            let file_3 = CurrentFile::new(
                test::rsync("rsync://host:10873/module/alice/sub/file1.txt"),
                &Bytes::from("content sub file"),
            );
            let file_4 = CurrentFile::new(
                test::rsync("rsync://host:10873/module/bob/file.txt"),
                &Bytes::from("content"),
            );

            file_1.save(&base_dir).unwrap();
            file_2.save(&base_dir).unwrap();
            file_3.save(&base_dir).unwrap();
            file_4.save(&base_dir).unwrap();

            let files = crawl_derive_rsync_uri(&base_dir).unwrap();

            assert!(files.contains(&file_1));
            assert!(files.contains(&file_2));
            assert!(files.contains(&file_3));
            assert!(files.contains(&file_4));
        });
    }
}
