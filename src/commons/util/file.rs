use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;

use rpki::uri;

use crate::commons::api::{Base64, HexEncodedHash, ListElement, Publish, Update, Withdraw};

/// Creates a sub dir if needed, return full path to it
pub fn sub_dir(base: &PathBuf, name: &str) -> Result<PathBuf, io::Error> {
    let mut full_path = base.clone();
    full_path.push(name);
    create_dir(&full_path)?;
    Ok(full_path)
}

pub fn create_dir(dir: &PathBuf) -> Result<(), io::Error> {
    if !dir.is_dir() {
        fs::create_dir(dir)?;
    }
    Ok(())
}

pub fn create_file_with_path(path: &PathBuf) -> Result<File, io::Error> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            trace!("Creating path: {}", parent.to_string_lossy());
            fs::create_dir_all(parent)?;
        }
    }
    File::create(path)
}

/// Derive the path for this file.
pub fn file_path(base_path: &PathBuf, file_name: &str) -> PathBuf {
    let mut path = base_path.clone();
    path.push(file_name);
    path
}

/// Saves a file, creating parent dirs as needed
pub fn save(content: &[u8], full_path: &PathBuf) -> Result<(), io::Error> {
    let mut f = create_file_with_path(full_path)?;
    f.write_all(content)?;

    trace!("Saved file: {}", full_path.to_string_lossy());
    Ok(())
}

/// Saves an object to json - unwraps any json errors!
pub fn save_json<O: Serialize>(object: &O, full_path: &PathBuf) -> Result<(), io::Error> {
    let json = serde_json::to_string(object).unwrap();
    save(&Bytes::from(json), full_path)
}

/// Loads a files and deserialzes as json for the expected type. Maps json
/// errors to io::Error
pub fn load_json<O: DeserializeOwned>(full_path: &PathBuf) -> Result<O, io::Error> {
    let bytes = read(full_path)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "could not deserialize json"))
}

/// Saves a file, creating parent dirs as needed
pub fn save_in_dir(content: &Bytes, base_path: &PathBuf, name: &str) -> Result<(), io::Error> {
    let mut full_path = base_path.clone();
    full_path.push(name);
    save(content, &full_path)
}

/// Saves a file under a base directory, using the rsync uri to create
/// sub-directories preserving the rsync authority and module in dir names.
pub fn save_with_rsync_uri(
    content: &Bytes,
    base_path: &PathBuf,
    uri: &uri::Rsync,
) -> Result<(), io::Error> {
    let path = path_with_rsync(base_path, uri);
    save(content, &path)
}

/// Reads a file to Bytes
pub fn read(path: &PathBuf) -> Result<Bytes, io::Error> {
    let mut f = File::open(path).map_err(|_| Error::cannot_read(path))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    Ok(Bytes::from(bytes))
}

pub fn read_with_rsync_uri(base_path: &PathBuf, uri: &uri::Rsync) -> Result<Bytes, io::Error> {
    let path = path_with_rsync(base_path, uri);
    read(&path)
}

pub fn delete_with_rsync_uri(base_path: &PathBuf, uri: &uri::Rsync) -> Result<(), io::Error> {
    delete(&path_with_rsync(base_path, uri))
}

pub fn delete_in_dir(base_path: &PathBuf, name: &str) -> Result<(), io::Error> {
    let mut full_path = base_path.clone();
    full_path.push(name);
    delete(&full_path)
}

pub fn delete(full_path: &PathBuf) -> Result<(), io::Error> {
    trace!("Removing file: {}", full_path.to_string_lossy());
    fs::remove_file(full_path)?;
    Ok(())
}

pub fn clean_file_and_path(path: &PathBuf) -> Result<(), io::Error> {
    if path.exists() {
        fs::remove_file(&path)?;

        let mut parent_opt = path.parent();

        while parent_opt.is_some() {
            let parent = parent_opt.unwrap();
            if parent.read_dir()?.count() == 0 {
                trace!("Will delete {}", parent.to_string_lossy().to_string());
                fs::remove_dir(parent)?;
            }

            parent_opt = parent.parent();
        }
    }
    Ok(())
}

fn path_with_rsync(base_path: &PathBuf, uri: &uri::Rsync) -> PathBuf {
    let mut path = base_path.clone();
    path.push(uri.module().authority());
    path.push(uri.module().module());
    path.push(uri.path());
    path
}

/// Recurses a path on disk and returns all files found as ['CurrentFile'],
/// using the provided rsync_base URI as the rsync prefix.
/// Allows a publication client to publish the contents below some base
/// dir, in their own designated rsync URI name space.
pub fn crawl_incl_rsync_base(
    base_path: &PathBuf,
    rsync_base: &uri::Rsync,
) -> Result<Vec<CurrentFile>, Error> {
    crawl_disk(base_path, base_path, Some(rsync_base))
}

/// Recurses a path on disk and returns all files found as ['CurrentFile'],
/// deriving the rsync_base URI from the directory structure. This is
/// useful when reading ['CurrentFile'] instances that were saved in some
/// base directory as is done by the ['FileStore'].
pub fn crawl_derive_rsync_uri(base_path: &PathBuf) -> Result<Vec<CurrentFile>, Error> {
    crawl_disk(base_path, base_path, None)
}

fn crawl_disk(
    base_path: &PathBuf,
    path: &PathBuf,
    rsync_base: Option<&uri::Rsync>,
) -> Result<Vec<CurrentFile>, Error> {
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

fn derive_uri(
    base_path: &PathBuf,
    path: &PathBuf,
    rsync_base: Option<&uri::Rsync>,
) -> Result<uri::Rsync, Error> {
    let rel = path
        .strip_prefix(base_path)
        .map_err(|_| Error::PathOutsideBasePath)?;

    let rel_string = rel.to_string_lossy().to_string();

    let uri_string = match rsync_base {
        Some(rsync_base) => format!("{}{}", rsync_base.to_string(), rel_string),
        None => format!("rsync://{}", rel_string),
    };

    let uri =
        uri::Rsync::from_str(&uri_string).map_err(|_| Error::UnsupportedFileName(uri_string))?;
    Ok(uri)
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
        let content = Base64::from_content(&content);
        let hash = content.to_encoded_hash();
        CurrentFile { uri, content, hash }
    }

    /// Saves this file under a base directory, based on the (rsync) uri of
    /// this file.
    pub fn save(&self, base_path: &PathBuf) -> Result<(), io::Error> {
        save_with_rsync_uri(&self.content.to_bytes(), &base_path, &self.uri)
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
#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "Cannot read: {}", _0)]
    CannotRead(String),

    #[display(fmt = "Unsupported characters: {}", _0)]
    UnsupportedFileName(String),

    #[display(fmt = "Cannot use path outside of rsync jail")]
    PathOutsideBasePath,
}

impl Error {
    pub fn cannot_read(path: &PathBuf) -> Error {
        let str = path.to_string_lossy().to_string();
        Error::CannotRead(str)
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
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
