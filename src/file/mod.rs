use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use ext_serde;
use bytes::Bytes;
use rpki::uri;
use rpki::publication;
use rpki::publication::query::{ Publish, PublishElement, Update, Withdraw };
use rpki::publication::reply::ListElement;


///-- Some helper functions

/// Saves a file, creating parent dirs as needed
pub fn save(content: &Bytes, full_path: &PathBuf) -> Result<(), io::Error> {
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut f = File::create(full_path)?;
    f.write(content)?;
    Ok(())
}

/// Saves a file, creating parent dirs as needed
pub fn save_in_dir(
    content: &Bytes,
    base_path: &PathBuf,
    name: &str) -> Result<(), io::Error> {
    let mut full_path = base_path.clone();
    full_path.push(name);
    save(content, &full_path)
}

/// Saves a file under a base directory, using the rsync uri to create
/// sub-directories preserving the rsync authority and module in dir names.
pub fn save_with_rsync_uri(
    content: &Bytes,
    base_path: &PathBuf,
    uri: &uri::Rsync
) -> Result<(), io::Error> {
    let path = path_with_rsync(base_path, uri);
    save(content, &path)
}

/// Reads a file to Bytes
pub fn read(path: &PathBuf) -> Result<Bytes, io::Error> {
    let mut f = File::open(path)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    Ok(Bytes::from(bytes))
}

pub fn read_with_rsync_uri(
    base_path: &PathBuf,
    uri: &uri::Rsync
) -> Result<Bytes, io::Error> {
    let path = path_with_rsync(base_path, uri);
    read(&path)
}

pub fn delete_with_rsync_uri(
    base_path: &PathBuf,
    uri: &uri::Rsync
) -> Result<(), io::Error> {
    delete(&path_with_rsync(base_path, uri))
}

pub fn delete_in_dir(
    base_path: &PathBuf,
    name: &str
) -> Result<(), io::Error> {
    let mut full_path = base_path.clone();
    full_path.push(name);
    delete(&full_path)
}

fn delete(full_path: &PathBuf) -> Result<(), io::Error> {
    fs::remove_file(full_path)?;
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
    rsync_base: &uri::Rsync
) -> Result<Vec<CurrentFile>, RecursorError> {
    crawl_disk(base_path, base_path, Some(rsync_base))
}

/// Recurses a path on disk and returns all files found as ['CurrentFile'],
/// deriving the rsync_base URI from the directory structure. This is
/// useful when reading ['CurrentFile'] instances that were saved in some
/// base directory as is done by the ['FileStore'].
pub fn crawl_derive_rsync_uri(
    base_path: &PathBuf
) -> Result<Vec<CurrentFile>, RecursorError> {
    crawl_disk(base_path, base_path, None)
}

fn crawl_disk(
    base_path: &PathBuf,
    path: &PathBuf,
    rsync_base: Option<&uri::Rsync>
) -> Result<Vec<CurrentFile>, RecursorError> {
    let mut res = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let mut other = crawl_disk(base_path, &path, rsync_base)?;
            res.append(&mut other);
        } else {
            let uri = derive_uri(base_path, &path, rsync_base)?;
            let content = read(&path)?;
            let current_file = CurrentFile::new(uri, content);

            res.push(current_file);
        }
    }

    Ok(res)
}

fn derive_uri(
    base_path: &PathBuf,
    path: &PathBuf,
    rsync_base: Option<&uri::Rsync>
) -> Result<uri::Rsync, RecursorError> {
    let rel = path
        .strip_prefix(base_path)
        .map_err(|_| RecursorError::PathOutsideBasePath)?;

    let rel_string = rel.to_string_lossy().to_string();

    let uri_string = match rsync_base {
        Some(rsync_base) =>
            format!("{}{}", rsync_base.to_string(), rel_string),
        None =>
            format!("rsync://{}", rel_string)
    };

    let uri = uri::Rsync::from_string(uri_string)?;
    Ok(uri)
}

//------------ CurrentFile ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentFile {
    #[serde(
    deserialize_with = "ext_serde::de_rsync_uri",
    serialize_with = "ext_serde::ser_rsync_uri")]
    uri:     uri::Rsync,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    /// The actual file content. Note that we may want to store this
    /// only on disk in future (look up by sha256 hash), to save memory.
    content: Bytes,

    #[serde(
    deserialize_with = "ext_serde::de_bytes",
    serialize_with = "ext_serde::ser_bytes")]
    /// The sha-256 hash of the file (as is used on the RPKI manifests and
    /// in the publication protocol for list, update and withdraw). Saving
    /// this rather than calculating on demand seems a small price for some
    /// performance gain.
    hash:    Bytes
}


impl CurrentFile {
    pub fn new(uri: uri::Rsync, content: Bytes) -> Self {
        let hash = publication::hash(&content);
        CurrentFile {uri, content, hash}
    }

    /// Saves this file under a base directory, based on the (rsync) uri of
    /// this file.
    pub fn save(&self, base_path: &PathBuf) -> Result<(), io::Error> {
        save_with_rsync_uri(&self.content, &base_path, &self.uri)
    }

    pub fn uri(&self) -> &uri::Rsync {
        &self.uri
    }

    pub fn content(&self) -> &Bytes {
        &self.content
    }

    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub fn as_publish(&self) -> PublishElement {
        Publish::publish(&self.content, self.uri.clone())
    }

    pub fn as_update(&self, old_content: &Bytes) -> PublishElement {
        Update::publish(old_content, &self.content, self.uri.clone())
    }

    /// Makes a withdraw element for a known file
    ///
    /// Note this is probably only useful for testing, because real files
    /// to be withdrawn will not be current. Look at Withdraw::publish
    /// instead which takes a reference to a ListElement from a ListReply.
    pub fn as_withdraw(&self) -> PublishElement {
        Withdraw::for_known_file(&self.content, self.uri.clone())
    }

    pub fn to_list_element(&self) -> ListElement {
        ListElement::reply(&self.content, self.uri.clone())
    }
}

impl PartialEq for CurrentFile {
    fn eq(&self, other: &CurrentFile) -> bool {
        self.uri == other.uri &&
            self.hash == other.hash &&
            self.content == other.content
    }
}

impl Eq for CurrentFile {}





//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum RecursorError {
    #[fail(display = "{}", _0)]
    IoError(io::Error),
    
    #[fail(display="{}", _0)]
    UriError(uri::Error),

    #[fail(display = "Trying to resolve a path outside of the base path")]
    PathOutsideBasePath,
}

impl From<io::Error> for RecursorError {
    fn from(e: io::Error) -> Self {
        RecursorError::IoError(e)
    }
}

impl From<uri::Error> for RecursorError {
    fn from(e: uri::Error) -> Self {
        RecursorError::UriError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test;

    #[test]
    fn should_scan_disk() {
        test::test_with_tmp_dir(|base_dir| {

            let file_1 = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/file1.txt"),
                Bytes::from("content 1")
            );
            let file_2 = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/file2.txt"),
                Bytes::from("content 2")
            );
            let file_3 = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/sub/file1\
                .txt"),
                Bytes::from("content sub file")
            );
            let file_4 = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/bob/file.txt"),
                Bytes::from("content")
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
