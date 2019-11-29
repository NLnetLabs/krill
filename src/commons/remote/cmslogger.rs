use std::path::PathBuf;
use std::{fmt, io};

use bytes::Bytes;
use rpki::x509::Time;

use crate::commons::api::{Handle, PublisherHandle};
use crate::commons::util::file;
use crate::constants::{RFC6492_LOG_DIR, RFC8181_RCVD_LOG_DIR, RFC8181_SENT_LOG_DIR};

/// This type helps to log CMS (RFC8181 and RFC6492) protocol messages
/// for auditing purposes.
pub struct CmsLogger {
    path: PathBuf,
    now: i64,
}

impl CmsLogger {
    fn new(path: PathBuf) -> Self {
        CmsLogger {
            path,
            now: Time::now().timestamp_millis(),
        }
    }

    pub fn for_rfc6492_rcvd(work_dir: &PathBuf, ca: &Handle, sender: &Handle) -> Self {
        let mut path = work_dir.clone();
        path.push(RFC6492_LOG_DIR);
        path.push(ca.as_str());
        path.push("rcvd");
        path.push(sender.as_str());

        Self::new(path)
    }

    pub fn for_rfc6492_sent(work_dir: &PathBuf, ca: &Handle, recipient: &Handle) -> Self {
        let mut path = work_dir.clone();
        path.push(RFC6492_LOG_DIR);
        path.push(ca.as_str());
        path.push("sent");
        path.push(recipient.as_str());

        Self::new(path)
    }

    pub fn for_rfc8181_sent(work_dir: &PathBuf, ca: &Handle) -> Self {
        let mut path = work_dir.clone();
        path.push(RFC8181_SENT_LOG_DIR);
        path.push(ca.as_str());

        Self::new(path)
    }

    pub fn for_rfc8181_rcvd(work_dir: &PathBuf, publisher: &PublisherHandle) -> Self {
        let mut path = work_dir.clone();
        path.push(RFC8181_RCVD_LOG_DIR);
        path.push(publisher.as_str());

        Self::new(path)
    }

    pub fn received(&self, msg: &Bytes) -> Result<(), io::Error> {
        let path = self.file_path("rcvd");
        file::save(msg, &path)
    }

    pub fn reply(&self, msg: &Bytes) -> Result<(), io::Error> {
        let path = self.file_path("repl");
        file::save(msg, &path)
    }

    pub fn sent(&self, msg: &Bytes) -> Result<(), io::Error> {
        let path = self.file_path("sent");
        file::save(msg, &path)
    }

    pub fn err(&self, msg: impl fmt::Display) -> Result<(), io::Error> {
        let path = self.file_path("err");
        file::save(&Bytes::from(msg.to_string()), &path)
    }

    fn file_path(&self, ext: &str) -> PathBuf {
        let mut path = self.path.clone();
        path.push(&format!("{}.{}", self.now, ext));
        path
    }
}
