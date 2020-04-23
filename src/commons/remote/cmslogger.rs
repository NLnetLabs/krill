use std::path::PathBuf;
use std::{fmt, io};

use bytes::Bytes;
use rpki::x509::Time;

use crate::commons::api::{Handle, PublisherHandle};
use crate::commons::util::file;

/// This type helps to log CMS (RFC8181 and RFC6492) protocol messages
/// for auditing purposes.
pub struct CmsLogger {
    path: Option<PathBuf>,
    now: i64,
}

impl CmsLogger {
    fn new(path: Option<PathBuf>) -> Self {
        CmsLogger {
            path,
            now: Time::now().timestamp_millis(),
        }
    }

    pub fn for_rfc6492_rcvd(log_dir: Option<&PathBuf>, ca: &Handle, sender: &Handle) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(ca.as_str());
            path.push("rcvd");
            path.push(sender.as_str());
            path
        });

        Self::new(path)
    }

    pub fn for_rfc6492_sent(log_dir: Option<&PathBuf>, ca: &Handle, recipient: &Handle) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(ca.as_str());
            path.push("sent");
            path.push(recipient.as_str());
            path
        });

        Self::new(path)
    }

    pub fn for_rfc8181_sent(log_dir: Option<&PathBuf>, ca: &Handle) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(ca.as_str());
            path.push("sent");
            path
        });

        Self::new(path)
    }

    pub fn for_rfc8181_rcvd(log_dir: Option<&PathBuf>, publisher: &PublisherHandle) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(publisher.as_str());
            path.push("rcvd");
            path
        });

        Self::new(path)
    }

    pub fn received(&self, msg: &Bytes) -> Result<(), io::Error> {
        self.save(msg, "rcvd")
    }

    pub fn reply(&self, msg: &Bytes) -> Result<(), io::Error> {
        self.save(msg, "repl")
    }

    pub fn sent(&self, msg: &Bytes) -> Result<(), io::Error> {
        self.save(msg, "sent")
    }

    pub fn err(&self, msg: impl fmt::Display) -> Result<(), io::Error> {
        self.save(msg.to_string().as_bytes(), "err")
    }

    fn save(&self, content: &[u8], ext: &str) -> Result<(), io::Error> {
        if let Some(path) = self.path.as_ref() {
            let mut path = path.clone();
            path.push(&format!("{}.{}", self.now, ext));

            file::save(content, &path)
        } else {
            Ok(())
        }
    }
}
