//! Logging of CMS protocol messages for auditing purposes.

use std::fmt
use std::path::PathBuf;
use bytes::Bytes;
use rpki::ca::idexchange::{
    CaHandle, PublisherHandle, RecipientHandle, SenderHandle,
};
use rpki::repository::x509::Time;
use crate::commons::error::KrillIoError;
use crate::commons::util::file;


//------------ CmsLogger -----------------------------------------------------

/// Logs CMS (RFC8181 and RFC6492) protocol messages for auditing purposes.
pub struct CmsLogger {
    /// The path to log to,
    ///
    /// If this is `None`, we don’t actually log.
    path: Option<PathBuf>,

    /// The current Unix timestamp.
    now: i64,
}

impl CmsLogger {
    /// Creates a new logger with the given base path.
    ///
    /// If the path is `None`, nothing will be logged.
    fn new(path: Option<PathBuf>) -> Self {
        CmsLogger {
            path,
            now: Time::now().timestamp_millis(),
        }
    }

    /// Creates a new logger for a received RFC 6492 message.
    pub fn for_rfc6492_rcvd(
        log_dir: Option<&PathBuf>,
        recipient: &RecipientHandle,
        sender: &SenderHandle,
    ) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(recipient.as_str());
            path.push("rcvd");
            path.push(sender.as_str());
            path
        });

        Self::new(path)
    }

    /// Creates a new logger for a sent RFC 6492 message.
    pub fn for_rfc6492_sent(
        log_dir: Option<&PathBuf>,
        sender: &SenderHandle,
        recipient: &RecipientHandle,
    ) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(sender.as_str());
            path.push("sent");
            path.push(recipient.as_str());
            path
        });

        Self::new(path)
    }

    /// Creates a new logger for a received RFC 8181 message.
    pub fn for_rfc8181_rcvd(
        log_dir: Option<&PathBuf>,
        publisher: &PublisherHandle,
    ) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(publisher.as_str());
            path.push("rcvd");
            path
        });

        Self::new(path)
    }

    /// Creates a new logger for a sent RFC 8181 message.
    pub fn for_rfc8181_sent(
        log_dir: Option<&PathBuf>,
        ca: &CaHandle,
    ) -> Self {
        let path = log_dir.map(|dir| {
            let mut path = dir.clone();
            path.push(ca.as_str());
            path.push("sent");
            path
        });

        Self::new(path)
    }

    /// Saves the received message.
    pub fn received(&self, msg: &Bytes) -> Result<(), KrillIoError> {
        self.save(msg, "rcvd")
    }

    /// Saves the reply message.
    pub fn reply(&self, msg: &Bytes) -> Result<(), KrillIoError> {
        self.save(msg, "repl")
    }

    /// Saves the sent message.
    pub fn sent(&self, msg: &Bytes) -> Result<(), KrillIoError> {
        self.save(msg, "sent")
    }

    /// Saves the error message.
    pub fn err(&self, msg: impl fmt::Display) -> Result<(), KrillIoError> {
        self.save(msg.to_string().as_bytes(), "err")
    }

    /// Saves the message.
    fn save(&self, content: &[u8], ext: &str) -> Result<(), KrillIoError> {
        if let Some(path) = self.path.as_ref() {
            let mut path = path.clone();
            path.push(format!("{}.{}", self.now, ext));

            file::save(content, &path)
        }
        else {
            Ok(())
        }
    }
}

