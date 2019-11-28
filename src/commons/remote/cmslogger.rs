use std::path::PathBuf;
use std::{fmt, io};

use bytes::Bytes;
use rpki::x509::Time;

use crate::commons::api::Handle;
use crate::commons::util::file;
use crate::constants::RFC6492_LOG_DIR;

/// This type helps to log CMS (RFC8181 and RFC6492) protocol messages
/// for auditing purposes.
pub struct CmsLogger {
    path: PathBuf,
    now: i64,
}

impl CmsLogger {
    pub fn for_rfc6492_rcvd(work_dir: &PathBuf, ca: &Handle, sender: &Handle) -> Self {
        let mut path = work_dir.clone();
        path.push(RFC6492_LOG_DIR);
        path.push(ca.as_str());
        path.push("rcvd");
        path.push(sender.as_str());

        let now = Time::now().timestamp_millis();

        CmsLogger { path, now }
    }

    pub fn received(&self, msg: &Bytes) -> Result<(), io::Error> {
        let path = self.file_path("rcvd");
        file::save(msg, &path)
    }

    pub fn reply(&self, msg: &Bytes) -> Result<(), io::Error> {
        let path = self.file_path("repl");
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
