use std::path::PathBuf;
use repo::file_store::{self, FileStore};
use rpki::publication::pubmsg::Message;
use rpki::publication::query::PublishQuery;
use rpki::publication::reply::ListElement;
use rpki::publication::reply::ListReply;
use rpki::publication::reply::SuccessReply;
use rpki::uri;


//------------ Repository ----------------------------------------------------

/// This type orchestrates publishing in both an RSYNC and RRDP (todo)
/// friendly format.
#[derive(Clone, Debug)]
pub struct Repository {
    // file_store
    fs: FileStore

    // XXX TODO: rrdp..
}

/// # Construct
///
impl Repository {
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
        let fs = FileStore::new(work_dir)?;
        Ok( Repository { fs } )
    }
}

/// # Publish / List
///
impl Repository {
    /// Publishes an publish query and returns a success reply embedded in
    /// a message. Throws an error in case of issues. The PubServer needs
    /// to wrap such errors in a response message to the publisher.
    pub fn publish(
        &self,
        update: &PublishQuery,
        base_uri: &uri::Rsync
    ) -> Result<Message, Error> {
        self.fs.publish(update, base_uri)?;
        Ok(SuccessReply::build_message())
    }

    /// Lists the objects for a base_uri, presumably all for the same
    /// publisher.
    pub fn list(
        &self,
        base_uri: &uri::Rsync
    ) -> Result<Message, Error> {
        let files = self.fs.list(base_uri)?;
        let mut builder = ListReply::build();
        for file in files {
            builder.add(
                ListElement::reply(
                    file.content(),
                    file.uri().clone()
                )
            )
        }
        Ok(builder.build_message())
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{}", _0)]
    FileStoreError(file_store::Error),
}

impl From<file_store::Error> for Error {
    fn from(e: file_store::Error) -> Self {
        Error::FileStoreError(e)
    }
}