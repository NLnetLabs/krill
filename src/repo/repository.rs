use std::path::PathBuf;
use repo::file_store::{self, FileStore};
use repo::rrdp::RrdpServer;
use rpki::publication::pubmsg::Message;
use rpki::publication::query::PublishQuery;
use rpki::publication::reply::ListElement;
use rpki::publication::reply::ListReply;
use rpki::publication::reply::SuccessReply;
use rpki::uri;
use repo::rrdp;


//------------ Repository ----------------------------------------------------

/// This type orchestrates publishing in both an RSYNC and RRDP (todo)
/// friendly format.
#[derive(Clone, Debug)]
pub struct Repository {
    // file_store
    fs: FileStore,

    // RRDP
    rrdp: RrdpServer
}

/// # Construct
///
impl Repository {
    pub fn new(
        rrdp_base_uri: &uri::Http,
        work_dir: &PathBuf
    ) -> Result<Self, Error>
    {
        let fs = FileStore::new(work_dir)?;
        let rrdp = RrdpServer::new(rrdp_base_uri, work_dir)?;
        Ok( Repository { fs, rrdp } )
    }
}

/// # Publish / List
///
impl Repository {
    /// Publishes an publish query and returns a success reply embedded in
    /// a message. Throws an error in case of issues. The PubServer needs
    /// to wrap such errors in a response message to the publisher.
    pub fn publish(
        &mut self,
        update: &PublishQuery,
        base_uri: &uri::Rsync
    ) -> Result<Message, Error> {
        self.fs.publish(update, base_uri)?;
        self.rrdp.publish(update)?;
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

    #[fail(display="{}", _0)]
    RrdpError(rrdp::Error),
}

impl From<file_store::Error> for Error {
    fn from(e: file_store::Error) -> Self {
        Error::FileStoreError(e)
    }
}

impl From<rrdp::Error> for Error {
    fn from(e: rrdp::Error) -> Self {
        Error::RrdpError(e)
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::Bytes;
    use file::CurrentFile;
    use test;

    #[test]
    fn should_publish() {
        test::test_with_tmp_dir(|d| {
            let rrdp_base = test::http_uri("http://localhost:3000/repo/");
            let mut repo = Repository::new(&rrdp_base, &d).unwrap() ;

            // Publish a file
            let rsync_for_alice =
                test::rsync_uri("rsync://host:10873/module/alice");
            let file = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/file.txt"),
                Bytes::from("example content")
            );

            let mut builder = PublishQuery::build();
            builder.add(file.clone().as_publish());
            let message = builder.build_message();
            let publish = message.as_query().unwrap().as_publish().unwrap();

            repo.publish(&publish, &rsync_for_alice).unwrap();
        });
    }
}


