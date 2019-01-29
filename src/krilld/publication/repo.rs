use std::path::PathBuf;
use rpki::uri;
use crate::api::publication;
use crate::krilld::publication::rsyncd;
use crate::krilld::publication::rrdpd;


//------------ Repository ----------------------------------------------------

/// This type orchestrates publishing in both an RSYNC and RRDP
/// (RFC8182) format.
#[derive(Clone, Debug)]
pub struct Repository {
    // file_store
    fs: rsyncd::FileStore,

    // RRDP
    rrdp: rrdpd::RrdpServer
}

/// # Construct
///
impl Repository {
    pub fn new(
        rrdp_base_uri: &uri::Http,
        work_dir: &PathBuf
    ) -> Result<Self, Error>
    {
        let fs = rsyncd::FileStore::new(work_dir)?;
        let rrdp = rrdpd::RrdpServer::new(rrdp_base_uri, work_dir)?;
        Ok( Repository { fs, rrdp } )
    }
}

/// # Access
///
impl Repository {
    /// Returns the RRDP notification URI for inclusion in the
    /// Repository Response
    pub fn rrdp_notification_uri(&self) -> uri::Http {
        self.rrdp.notification_uri().clone()
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
        delta: &publication::PublishDelta,
        base_uri: &uri::Rsync
    ) -> Result<(), Error> {
        debug!("Processing update with {} elements", delta.len());
        self.fs.publish(delta, base_uri)?;
        self.rrdp.publish(delta)?;
        Ok(())
    }

    /// Lists the objects for a base_uri, presumably all for the same
    /// publisher.
    pub fn list(
        &self,
        base_uri: &uri::Rsync
    ) -> Result<publication::ListReply, Error> {
        debug!("Processing list query");
        let files = self.fs.list(base_uri)?;
        Ok(publication::ListReply::from_files(files))
    }
}




//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt="{}", _0)]
    Rrdpd(rrdpd::Error),

    #[display(fmt="{}", _0)]
    Rsyncd(rsyncd::Error),
}

impl From<rrdpd::Error> for Error {
    fn from(e: rrdpd::Error) -> Self { Error::Rrdpd(e) }
}

impl From<rsyncd::Error> for Error {
    fn from(e: rsyncd::Error) -> Self { Error::Rsyncd(e) }
}



//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use bytes::Bytes;
    use crate::util::file::CurrentFile;
    use crate::util::test;
    use crate::api::publication::PublishDeltaBuilder;
    use crate::api::rrdp_data;

    #[test]
    fn should_publish() {
        test::test_with_tmp_dir(|d| {
            let rrdp_base_uri = test::http_uri("http://localhost:3000/repo/");
            let mut repo = Repository::new(&rrdp_base_uri, &d).unwrap() ;

            // Publish a file
            let rsync_for_alice =
                test::rsync_uri("rsync://host:10873/module/alice");
            let file = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/file.txt"),
                Bytes::from("example content")
            );

            let mut builder = PublishDeltaBuilder::new();
            builder.add_publish(file.as_publish());
            let delta = builder.finish();

            repo.publish(&delta, &rsync_for_alice).unwrap();

            // Now publish an update a bunch of times
            // (overwrite file with same file, strictly speaking allowed,
            // and convenient here)

            let file_update = file.clone();

            let mut builder = PublishDeltaBuilder::new();
            builder.add_update(file_update.as_update(file.hash()));
            let delta = builder.finish();

            repo.publish(&delta, &rsync_for_alice).unwrap();
            repo.publish(&delta, &rsync_for_alice).unwrap();
            repo.publish(&delta, &rsync_for_alice).unwrap();
            repo.publish(&delta, &rsync_for_alice).unwrap();
            repo.publish(&delta, &rsync_for_alice).unwrap();

            // Now we expect a notification file with serial 6, which only
            // includes deltas for 5 and 6, because more deltas would
            // exceed the size of the snapshot.

            let mut rrdp_disk_path = d.clone();
            rrdp_disk_path.push("rrdp");

            let mut notification_disk_path = rrdp_disk_path.clone();
            notification_disk_path.push("notification.xml");

            match rrdp_data::Notification::build(
                &notification_disk_path,
                &rrdp_base_uri,
                &rrdp_disk_path
            ) {
                Some(notification) => {
                    let expected_serial: usize = 6;
                    let expected_prev: usize = 5;
                    assert_eq!(notification.serial(), &expected_serial);

                    let deltas = notification.deltas();
                    assert_eq!(2, deltas.len());

                    assert!(
                        deltas.iter().find(|d| {
                            d.serial() == &expected_serial}
                        ).is_some()
                    );

                    assert!(
                        deltas.iter().find(|d| {
                            d.serial() == &expected_prev}
                        ).is_some()
                    );
                },
                None => panic!("Should have derived notification"),
            }
        });
    }

    #[test]
    fn should_store_list_withdraw_files() {
        test::test_with_tmp_dir(|d| {
            let mut file_store = rsyncd::FileStore::new(&d).unwrap();

            // Using a port here to make sure that it works in mapping
            // the rsync URI to and from disk.
            let base_uri = test::rsync_uri
                ("rsync://host:10873/module/alice/");

            // Publish a file
            let file = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/alice/file.txt"),
                Bytes::from("example content")
            );

            let mut builder = PublishDeltaBuilder::new();
            builder.add_publish(file.as_publish());
            let delta = builder.finish();

            file_store.publish(&delta, &base_uri).unwrap();

            // See that it's the only one listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(1, files.len());
            assert!(files.contains(&file));

            // Update a file
            let file_update = CurrentFile::new(
                file.uri().clone(),
                Bytes::from("example updated content")
            );

            let mut builder = PublishDeltaBuilder::new();
            builder.add_update(file_update.as_update(file.hash()));
            let delta = builder.finish();
            file_store.publish(&delta, &base_uri).unwrap();

            // See that it's the only one listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(1, files.len());
            assert!(files.contains(&file_update));

            // Withdraw a file
            let mut builder = PublishDeltaBuilder::new();
            builder.add_withdraw(file_update.as_withdraw());
            let delta = builder.finish();
            file_store.publish(&delta, &base_uri).unwrap();

            // See that there are no files listed
            let files = file_store.list(&base_uri).unwrap();
            assert_eq!(0, files.len());
        });
    }

    #[test]
    fn should_not_allow_publishing_or_withdrawing_outside_of_base() {
        test::test_with_tmp_dir(|d| {
            let mut file_store = rsyncd::FileStore::new(&d).unwrap();

            // Using a port here to make sure that it works in mapping
            // the rsync URI to and from disk.
            let base_uri = test::rsync_uri
                ("rsync://host:10873/module/alice/");

            // Publish a file
            let file = CurrentFile::new(
                test::rsync_uri("rsync://host:10873/module/bob/file.txt"),
                Bytes::from("example content")
            );

            let mut builder = PublishDeltaBuilder::new();
            builder.add_publish(file.as_publish());
            let delta = builder.finish();

            match file_store.publish(&delta, &base_uri) {
                Err(rsyncd::Error::OutsideBaseUri) => {},
                _ => { panic!("Expected Error::OutsideBaseUri") }
            }
        });
    }
}


