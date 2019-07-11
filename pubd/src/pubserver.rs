use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use rpki::uri;
use krill_commons::api::publication;
use krill_commons::api::admin::{
    Handle,
    PublisherRequest
};
use krill_commons::api::ca::RepoInfo;
use krill_commons::api::rrdp::DeltaElements;
use krill_commons::eventsourcing::{
    Aggregate,
    AggregateStore,
    AggregateStoreError,
    Command,
    DiskAggregateStore,
};
use crate::publishers::{
    Publisher,
    PublisherCommand,
    PublisherCommandDetails,
    PublisherError,
    PublisherEventDetails,
    InitPublisherDetails
};
use crate::repo::{
    self,
    RetentionTime,
    RrdpCommandDetails,
    RrdpInitDetails,
    RrdpServer,
    RrdpServerError,
    RsyncdStore,
};


//------------ PubServer -----------------------------------------------------

/// This server manages all publishers. I.e. finds them, adds them, dispatches
/// commands to them, stores them.. also publishes the combined snapshots and
/// deltas, and manages the files on disk for rsync.
pub struct PubServer {
    rrdp_store: Arc<DiskAggregateStore<RrdpServer>>,
    rsyncd_store: RsyncdStore,
    store: Arc<DiskAggregateStore<Publisher>>,
    base_rsync_uri: uri::Rsync // jail for the publishers
}

impl PubServer {
    pub fn build(
        base_rsync_uri: uri::Rsync,
        base_http_uri: uri::Https, // for the RRDP files
        repo_dir: PathBuf, // for the RRDP and rsync files
        work_dir: &PathBuf // for the aggregate stores
    ) -> Result<Self, Error> {
        let rrdp_store = Arc::new(DiskAggregateStore::<RrdpServer>::new(work_dir, "repo-server")?);

        let rsyncd_store = RsyncdStore::build(&repo_dir)?;

        if ! rrdp_store.has(&repo::id()) {
            let init = RrdpInitDetails::init_new(base_http_uri, repo_dir);
            rrdp_store.add(init)?;
        }

        let store = Arc::new(DiskAggregateStore::<Publisher>::new(work_dir, "publishers")?);

        let pubserver = PubServer {
            rrdp_store,
            rsyncd_store,
            store,
            base_rsync_uri
        };

        Ok(pubserver)
    }

    pub fn repo_info_for(&self, handle: &Handle) -> Result<RepoInfo, Error> {
        let rsync_jail = format!("{}{}/", self.base_rsync_uri.to_string(), handle);
        let base_uri = uri::Rsync::from_string(rsync_jail).unwrap();
        let rpki_notify = self.rrdp_server()?.notification_uri();
        Ok(RepoInfo::new(base_uri, rpki_notify))
    }

    pub fn ta_aia(&self) -> uri::Rsync {
        let uri = format!("{}ta.cer", self.base_rsync_uri.to_string());
        uri::Rsync::from_string(uri).unwrap()
    }
}


/// # Publication Protocol support
///
impl PubServer {

    fn rrdp_server(&self) -> Result<Arc<RrdpServer>, Error> {
        self.rrdp_store.get_latest(&repo::id()).map_err(Error::AggregateStoreError)
    }

    pub fn publish(
        &self,
        handle: &Handle,
        delta: publication::PublishDelta
    ) -> Result<(), Error> {

        // Publish the delta for the publisher
        let cmd = PublisherCommandDetails::publish(handle, delta);
        if let Some(delta) = self.command_publisher(cmd)? {
            // Apparently the delta was valid, and for a known publisher

            let repo_id = repo::id();

            // Update rsync repo on disk
            let delta = delta.clone();
            self.rsyncd_store.publish(&delta)?;

            // Add the delta to the RRDP server
            let rrdp = self.rrdp_server()?;
            let add_cmd = RrdpCommandDetails::add_delta(delta);
            let rrdp_add_delta_events = rrdp.process_command(add_cmd)?;
            let rrdp = self.rrdp_store.update(&repo_id, rrdp, rrdp_add_delta_events)?;

            // Trigger publication of the RRDP files
            let publish_cmd = RrdpCommandDetails::publish();
            let rrdp_publish_events = rrdp.process_command(publish_cmd)?;
            let rrdp = self.rrdp_store.update(&repo_id, rrdp, rrdp_publish_events)?;

            // Clean up old files
            let retention = RetentionTime::from_secs(0);
            let clean_cmd = RrdpCommandDetails::clean_up(retention);
            let rrdp_clean_events = rrdp.process_command(clean_cmd)?;
            self.rrdp_store.update(&repo_id, rrdp, rrdp_clean_events)?;
        }

        Ok(())
    }

    pub fn list(
        &self,
        handle: &Handle
    ) -> Result<publication::ListReply, Error> {
        match self.get_publisher(handle)? {
            Some(publisher) => Ok(publisher.list_current()),
            None => Err(Error::UnknownPublisher(handle.to_string()))
        }
    }
}


/// # Publishing
///
impl PubServer {

    fn verify_handle(&self, handle: &Handle) -> Result<(), Error> {
        let name = handle.as_str();

        if ! name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Error::InvalidHandle(name.to_string()))
        }

        if self.store.has(handle) {
            return Err(Error::DuplicatePublisher(name.to_string()))
        }

        Ok(())
    }

    fn verify_base_uri(&self, base_uri: &uri::Rsync) -> Result<(), Error> {
        if self.base_rsync_uri.is_parent_of(base_uri) && base_uri.ends_with("/") {
            // Note it's allowed for multiple publishers to share the same
            // base_uri, and for publishers to have a base_uri under another.
            // Maybe we will want to change this in future, but for the moment
            // this freedom is given to the admin. There are use cases here,
            // such as hierarchical rsync, and possibly migrations that appear
            // as standard key rolls to an RP.
            Ok(())
        } else {
            Err(Error::InvalidBaseUri)
        }
    }

    pub fn get_publisher(
        &self,
        handle: &Handle
    ) -> Result<Option<Arc<Publisher>>, Error> {
        if self.store.has(handle) {
            self.store.get_latest(handle)
                .map(Some)
                .map_err(Error::AggregateStoreError)
        } else {
            Ok(None)
        }
    }

    /// Adds a publisher. Will complain if a publisher already exists for this
    /// handle. Will also verify that the base_uri is allowed.
    pub fn create_publisher(
        &self,
        req: PublisherRequest
    ) -> Result<(), Error> {
        self.verify_handle(req.handle())?;
        self.verify_base_uri(req.base_uri())?;

        let init = InitPublisherDetails::for_request(req);

        self.store.add(init)?;

        Ok(())
    }

    /// Returns a list of publisher handles
    pub fn list_publishers(&self) -> Vec<Handle> {
        self.store.list()
    }

    /// Deactivates a publisher. For now this is irreversible, but we may add
    /// re-activation in future. Reason is that we never forget the history
    /// of the old publisher, and if handles are re-used by different
    /// entities that would get confusing.
    pub fn deactivate_publisher(
        &self,
        handle: &Handle
    ) -> Result<(), Error> {
        let cmd = PublisherCommandDetails::deactivate(handle);
        self.command_publisher(cmd)?;
        Ok(())
    }


    /// Apply a command to a publisher. If this was a successful publication
    /// command, then return the delta so that it can be published by the
    /// RRDP server.
    fn command_publisher(
        &self,
        command: PublisherCommand
    ) -> Result<Option<DeltaElements>, Error> {

        let handle = command.handle().clone();

        match self.get_publisher(&handle)? {
            None => Err(Error::UnknownPublisher(handle.to_string())),
            Some(pbl) => {
                let mut res = None;

                if let Some(version) = command.version() {
                    if version != pbl.version() {
                        return Err(
                            Error::ConcurrentModification(version, pbl.version())
                        )
                    }
                }

                let events = pbl.process_command(command)?;

                for event in &events {
                    if let PublisherEventDetails::Published(delta) = event.details() {
                        res = Some(delta.clone())
                    }
                }

                self.store.update(&handle, pbl, events)?;

                Ok(res)
            }
        }
    }

}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "The publisher handle may only contain a-ZA-Z0-9 and _. You sent: {}", _0)]
    InvalidHandle(String),

    #[display(fmt = "Duplicate publisher with name: {} (note: might be de-activated).", _0)]
    DuplicatePublisher(String),

    #[display(fmt = "Unknown publisher with name: {}.", _0)]
    UnknownPublisher(String),

    #[display(fmt = "Trying to update version: {}, publisher at: {}", _0, _1)]
    ConcurrentModification(u64, u64),

    #[display(fmt = "Base uri for publisher needs to be under server, and must end with a '/'.")]
    InvalidBaseUri,

    #[display(fmt = "{}", _0)]
    PublisherError(PublisherError),

    #[display(fmt = "{}", _0)]
    RrdpServerError(RrdpServerError),

    #[display(fmt = "{}", _0)]
    AggregateStoreError(AggregateStoreError),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self { Error::IoError(e) }
}

impl From<PublisherError> for Error {
    fn from(e: PublisherError) -> Self { Error::PublisherError(e) }
}

impl From<RrdpServerError> for Error {
    fn from(e: RrdpServerError) -> Self { Error::RrdpServerError(e) }
}

impl From<AggregateStoreError> for Error {
    fn from(e: AggregateStoreError) -> Self { Error::AggregateStoreError(e) }
}

impl std::error::Error for Error {}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::path::PathBuf;
    use bytes::Bytes;
    use krill_commons::api::admin::Token;
    use krill_commons::api::publication::PublishDeltaBuilder;
    use krill_commons::api::rrdp::VerificationError;
    use krill_commons::util::file::CurrentFile;
    use krill_commons::util::test;

    fn server_base_uri() -> uri::Rsync {
        test::rsync("rsync://localhost/repo/")
    }

    fn server_base_http_uri() -> uri::Https {
        test::https("https://localhost/rrdp/")
    }

    fn make_publisher_req(
        handle: &str,
        uri: &str,
    ) -> PublisherRequest {
        let base_uri = test::rsync(uri);
        let handle = Handle::from(handle);
        let token = Token::from("secret");

        PublisherRequest::new(handle, token, base_uri)
    }

    fn make_server(work_dir: &PathBuf) -> PubServer {
        let mut base_dir = work_dir.clone();
        base_dir.push("repo");

        PubServer::build(
            server_base_uri(),
            server_base_http_uri(),
            base_dir,
            work_dir
        ).unwrap()
    }

    #[test]
    fn should_add_publisher() {
        test::test_under_tmp(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );

            let server = make_server(&d);
            server.create_publisher(publisher_req).unwrap();

            let handle = Handle::from("alice");
            let alice = server.get_publisher(&handle).unwrap().unwrap();

            assert_eq!(alice.handle(), &handle);
        })
    }

    #[test]
    fn should_refuse_invalid_publisher_handle() {
        test::test_under_tmp(|d| {
            let publisher_req = make_publisher_req(
                "alice&",
                "rsync://localhost/repo/alice/",
            );

            let server = make_server(&d);
            match server.create_publisher(publisher_req) {
                Err(Error::InvalidHandle(handle)) => {
                    assert_eq!(handle, "alice&".to_string())
                },
                _ => panic!("Expected error")
            }
        })
    }

    #[test]
    fn should_refuse_base_uri_not_ending_with_slash() {
        test::test_under_tmp(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice",
            );

            let server = make_server(&d);
            match server.create_publisher(publisher_req) {
                Err(Error::InvalidBaseUri) => { },
                _ => panic!("Expected error")
            }
        })
    }

    #[test]
    fn should_refuse_base_uri_outside_of_server_base() {
        test::test_under_tmp(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/outside/alice/",
            );

            let server = make_server(&d);
            match server.create_publisher(publisher_req) {
                Err(Error::InvalidBaseUri) => { },
                _ => panic!("Expected error")
            }
        })
    }

    #[test]
    fn should_not_add_publisher_twice() {
        test::test_under_tmp(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );

            let server = make_server(&d);
            server.create_publisher(publisher_req.clone()).unwrap();
            match server.create_publisher(publisher_req) {
                Err(Error::DuplicatePublisher(name)) => {
                    assert_eq!(name, "alice".to_string())
                },
                _ => panic!("Expected error")
            }
        })
    }

    #[test]
    fn should_remove_publisher() {
        test::test_under_tmp(|d| {
            let server = make_server(&d);
            let handle = Handle::from("alice");

            // create publisher
            let publisher_req = make_publisher_req(
                handle.as_str(),
                "rsync://localhost/repo/alice/",
            );
            server.create_publisher(publisher_req).unwrap();

            // expect to see it in the list
            let list = server.list_publishers();
            assert_eq!(list, vec![handle.clone()]);

            // deactivate
            let deactivate = PublisherCommandDetails::deactivate(&handle);
            server.command_publisher(deactivate).unwrap();

            // expect that it is now inactive
            let alice = server.get_publisher(&handle).unwrap().unwrap();
            assert!(alice.is_deactivated())

        })
    }

    #[test]
    fn should_list_files() {
        test::test_under_tmp(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );
            let handle = Handle::from("alice");

            let server = make_server(&d);
            server.create_publisher(publisher_req).unwrap();

            let alice = server.get_publisher(&handle).unwrap().unwrap();

            let list_reply = alice.list_current();
            assert_eq!(0, list_reply.elements().len());
        });
    }

    #[test]
    fn should_publish_files() {
        test::test_under_tmp(|d| {
            // get the file out of a list_reply
            fn find_in_reply<'a>(
                reply: &'a publication::ListReply,
                uri: &uri::Rsync
            ) -> Option<&'a publication::ListElement> {
                reply.elements().iter().find(|e| e.uri() == uri)
            }

            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );
            let handle = Handle::from("alice");

            let server = make_server(&d);
            server.create_publisher(publisher_req).unwrap();

            // Publish a single file
            let file1 = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file.txt"),
                &Bytes::from("example content")
            );

            let file2 = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file2.txt"),
                &Bytes::from("example content 2")
            );

            let mut builder = PublishDeltaBuilder::new();
            builder.add_publish(file1.as_publish());
            builder.add_publish(file2.as_publish());
            let delta = builder.finish();

            server.publish(&handle, delta).unwrap();

            // Two files should now appear in the list
            let alice = server.get_publisher(&handle).unwrap().unwrap();
            let list_reply = alice.list_current();
            assert_eq!(2, list_reply.elements().len());
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file.txt")
            ).is_some());
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file2.txt")
            ).is_some());

            // Update
            // - update file
            // - withdraw file2
            // - add file 3

            let file1_update = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file.txt"),
                &Bytes::from("example content - updated")
            );

            let file3 = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file3.txt"),
                &Bytes::from("example content 3")
            );

            let mut builder = PublishDeltaBuilder::new();
            builder.add_update(file1_update.as_update(file1.hash()));
            builder.add_withdraw(file2.as_withdraw());
            builder.add_publish(file3.as_publish());
            let delta = builder.finish();

            server.publish(&handle, delta).unwrap();

            // Two files should now appear in the list
            let alice = server.get_publisher(&handle).unwrap().unwrap();
            let list_reply = alice.list_current();

            assert_eq!(2, list_reply.elements().len());
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file.txt")
            ).is_some());
            assert_eq!(
                find_in_reply(
                    &list_reply,
                    &test::rsync("rsync://localhost/repo/alice/file.txt")
                ).unwrap().hash(),
                file1_update.hash()
            );
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file3.txt")
            ).is_some());

            // Should reject publish outside of base uri
            let file_outside = CurrentFile::new(
                test::rsync("rsync://localhost/repo/bob/file.txt"),
                &Bytes::from("irrelevant")
            );
            let mut builder = PublishDeltaBuilder::new();
            builder.add_publish(file_outside.as_publish());
            let delta = builder.finish();

            match server.publish(&handle, delta) {
                Err(
                    Error::PublisherError(
                        PublisherError::VerificationError(
                            VerificationError::UriOutsideJail(_, _)
                        )
                    )
                ) => {}, // ok
                _ => panic!("Expected error publishing outside of base uri jail")
            }

            // Should reject update of file that does not exist
            let file2_update = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file2.txt"),
                &Bytes::from("example content 2 updated")
            ); // file2 was removed
            let mut builder = PublishDeltaBuilder::new();
            builder.add_update(file2_update.as_update(file2.hash()));
            let delta = builder.finish();

            match server.publish(&handle, delta) {
                Err(
                    Error::PublisherError(
                        PublisherError::VerificationError(
                            VerificationError::NoObjectForHashAndOrUri(_)
                        )
                    )
                ) => {},
                // ok
                _ => panic!("Expected error when file for update can't be found")
            }

            // should reject withdraw for file that does not exist
            let mut builder = PublishDeltaBuilder::new();
            builder.add_withdraw(file2.as_withdraw());
            let delta = builder.finish();
            let cmd = PublisherCommandDetails::publish(&handle, delta);

            match server.command_publisher(cmd) {
                Err(
                    Error::PublisherError(
                        PublisherError::VerificationError(
                            VerificationError::NoObjectForHashAndOrUri(_)
                        )
                    )
                ) => {}, // ok
                _ => panic!("Expected error withdrawing file that does not exist")
            }

            // should reject publish for file that does exist
            let mut builder = PublishDeltaBuilder::new();
            builder.add_publish(file3.as_publish());
            let delta = builder.finish();

            match server.publish(&handle, delta) {
                Err(
                    Error::PublisherError(
                        PublisherError::VerificationError
                        (VerificationError::ObjectAlreadyPresent(uri)
                        )
                    )
                ) => { assert_eq!(
                    uri,
                    test::rsync("rsync://localhost/repo/alice/file3.txt")
                )},
                _ => panic!("Expected error publishing file that already exists")
            }
        });
    }
}