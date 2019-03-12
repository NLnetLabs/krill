pub mod publishers;
pub mod repo;

use std::io;
use std::path::PathBuf;
use std::sync::{
    Arc,
    RwLock,
    RwLockReadGuard,
    RwLockWriteGuard
};
use rpki::uri;
use crate::api::publication_data;
use crate::api::publisher_data::{
    PublisherHandle,
    PublisherRequest
};
use crate::api::repo_data::DeltaElements;
use crate::api::publisher_data::PUBLISHER_TYPE_ID;
use crate::krilld::pubd::repo::{
    RetentionTime,
    RrdpCommand,
    RrdpEvent,
    RrdpInit,
    RrdpServer,
    RrdpServerError,
    RsyncdStore,
    rrdp_id
};
use crate::eventsourcing::{
    Aggregate,
    Command,
    Event,
    KeyStore,
    KeyStoreError,
};
use crate::krilld::pubd::publishers::{
    Publisher,
    PublisherCommand,
    PublisherError,
    PublisherEvent,
    PublisherEventDetails,
    PublisherInit,
};
use crate::krilld::pubd::repo::RRDP_TYPE_ID;


//------------ PubServer -----------------------------------------------------

/// This server manages all publishers. I.e. finds them, adds them, dispatches
/// commands to them, stores them.. also publishes the combined snapshots and
/// deltas, and manages the files on disk for rsync.
pub struct PubServer<S: KeyStore> {
    rrdp_server: RwLock<RrdpServer>,
    rsyncd_store: RsyncdStore,
    store: S,
    base_uri: uri::Rsync // jail for the publishers
}

impl<S: KeyStore> PubServer<S> {
    pub fn build(
        base_uri: uri::Rsync,
        base_http_uri: uri::Http, // for the RRDP files
        repo_dir: PathBuf, // for the RRDP and rsync files
        store: S
    ) -> Result<Self, Error> {
        let rsyncd_store = RsyncdStore::build(&repo_dir)?;

        let rrdp_server = Self::get_or_init_rrpd_server(
            &store,
            base_http_uri,
            repo_dir
        )?;

        let pubserver = PubServer {
            rrdp_server,
            rsyncd_store,
            store,
            base_uri
        };

        // Warm up the rrdp server
        let _ = pubserver.rrdp_updated_writer()?;

        Ok(pubserver)
    }

    /// Read an existing RRDP server, if that fails initialise a new one, and
    /// if that also fails blow up miserably!
    fn get_or_init_rrpd_server(
        store: &S,
        base_uri: uri::Http,
        repo_dir: PathBuf
    ) -> Result<RwLock<RrdpServer>, Error> {
        let id = rrdp_id();
        let key = S::key_for_event(0);


        let init = match store.get::<RrdpInit>(&id, &key)
            .map_err(Error::KeyStoreError)? {

            Some(init) => init,
            None => {
                let init = RrdpInit::init_new(base_uri, repo_dir);

                store.store(&id, &key, &init)
                    .map_err(Error::KeyStoreError)?;

                init
            }
        };

        let rrdp = RrdpServer::init(init)?;

        Ok(RwLock::new(rrdp)) // Note server still needs to update.
    }
}

/// # Managing the cache, and reading/writing events.
///
impl<S: KeyStore> PubServer<S> {

    fn load_publisher(
        &self,
        handle: &PublisherHandle
    ) -> Result<Option<Publisher>, Error> {
        if let Some(init) = self.store.get_event::<PublisherInit> (
            handle.as_ref(),
            0
        )? {
            let mut publisher = Publisher::init(init)?;
            while let Some(event) = self.store.get_event::<PublisherEvent>(
                handle.as_ref(),
                publisher.version()
            )? {
                publisher.apply(event);
            }
            Ok(Some(publisher))
        } else {
            Ok(None)
        }
    }

    fn rrdp_reader(&self) -> RwLockReadGuard<RrdpServer> {
        self.rrdp_server.read().unwrap()
    }

    fn rrdp_updated_writer(
        &self
    ) -> Result<RwLockWriteGuard<RrdpServer>, Error> {
        let mut rrdp_writer = self.rrdp_server.write().unwrap();
        while let Some(event) = self.store_get_rrdp_event(rrdp_writer.version())? {
            rrdp_writer.apply(event);
        }
        Ok(rrdp_writer)
    }

    fn store_get_rrdp_event(
        &self,
        version: u64
    ) -> Result<Option<RrdpEvent>, Error> {
        let key = S::key_for_event(version);
        let id = rrdp_id();
        self.store.get::<RrdpEvent>(&id, &key).map_err(Error::KeyStoreError)
    }

    fn store_save_rrdp_event(
        &self,
        event: &RrdpEvent
    ) -> Result<(), Error> {
        let key = S::key_for_event(event.version());
        self.store.store(event.id(), &key, event).map_err(Error::KeyStoreError)?;
        Ok(())
    }

    fn store_save_init(
        &self,
        event: &PublisherInit
    ) -> Result<(), Error> {
        let key = S::key_for_event(event.version());
        self.store.store(event.id(), &key, event).map_err(Error::KeyStoreError)?;
        Ok(())
    }

    fn store_save_event(
        &self,
        event: &PublisherEvent
    ) -> Result<(), Error> {
        let key = S::key_for_event(event.version());
        self.store.store(event.id(), &key, event).map_err(Error::KeyStoreError)?;
        Ok(())
    }
}

/// # Add / remove / list publishers
impl<S: KeyStore> PubServer<S> {

    fn has_publisher(&self, handle: &PublisherHandle) -> Result<bool, Error> {
        Ok(self.get_publisher(handle)?.is_some())
    }

    /// Gets an existing publisher. Note, will also return de-activated
    /// publishers when asked.
    pub fn get_publisher(
        &self,
        handle: &PublisherHandle
    ) -> Result<Option<Arc<Publisher>>, Error> {
        match self.load_publisher(handle)? {
            None => Ok(None),
            Some(publisher) => Ok(Some(Arc::new(publisher)))
        }
    }

    fn verify_handle(&self, handle: &PublisherHandle) -> Result<(), Error> {
        let name = handle.name();

        if name == RRDP_TYPE_ID {
            return Err(Error::ReservedName(handle.to_string()))
        }

        if ! name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(Error::InvalidHandle(handle.to_string()))
        }

        if self.has_publisher(handle)? {
            return Err(Error::DuplicatePublisher(handle.to_string()))
        }

        Ok(())
    }

    fn verify_base_uri(&self, base_uri: &uri::Rsync) -> Result<(), Error> {
        if self.base_uri.is_parent_of(base_uri) && base_uri.ends_with("/") {
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

    /// Adds a publisher. Will complain if a publisher already exists for this
    /// handle. Will also verify that the base_uri is allowed.
    pub fn create_publisher(
        &self,
        req: PublisherRequest
    ) -> Result<(), Error> {
        let (handle, token, uri) = req.unwrap();
        let handle = PublisherHandle::from(handle);
        self.verify_handle(&handle)?;
        self.verify_base_uri(&uri)?;

        let init = PublisherInit::init(
            &handle,
            token,
            uri,
        );

        self.store_save_init(&init)?;

        Ok(())
    }

    /// Returns a list of publisher handles
    pub fn list_publishers(&self) -> Result<Vec<PublisherHandle>, Error> {
        let mut res = vec![];
        for agg_id in self.store.aggregates(PUBLISHER_TYPE_ID) {
            let handle = PublisherHandle::from(&agg_id);
            res.push(handle)
        }
        Ok(res)
    }

    /// Deactivates a publisher. For now this is irreversible, but we may add
    /// re-activation in future. Reason is that we never forget the history
    /// of the old publisher, and if handles are re-used by different
    /// entities that would get confusing.
    pub fn deactivate_publisher(
        &self,
        handle: &PublisherHandle
    ) -> Result<(), Error> {
        let cmd = PublisherCommand::deactivate(handle);
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
        let handle = PublisherHandle::from(command.id());

        match self.load_publisher(&handle)? {
            None => Err(Error::UnknownPublisher(handle.to_string())),
            Some(mut pbl) => {
                let mut res = None;

                if let Some(version) = command.version() {
                    if version != pbl.version() {
                        return Err(
                            Error::ConcurrentModification(version, pbl.version())
                        )
                    }
                }

                for event in pbl.process_command(command)? {
                    if let PublisherEventDetails::Published(delta) = event.details() {
                        res = Some(delta.clone())
                    }

                    self.store_save_event(&event)?;
                    pbl.apply(event);
                }

                Ok(res)
            }
        }
    }
}


/// # Publication Protocol support
///
impl<S: KeyStore> PubServer<S> {

    pub fn publish(
        &self,
        handle: &PublisherHandle,
        delta: publication_data::PublishDelta
    ) -> Result<(), Error> {

        match self.load_publisher(handle)? {
            None => Err(Error::UnknownPublisher(handle.to_string())),
            Some(publisher) => {
                let cmd = PublisherCommand::publish(handle, delta);

                let publisher_events = publisher.process_command(cmd)?;

                for event in &publisher_events {
                    if let PublisherEventDetails::Published(delta) = event.details() {
                        let mut rrdp = self.rrdp_updated_writer()?;
                        let delta = delta.clone();

                        self.rsyncd_store.publish(&delta)?;

                        let add_cmd = RrdpCommand::add_delta(delta);
                        let rrdp_add_delta_events = rrdp.process_command(add_cmd)?;

                        for e in &rrdp_add_delta_events {
                            rrdp.apply(e.clone());
                        }

                        let publish_cmd = RrdpCommand::publish();
                        let rrdp_publish_events = rrdp.process_command(publish_cmd)?;

                        for e in &rrdp_publish_events {
                            rrdp.apply(e.clone())
                        }

                        let retention = RetentionTime::from_secs(0);
                        let clean_cmd = RrdpCommand::clean_up(retention);
                        let rrdp_clean_events = rrdp.process_command(clean_cmd)?;

                        for e in rrdp_add_delta_events {
                            self.store_save_rrdp_event(&e)?;
                        }

                        for e in rrdp_publish_events {
                            self.store_save_rrdp_event(&e)?;
                        }

                        for e in rrdp_clean_events {
                            self.store_save_rrdp_event(&e)?;
                            rrdp.apply(e);
                        }
                    }
                }

                for e in publisher_events {
                    self.store_save_event(&e)?;
                }

                Ok(())
            }
        }
    }

    pub fn list(
        &self,
        handle: &PublisherHandle
    ) -> Result<publication_data::ListReply, Error> {
        match self.get_publisher(handle)? {
            Some(publisher) => Ok(publisher.list_current()),
            None => Err(Error::UnknownPublisher(handle.to_string()))
        }
    }
}


/// # Publishing
///
impl<S: KeyStore> PubServer<S> {
    pub fn rrdp_notification(&self) -> uri::Http {
        self.rrdp_reader().notification_uri()
    }
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    IoError(io::Error),

    #[display(fmt = "The publisher handle may only contain a-ZA-Z0-9 and _. You sent: {}", _0)]
    InvalidHandle(String),

    #[display(fmt = "The publisher handle may not use the reserved name: {}", _0)]
    ReservedName(String),

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
    KeyStoreError(KeyStoreError),
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

impl From<KeyStoreError> for Error {
    fn from(e: KeyStoreError) -> Self { Error::KeyStoreError(e) }
}

impl std::error::Error for Error {}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use std::path::PathBuf;
    use bytes::Bytes;
    use crate::api::publication_data::PublishDeltaBuilder;
    use crate::eventsourcing::DiskKeyStore;
    use crate::util::file::CurrentFile;
    use crate::util::test;
    use api::repo_data::VerificationError;

    fn server_base_uri() -> uri::Rsync {
        test::rsync_uri("rsync://localhost/repo/")
    }

    fn server_base_http_uri() -> uri::Http {
        test::http_uri("http://localhost/rrdp/")
    }

    fn make_publisher_req(
        handle: &str,
        uri: &str,
    ) -> PublisherRequest {
        let base_uri = test::rsync_uri(uri);
        let token = "secret";

        PublisherRequest::new(handle.to_string(), token.to_string(), base_uri)
    }

    fn make_server(work_dir: &PathBuf) -> PubServer<DiskKeyStore> {
        let mut store_dir = work_dir.clone();
        store_dir.push("pubserver");
        let store = DiskKeyStore::new(store_dir);

        let mut base_dir = work_dir.clone();
        base_dir.push("repo");

        PubServer::build(
            server_base_uri(),
            server_base_http_uri(),
            base_dir,
            store
        ).unwrap()
    }

    #[test]
    fn should_add_publisher() {
        test::test_with_tmp_dir(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );

            let server = make_server(&d);
            server.create_publisher(publisher_req).unwrap();

            let handle = PublisherHandle::from("alice");
            let alice = server.get_publisher(&handle).unwrap().unwrap();

            assert_eq!(alice.id(), &handle);
        })
    }

    #[test]
    fn should_refuse_invalid_publisher_handle() {
        test::test_with_tmp_dir(|d| {
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
        test::test_with_tmp_dir(|d| {
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
        test::test_with_tmp_dir(|d| {
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
        test::test_with_tmp_dir(|d| {
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
        test::test_with_tmp_dir(|d| {
            let server = make_server(&d);
            let handle = PublisherHandle::from("alice");

            // create publisher
            let publisher_req = make_publisher_req(
                handle.name(),
                "rsync://localhost/repo/alice/",
            );
            server.create_publisher(publisher_req).unwrap();

            // expect to see it in the list
            let list = server.list_publishers().unwrap();
            assert_eq!(list, vec![handle.clone()]);

            // deactivate
            let deactivate = PublisherCommand::deactivate(&handle);
            server.command_publisher(deactivate).unwrap();

            // expect that it is now inactive
            let alice = server.get_publisher(&handle).unwrap().unwrap();
            assert!(alice.is_deactivated())

        })
    }

    #[test]
    fn should_list_files() {
        test::test_with_tmp_dir(|d| {
            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );
            let handle = PublisherHandle::from("alice");

            let server = make_server(&d);
            server.create_publisher(publisher_req).unwrap();

            let alice = server.get_publisher(&handle).unwrap().unwrap();

            let list_reply = alice.list_current();
            assert_eq!(0, list_reply.elements().len());
        });
    }

    #[test]
    fn should_publish_files() {
        test::test_with_tmp_dir(|d| {
            // get the file out of a list_reply
            fn find_in_reply<'a>(
                reply: &'a publication_data::ListReply,
                uri: &uri::Rsync
            ) -> Option<&'a publication_data::ListElement> {
                reply.elements().iter().find(|e| e.uri() == uri)
            }

            let publisher_req = make_publisher_req(
                "alice",
                "rsync://localhost/repo/alice/",
            );
            let handle = PublisherHandle::from("alice");

            let server = make_server(&d);
            server.create_publisher(publisher_req).unwrap();

            // Publish a single file
            let file1 = CurrentFile::new(
                test::rsync_uri("rsync://localhost/repo/alice/file.txt"),
                &Bytes::from("example content")
            );

            let file2 = CurrentFile::new(
                test::rsync_uri("rsync://localhost/repo/alice/file2.txt"),
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
                &test::rsync_uri("rsync://localhost/repo/alice/file.txt")
            ).is_some());
            assert!(find_in_reply(
                &list_reply,
                &test::rsync_uri("rsync://localhost/repo/alice/file2.txt")
            ).is_some());

            // Update
            // - update file
            // - withdraw file2
            // - add file 3

            let file1_update = CurrentFile::new(
                test::rsync_uri("rsync://localhost/repo/alice/file.txt"),
                &Bytes::from("example content - updated")
            );

            let file3 = CurrentFile::new(
                test::rsync_uri("rsync://localhost/repo/alice/file3.txt"),
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
                &test::rsync_uri("rsync://localhost/repo/alice/file.txt")
            ).is_some());
            assert_eq!(
                find_in_reply(
                    &list_reply,
                    &test::rsync_uri("rsync://localhost/repo/alice/file.txt")
                ).unwrap().hash(),
                file1_update.hash()
            );
            assert!(find_in_reply(
                &list_reply,
                &test::rsync_uri("rsync://localhost/repo/alice/file3.txt")
            ).is_some());

            // Should reject publish outside of base uri
            let file_outside = CurrentFile::new(
                test::rsync_uri("rsync://localhost/repo/bob/file.txt"),
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
                test::rsync_uri("rsync://localhost/repo/alice/file2.txt"),
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
            let cmd = PublisherCommand::publish(&handle, delta);

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
                    test::rsync_uri("rsync://localhost/repo/alice/file3.txt")
                )},
                _ => panic!("Expected error publishing file that already exists")
            }
        });
    }
}