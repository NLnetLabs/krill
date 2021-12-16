use std::sync::Arc;

use bytes::Bytes;

use crate::{
    commons::{
        actor::Actor,
        api::{ListReply, PublicationServerUris, PublishDelta, PublisherDetails, PublisherHandle, RepoInfo},
        crypto::KrillSigner,
        error::Error,
        remote::cmslogger::CmsLogger,
        remote::rfc8181,
        remote::rfc8183,
        KrillResult,
    },
    daemon::config::Config,
    pubd::{RepoStats, RepositoryAccessProxy, RepositoryContentProxy},
};

//------------ RepositoryManager -----------------------------------------------------

/// RepositoryManager is responsible for:
/// * verifying that a publisher is allowed to publish
/// * publish content to RRDP and rsync
pub struct RepositoryManager {
    config: Arc<Config>,
    access: Arc<RepositoryAccessProxy>,
    content: Arc<RepositoryContentProxy>,
    signer: Arc<KrillSigner>,
}

/// # Constructing
///
impl RepositoryManager {
    /// Builds a RepositoryManager. This will use a disk based KeyValueStore using the
    /// the data directory specified in the supplied `Config`.
    pub fn build(config: Arc<Config>, signer: Arc<KrillSigner>) -> Result<Self, Error> {
        let content_proxy = Arc::new(RepositoryContentProxy::disk(&config)?);
        let access_proxy = Arc::new(RepositoryAccessProxy::disk(&config)?);

        Ok(RepositoryManager {
            config,
            access: access_proxy,
            content: content_proxy,
            signer,
        })
    }
}
/// # Repository Server Management
///
impl RepositoryManager {
    pub fn initialized(&self) -> KrillResult<bool> {
        self.access.initialized()
    }

    /// Create the publication server, will fail if it was already created.
    pub fn init(&self, uris: PublicationServerUris) -> KrillResult<()> {
        info!("Initializing repository");
        self.access.init(uris.clone(), &self.signer)?;
        self.content.init(&self.config.data_dir, uris)?;
        self.content.write_repository(&self.config.repository_retention)?;

        Ok(())
    }

    /// Clear the publication server. Will fail if it still
    /// has publishers. Or if it does not exist.
    pub fn repository_clear(&self) -> KrillResult<()> {
        self.access.clear()?;
        self.content.clear()
    }

    /// List all current publishers
    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        self.access.publishers()
    }
}

/// # Publication Protocol support
///
impl RepositoryManager {
    /// Handle an RFC8181 request and sign the response.
    pub fn rfc8181(&self, publisher_handle: PublisherHandle, msg_bytes: Bytes) -> KrillResult<Bytes> {
        let cms_logger = CmsLogger::for_rfc8181_rcvd(self.config.rfc8181_log_dir.as_ref(), &publisher_handle);

        let msg = self.access.validate(&publisher_handle, msg_bytes.clone())?;
        let content = rfc8181::Message::from_signed_message(&msg)?;
        let query = content.into_query()?;

        let (response, should_log_cms) = match query {
            rfc8181::QueryMessage::ListQuery => {
                let list_reply = self.list(&publisher_handle)?;
                (rfc8181::Message::list_reply(list_reply), false)
            }
            rfc8181::QueryMessage::PublishDelta(delta) => match self.publish(publisher_handle.clone(), delta) {
                Ok(()) => (rfc8181::Message::success_reply(), true),
                Err(e) => {
                    warn!("Rejecting delta sent by: {}. Error was: {}", publisher_handle, e);

                    let error_code = e.to_rfc8181_error_code();
                    let report_error = rfc8181::ReportError::reply(error_code, None);
                    let mut builder = rfc8181::ErrorReply::build_with_capacity(1);
                    builder.add(report_error);
                    (builder.build_message(), true)
                }
            },
        };

        let response_bytes = self.access.respond(response.into_bytes(), &self.signer)?;

        if should_log_cms {
            cms_logger.received(&msg_bytes)?;
            cms_logger.reply(&response_bytes)?;
        }

        Ok(response_bytes)
    }

    /// Do an RRDP session reset.
    pub fn rrdp_session_reset(&self) -> KrillResult<()> {
        self.content.session_reset(&self.config.repository_retention)
    }

    /// Let a known publisher publish in a repository.
    pub fn publish(&self, name: PublisherHandle, delta: PublishDelta) -> KrillResult<()> {
        let publisher = self.access.get_publisher(&name)?;

        self.content
            .publish(&name, delta, publisher.base_uri(), &self.config.repository_retention)
    }

    pub fn repo_stats(&self) -> KrillResult<RepoStats> {
        self.content.stats()
    }

    /// Returns a list reply for a known publisher in a repository.
    pub fn list(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.content.list_reply(publisher)
    }
}

/// # Manage publishers
///
impl RepositoryManager {
    /// Returns the repository URI information for a publisher.
    pub fn repo_info_for(&self, name: &PublisherHandle) -> KrillResult<RepoInfo> {
        self.access.repo_info_for(name)
    }

    pub fn get_publisher_details(&self, name: &PublisherHandle) -> KrillResult<PublisherDetails> {
        let publisher = self.access.get_publisher(name)?;
        let id_cert = publisher.id_cert().clone();
        let base_uri = publisher.base_uri().clone();

        let current = self.content.current_objects(name)?.into_elements();

        Ok(PublisherDetails::new(name, id_cert, base_uri, current))
    }

    /// Returns the RFC8183 Repository Response for the publisher.
    pub fn repository_response(&self, publisher: &PublisherHandle) -> KrillResult<rfc8183::RepositoryResponse> {
        let rfc8181_uri = self.config.rfc8181_uri(publisher);
        self.access.repository_response(rfc8181_uri, publisher)
    }

    /// Adds a publisher. This will fail if a publisher already exists for the handle in the request.
    pub fn create_publisher(&self, req: rfc8183::PublisherRequest, actor: &Actor) -> KrillResult<()> {
        let name = req.publisher_handle().clone();

        self.access.add_publisher(req, actor)?;
        self.content.add_publisher(name)
    }

    /// Removes a publisher and all of its content.
    pub fn remove_publisher(&self, name: PublisherHandle, actor: &Actor) -> KrillResult<()> {
        let publisher = self.access.get_publisher(&name)?;
        let base_uri = publisher.base_uri();

        self.content
            .remove_publisher(&name, base_uri, &self.config.repository_retention)?;

        self.access.remove_publisher(name, actor)
    }
}

/// # Publishing RRDP and rsync
///
impl RepositoryManager {
    /// Update the RRDP files and rsync content on disk.
    pub fn write_repository(&self) -> KrillResult<()> {
        self.content.write_repository(&self.config.repository_retention)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        str::{from_utf8, FromStr},
        time::Duration,
    };

    use bytes::Bytes;
    use tokio::time::sleep;

    use rpki::uri;

    use crate::{constants::*, pubd::RrdpServer};

    use super::*;

    use crate::{
        commons::{
            api::rrdp::{PublicationDeltaError, RrdpSession},
            api::{Handle, ListElement, PublishDeltaBuilder},
            crypto::{IdCert, IdCertBuilder},
            util::file::{self, CurrentFile},
        },
        pubd::Publisher,
        test::{self, https, init_config, rsync},
    };

    fn publisher_alice(work_dir: &Path) -> Publisher {
        let signer = KrillSigner::build(work_dir).unwrap();

        let key = signer.create_key().unwrap();
        let id_cert = IdCertBuilder::new_ta_id_cert(&key, &signer).unwrap();

        let base_uri = uri::Rsync::from_str("rsync://localhost/repo/alice/").unwrap();

        Publisher::new(id_cert, base_uri)
    }

    fn make_publisher_req(handle: &str, id_cert: &IdCert) -> rfc8183::PublisherRequest {
        let handle = Handle::from_str(handle).unwrap();
        rfc8183::PublisherRequest::new(None, handle, id_cert.clone())
    }

    fn make_server(work_dir: &Path) -> RepositoryManager {
        enable_test_mode();
        let config = Arc::new(Config::test(work_dir, true, false, false));
        init_config(&config);

        let signer = KrillSigner::build(work_dir).unwrap();
        let signer = Arc::new(signer);

        let repository_manager = RepositoryManager::build(config, signer).unwrap();

        let rsync_base = rsync("rsync://localhost/repo/");
        let rrdp_base = https("https://localhost/repo/rrdp/");

        let uris = PublicationServerUris::new(rrdp_base, rsync_base);

        repository_manager.init(uris).unwrap();

        repository_manager
    }

    #[test]
    fn should_add_publisher() {
        let d = test::tmp_dir();
        let server = make_server(&d);

        let alice = publisher_alice(&d);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::test_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req, &actor).unwrap();

        let alice_found = server.get_publisher_details(&alice_handle).unwrap();

        assert_eq!(alice_found.base_uri(), alice.base_uri());
        assert_eq!(alice_found.id_cert(), alice.id_cert());
        assert!(alice_found.current_files().is_empty());

        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn should_not_add_publisher_twice() {
        let d = test::tmp_dir();
        let server = make_server(&d);

        let alice = publisher_alice(&d);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::test_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req.clone(), &actor).unwrap();

        match server.create_publisher(publisher_req, &actor) {
            Err(Error::PublisherDuplicate(name)) => assert_eq!(name, alice_handle),
            _ => panic!("Expected error"),
        }
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn should_list_files() {
        let d = test::tmp_dir();
        let server = make_server(&d);

        let alice = publisher_alice(&d);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::test_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req, &actor).unwrap();

        let list_reply = server.list(&alice_handle).unwrap();
        assert_eq!(0, list_reply.elements().len());

        let _ = fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn should_publish_files() {
        let d = test::tmp_dir();
        let server = make_server(&d);
        let session = session_dir(&d);

        // Check that the server starts with dir for serial 1 for RRDP
        // and does not use 0 (RFC 8182)
        assert!(!session_dir_contains_serial(&session, 0));
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL));

        // set up server with default repository, and publisher alice
        let alice = publisher_alice(&d);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::test_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req, &actor).unwrap();

        // get the file out of a list_reply
        fn find_in_reply<'a>(reply: &'a ListReply, uri: &uri::Rsync) -> Option<&'a ListElement> {
            reply.elements().iter().find(|e| e.uri() == uri)
        }

        // Publish files
        let file1 = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file.txt"),
            &Bytes::from("example content"),
        );

        let file2 = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file2.txt"),
            &Bytes::from("example content 2"),
        );

        let mut builder = PublishDeltaBuilder::new();
        builder.add_publish(file1.as_publish());
        builder.add_publish(file2.as_publish());
        let delta = builder.finish();

        server.publish(alice_handle.clone(), delta).unwrap();

        // Two files should now appear in the list
        let list_reply = server.list(&alice_handle).unwrap();
        assert_eq!(2, list_reply.elements().len());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file.txt")).is_some());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file2.txt")).is_some());

        sleep(Duration::from_secs(2)).await;

        // Update
        // - update file
        // - withdraw file2
        // - add big file 3

        let file1_update = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file.txt"),
            &Bytes::from("example content - updated"),
        );

        let big_file_3 = include_bytes!("../../LICENSE");
        let file3 = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file3.txt"),
            &Bytes::from_static(big_file_3),
        );

        let mut builder = PublishDeltaBuilder::new();
        builder.add_update(file1_update.as_update(file1.hash()));
        builder.add_withdraw(file2.as_withdraw());
        builder.add_publish(file3.as_publish());
        let delta = builder.finish();

        server.publish(alice_handle.clone(), delta).unwrap();

        // Two files should now appear in the list
        let list_reply = server.list(&alice_handle).unwrap();

        assert_eq!(2, list_reply.elements().len());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file.txt")).is_some());
        assert_eq!(
            find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file.txt"))
                .unwrap()
                .hash(),
            file1_update.hash()
        );
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file3.txt")).is_some());

        // Should reject publish outside of base uri
        let file_outside = CurrentFile::new(
            test::rsync("rsync://localhost/repo/bob/file.txt"),
            &Bytes::from("irrelevant"),
        );
        let mut builder = PublishDeltaBuilder::new();
        builder.add_publish(file_outside.as_publish());
        let delta = builder.finish();

        match server.publish(alice_handle.clone(), delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::UriOutsideJail(_, _))) => {} // ok
            _ => panic!("Expected error publishing outside of base uri jail"),
        }

        // Should reject update of file that does not exist
        let file2_update = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file2.txt"),
            &Bytes::from("example content 2 updated"),
        ); // file2 was removed
        let mut builder = PublishDeltaBuilder::new();
        builder.add_update(file2_update.as_update(file2.hash()));
        let delta = builder.finish();

        match server.publish(alice_handle.clone(), delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::NoObjectForHashAndOrUri(_))) => {}
            _ => panic!("Expected error when file for update can't be found"),
        }

        // should reject withdraw for file that does not exist
        let mut builder = PublishDeltaBuilder::new();
        builder.add_withdraw(file2.as_withdraw());
        let delta = builder.finish();

        match server.publish(alice_handle.clone(), delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::NoObjectForHashAndOrUri(_))) => {} // ok
            _ => panic!("Expected error withdrawing file that does not exist"),
        }

        // should reject publish for file that does exist
        let mut builder = PublishDeltaBuilder::new();
        builder.add_publish(file3.as_publish());
        let delta = builder.finish();

        match server.publish(alice_handle.clone(), delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::ObjectAlreadyPresent(uri))) => {
                assert_eq!(uri, test::rsync("rsync://localhost/repo/alice/file3.txt"))
            }
            _ => panic!("Expected error publishing file that already exists"),
        }

        //------------------------------------------------------
        // Check that old serials are cleaned
        //------------------------------------------------------

        // Should not include
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL));

        // Should include
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 1));
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 1));
        assert!(session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 1));
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 2));
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 2));
        assert!(session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 2));

        sleep(Duration::from_secs(2)).await;

        // Add file 4,5,6
        //
        let file4 = CurrentFile::new(test::rsync("rsync://localhost/repo/alice/file4.txt"), &Bytes::from("4"));

        let mut builder = PublishDeltaBuilder::new();
        builder.add_publish(file4.as_publish());
        let delta = builder.finish();

        server.publish(alice_handle.clone(), delta).unwrap();

        // Should include new snapshot and delta
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 3));
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 3));
        assert!(session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 3));

        // Should no longer include serial RRDP_FIRST_SERIAL or RRDP_FIRST_SERIAL + 1
        // the total size exceeds the snapshot, and they have been retained long enough
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL));
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 1));

        // Should still include
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 2));
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 2));
        assert!(session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 2));

        // Wait a bit to ensure that the notification file for serial RRDP_FIRST_SERIAL + 2 will be out of scope
        sleep(Duration::from_secs(2)).await;

        // Removing the publisher should remove its contents
        server.remove_publisher(alice_handle, &actor).unwrap();

        // new snapshot should be published, and should be empty now
        assert!(session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 4));
        let snapshot_bytes = file::read(
            &RrdpServer::session_dir_snapshot(&session, RRDP_FIRST_SERIAL + 4)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let snapshot_xml = from_utf8(&snapshot_bytes).unwrap();
        assert!(!snapshot_xml.contains("/alice/"));

        // We expect that the delta for serial RRDP_FIRST_SERIAL + 2 is still there because it is still referenced,
        // but the snapshot is gone because it is no longer referenced and the notification for
        // serial +2 is now more than 1 second old (1s is the retention time configured for the test)
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 2));
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 2));
        assert!(!session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 2));

        let _ = fs::remove_dir_all(d);
    }

    #[test]
    pub fn repository_session_reset() {
        let d = test::tmp_dir();
        let server = make_server(&d);

        // set up server with default repository, and publisher alice
        let alice = publisher_alice(&d);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::test_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req, &actor).unwrap();

        // get the file out of a list_reply
        fn find_in_reply<'a>(reply: &'a ListReply, uri: &uri::Rsync) -> Option<&'a ListElement> {
            reply.elements().iter().find(|e| e.uri() == uri)
        }

        // Publish files
        let file1 = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file.txt"),
            &Bytes::from("example content"),
        );

        let file2 = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file2.txt"),
            &Bytes::from("example content 2"),
        );

        let mut builder = PublishDeltaBuilder::new();
        builder.add_publish(file1.as_publish());
        builder.add_publish(file2.as_publish());
        let delta = builder.finish();

        server.publish(alice_handle.clone(), delta).unwrap();

        // Two files should now appear in the list
        let list_reply = server.list(&alice_handle).unwrap();
        assert_eq!(2, list_reply.elements().len());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file.txt")).is_some());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file2.txt")).is_some());

        // Find RRDP files on disk
        let stats_before = server.repo_stats().unwrap();
        let session_before = stats_before.session();
        let snapshot_before_session_reset =
            find_in_session_and_serial_dir(&d, &session_before, RRDP_FIRST_SERIAL + 1, "snapshot.xml");

        assert!(snapshot_before_session_reset.is_some());

        // Now test that a session reset works...
        server.rrdp_session_reset().unwrap();

        // Should write new session and snapshot
        let stats_after = server.repo_stats().unwrap();
        let session_after = stats_after.session();

        let snapshot_after_session_reset =
            find_in_session_and_serial_dir(&d, &session_after, RRDP_FIRST_SERIAL, "snapshot.xml");
        assert_ne!(snapshot_before_session_reset, snapshot_after_session_reset);

        assert!(snapshot_after_session_reset.is_some());

        // and clean up old dir
        let snapshot_before_session_reset =
            find_in_session_and_serial_dir(&d, &session_before, RRDP_FIRST_SERIAL + 1, "snapshot.xml");

        assert!(snapshot_before_session_reset.is_none());

        let _ = fs::remove_dir_all(d);
    }

    fn session_dir(work_dir: &Path) -> PathBuf {
        let mut rrdp_dir = work_dir.to_path_buf();
        rrdp_dir.push("repo/rrdp");

        for entry in fs::read_dir(&rrdp_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy() != "notification.xml" {
                return entry.path();
            }
        }
        panic!("Could not find session dir under: {}", work_dir.to_string_lossy())
    }

    fn session_dir_contains_serial(session_path: &Path, serial: u64) -> bool {
        let mut path = session_path.to_path_buf();
        path.push(serial.to_string());
        path.is_dir()
    }

    fn session_dir_contains_delta(session_path: &Path, serial: u64) -> bool {
        RrdpServer::find_in_serial_dir(session_path, serial, "delta.xml")
            .unwrap()
            .is_some()
    }

    fn session_dir_contains_snapshot(session_path: &Path, serial: u64) -> bool {
        RrdpServer::session_dir_snapshot(session_path, serial)
            .unwrap()
            .is_some()
    }

    fn find_in_session_and_serial_dir(
        base_dir: &Path,
        session: &RrdpSession,
        serial: u64,
        filename: &str,
    ) -> Option<PathBuf> {
        let session_path = base_dir.join(format!("repo/rrdp/{}", session));
        RrdpServer::find_in_serial_dir(&session_path, serial, filename).unwrap()
    }
}
