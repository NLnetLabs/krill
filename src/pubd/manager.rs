use std::sync::Arc;

use bytes::Bytes;

use rpki::{
    ca::{
        idexchange,
        idexchange::{PublisherHandle, RepoInfo},
        publication,
        publication::{ListReply, PublishDelta},
    },
    repository::x509::Time,
};

use crate::{
    commons::{
        actor::Actor,
        api::{PublicationServerUris, PublisherDetails, RepoFileDeleteCriteria},
        crypto::KrillSigner,
        error::Error,
        util::cmslogger::CmsLogger,
        KrillResult,
    },
    daemon::{config::Config, mq::TaskQueue},
    pubd::{RepoStats, RepositoryAccessProxy, RepositoryContentProxy},
};

use super::RrdpUpdateNeeded;

//------------ RepositoryManager -----------------------------------------------------

/// RepositoryManager is responsible for:
/// * verifying that a publisher is allowed to publish
/// * publish content to RRDP and rsync
pub struct RepositoryManager {
    access: Arc<RepositoryAccessProxy>,
    content: Arc<RepositoryContentProxy>,

    // shared task queue, use to schedule RRDP updates when content is updated.
    tasks: Arc<TaskQueue>,

    config: Arc<Config>,
    signer: Arc<KrillSigner>,
}

/// # Constructing
///
impl RepositoryManager {
    /// Builds a RepositoryManager. This will use a KeyValueStore using the
    /// the storage uri specified in the supplied `Config`.
    pub fn build(config: Arc<Config>, tasks: Arc<TaskQueue>, signer: Arc<KrillSigner>) -> Result<Self, Error> {
        let access_proxy = Arc::new(RepositoryAccessProxy::create(&config)?);
        let content_proxy = Arc::new(RepositoryContentProxy::create(&config)?);

        Ok(RepositoryManager {
            access: access_proxy,
            content: content_proxy,
            tasks,
            config,
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
        self.access.init(uris.clone(), self.signer.clone())?;
        self.content.init(self.config.repo_dir(), uris)?;
        self.content.write_repository(self.config.rrdp_updates_config)?;

        Ok(())
    }

    /// Clear the publication server. Will fail if it still
    /// has publishers. Or if it does not exist.
    pub fn repository_clear(&self) -> KrillResult<()> {
        self.access.clear()?;
        self.content.clear()
    }

    /// Update snapshots on disk for faster re-starts
    pub fn update_snapshots(&self) -> KrillResult<()> {
        if self.initialized()? {
            self.content.update_snapshots()
        } else {
            Ok(())
        }
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

        let cms = self
            .access
            .decode_and_validate(&publisher_handle, &msg_bytes)
            .map_err(|e| {
                Error::Custom(format!(
                    "Issue with publication request by publisher '{}': {}",
                    publisher_handle, e
                ))
            })?;
        let message = cms.into_message();
        let query = message.as_query()?;

        let is_list_query = query == publication::Query::List;

        let response_result = self.rfc8181_message(&publisher_handle, query);

        let should_log_cms = response_result.is_err() || !is_list_query;

        let response = match response_result {
            Ok(response) => response,
            Err(e) => {
                let error_code = e.to_rfc8181_error_code();
                let report_error = publication::ReportError::with_code(error_code);
                let error_reply = publication::ErrorReply::for_error(report_error);

                publication::Message::error(error_reply)
            }
        };

        let response_bytes = self.access.respond(response, &self.signer)?.to_bytes();

        if should_log_cms {
            cms_logger.received(&msg_bytes)?;
            cms_logger.reply(&response_bytes)?;
        }

        Ok(response_bytes)
    }

    pub fn rfc8181_message(
        &self,
        publisher_handle: &PublisherHandle,
        query: publication::Query,
    ) -> KrillResult<publication::Message> {
        match query {
            publication::Query::List => {
                debug!("Received RFC 8181 list query for {}", publisher_handle);
                let list_reply = self.list(publisher_handle)?;
                Ok(publication::Message::list_reply(list_reply))
            }
            publication::Query::Delta(delta) => {
                debug!("Received RFC 8181 delta query for {}", publisher_handle);
                self.publish(publisher_handle, delta)?;
                Ok(publication::Message::success())
            }
        }
    }

    /// Do an RRDP session reset.
    pub fn rrdp_session_reset(&self) -> KrillResult<()> {
        self.content.session_reset(self.config.rrdp_updates_config)
    }

    /// Let a known publisher publish in a repository.
    pub fn publish(&self, publisher_handle: &PublisherHandle, delta: PublishDelta) -> KrillResult<()> {
        let publisher = self.access.get_publisher(publisher_handle)?;

        self.content
            .publish(publisher_handle.clone(), delta, publisher.base_uri())?;

        self.tasks.update_rrdp_if_needed(Time::now().into());
        Ok(())
    }

    /// Update RRDP (make new delta) if needed. If there are staged changes, but
    /// the rrdp update interval since last_update has not passed, then no update
    /// is done, but the eligible time for the next update is returned.
    pub fn update_rrdp_if_needed(&self) -> KrillResult<Option<Time>> {
        // See if an update is needed
        {
            match self.content.rrdp_update_needed(self.config.rrdp_updates_config)? {
                RrdpUpdateNeeded::No => return Ok(None),
                RrdpUpdateNeeded::Later(time) => return Ok(Some(time)),
                RrdpUpdateNeeded::Yes => {} // proceed
            }
        }

        let content = self.content.update_rrdp(self.config.rrdp_updates_config)?;
        content.write_repository(self.config.rrdp_updates_config)?;

        Ok(None)
    }

    /// Purge URI(s) from the server.
    pub fn delete_matching_files(&self, criteria: RepoFileDeleteCriteria) -> KrillResult<()> {
        // update RRDP first so we apply any staged deltas.
        self.content.update_rrdp(self.config.rrdp_updates_config)?;

        // delete matching files using the updated snapshot and stage a delta if needed.
        self.content.delete_matching_files(criteria.into())?;

        // update RRDP again to make the delta effective immediately.
        let content = self.content.update_rrdp(self.config.rrdp_updates_config)?;

        // Write the updated repository - NOTE: we no longer lock it.
        content.write_repository(self.config.rrdp_updates_config)?;

        Ok(())
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

        let current = self.content.current_objects(name)?.try_into_publish_elements()?;

        Ok(PublisherDetails::new(name, id_cert, base_uri, current))
    }

    /// Returns the RFC8183 Repository Response for the publisher.
    pub fn repository_response(&self, publisher: &PublisherHandle) -> KrillResult<idexchange::RepositoryResponse> {
        let rfc8181_uri = self.config.rfc8181_uri(publisher);
        self.access.repository_response(rfc8181_uri, publisher)
    }

    /// Adds a publisher. This will fail if a publisher already exists for the handle in the request.
    pub fn create_publisher(&self, req: idexchange::PublisherRequest, actor: &Actor) -> KrillResult<()> {
        let name = req.publisher_handle().clone();

        self.access.add_publisher(req, actor)?;
        self.content.add_publisher(name)
    }

    /// Removes a publisher and all of its content.
    pub fn remove_publisher(&self, name: PublisherHandle, actor: &Actor) -> KrillResult<()> {
        self.content.remove_publisher(name.clone())?;
        self.access.remove_publisher(name, actor)?;

        self.tasks.update_rrdp_if_needed(Time::now().into());

        Ok(())
    }
}

/// # Publishing RRDP and rsync
///
impl RepositoryManager {
    /// Update the RRDP files and rsync content on disk.
    pub fn write_repository(&self) -> KrillResult<()> {
        self.content.write_repository(self.config.rrdp_updates_config)
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
    use url::Url;

    use bytes::Bytes;
    use tokio::time::sleep;

    use rpki::{
        ca::{
            idexchange::Handle,
            publication::{ListElement, PublishDelta},
        },
        uri,
    };

    use super::*;

    use crate::{
        commons::{
            api::{
                rrdp::{PublicationDeltaError, RrdpSession},
                IdCertInfo,
            },
            crypto::{KrillSignerBuilder, OpenSslSignerConfig},
            util::file::{self, CurrentFile},
        },
        constants::*,
        daemon::config::{SignerConfig, SignerType},
        pubd::{Publisher, RrdpServer},
        test::{self, https, init_config, rsync},
    };

    fn publisher_alice(storage_uri: &Url) -> Publisher {
        // When the "hsm" feature is enabled we could be running the tests with PKCS#11 as the default signer type.
        // In that case, if the backend signer is SoftHSMv2, attempting to create a second instance of KrillSigner in
        // the same process will fail because it will attempt to login to SoftHSMv2 a second time which SoftHSMv2 does
        // not support. To work around this issue we therefore explicitly request that the second KrillSigner instance
        // that we create here uses OpenSSL as its backend signer.
        let signer = {
            let signer_type = SignerType::OpenSsl(OpenSslSignerConfig::default());
            let signer_config = SignerConfig::new("Alice".to_string(), signer_type);
            let signer_configs = &[signer_config];
            KrillSignerBuilder::new(storage_uri, Duration::from_secs(1), signer_configs)
                .build()
                .unwrap()
        };

        let id_cert = signer.create_self_signed_id_cert().unwrap();
        let base_uri = uri::Rsync::from_str("rsync://localhost/repo/alice/").unwrap();

        Publisher::new(id_cert.into(), base_uri)
    }

    fn make_publisher_req(handle: &str, id_cert: &IdCertInfo) -> idexchange::PublisherRequest {
        let handle = Handle::from_str(handle).unwrap();
        idexchange::PublisherRequest::new(id_cert.base64().clone(), handle, None)
    }

    fn make_server(storage_uri: &Url, data_dir: &Path) -> RepositoryManager {
        enable_test_mode();
        let mut config = Config::test(storage_uri, Some(data_dir), true, false, false, false);
        init_config(&mut config);

        let signer = KrillSignerBuilder::new(storage_uri, Duration::from_secs(1), &config.signers)
            .with_default_signer(config.default_signer())
            .with_one_off_signer(config.one_off_signer())
            .build()
            .unwrap();

        let signer = Arc::new(signer);
        let config = Arc::new(config);
        let mq = Arc::new(TaskQueue::default());
        let repository_manager = RepositoryManager::build(config, mq, signer).unwrap();

        let rsync_base = rsync("rsync://localhost/repo/");
        let rrdp_base = https("https://localhost/repo/rrdp/");

        let uris = PublicationServerUris::new(rrdp_base, rsync_base);

        repository_manager.init(uris).unwrap();

        repository_manager
    }

    #[test]
    fn should_add_publisher() {
        // we need a disk, as repo_dir, etc. use data_dir by default
        let (data_dir, cleanup) = test::tmp_dir();
        let storage_uri = test::tmp_storage();
        let server = make_server(&storage_uri, &data_dir);

        let alice = publisher_alice(&storage_uri);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req, &actor).unwrap();

        let alice_found = server.get_publisher_details(&alice_handle).unwrap();

        assert_eq!(alice_found.base_uri(), alice.base_uri());
        assert_eq!(alice_found.id_cert(), alice.id_cert());
        assert!(alice_found.current_files().is_empty());

        cleanup();
    }

    #[test]
    fn should_not_add_publisher_twice() {
        // we need a disk, as repo_dir, etc. use data_dir by default
        let (data_dir, cleanup) = test::tmp_dir();
        let storage_uri = test::tmp_storage();

        let server = make_server(&storage_uri, &data_dir);

        let alice = publisher_alice(&storage_uri);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req.clone(), &actor).unwrap();

        match server.create_publisher(publisher_req, &actor) {
            Err(Error::PublisherDuplicate(name)) => assert_eq!(name, alice_handle),
            _ => panic!("Expected error"),
        }

        cleanup();
    }

    #[test]
    fn should_list_files() {
        // we need a disk, as repo_dir, etc. use data_dir by default
        let (data_dir, cleanup) = test::tmp_dir();
        let storage_uri = test::tmp_storage();
        let server = make_server(&storage_uri, &data_dir);

        let alice = publisher_alice(&storage_uri);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
        server.create_publisher(publisher_req, &actor).unwrap();

        let list_reply = server.list(&alice_handle).unwrap();
        assert_eq!(0, list_reply.elements().len());

        cleanup();
    }

    #[tokio::test]
    async fn should_publish_files() {
        // we need a disk, as repo_dir, etc. use data_dir by default
        let (data_dir, cleanup) = test::tmp_dir();
        let storage_uri = test::tmp_storage();
        let server = make_server(&storage_uri, &data_dir);

        let session = session_dir(&data_dir);

        // Check that the server starts with dir for serial 1 for RRDP
        // and does not use 0 (RFC 8182)
        assert!(!session_dir_contains_serial(&session, 0));
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL));

        // set up server with default repository, and publisher alice
        let alice = publisher_alice(&storage_uri);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
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

        let mut delta = PublishDelta::empty();
        delta.add_publish(file1.as_publish());
        delta.add_publish(file2.as_publish());

        server.publish(&alice_handle, delta).unwrap();
        server.update_rrdp_if_needed().unwrap();
        server.write_repository().unwrap();

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

        let mut delta = PublishDelta::empty();
        delta.add_update(file1_update.as_update(file1.hash()));
        delta.add_withdraw(file2.as_withdraw());
        delta.add_publish(file3.as_publish());

        server.publish(&alice_handle, delta).unwrap();
        server.update_rrdp_if_needed().unwrap();
        server.write_repository().unwrap();

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
        let mut delta = PublishDelta::empty();
        delta.add_publish(file_outside.as_publish());

        match server.publish(&alice_handle, delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::UriOutsideJail(_, _))) => {} // ok
            _ => panic!("Expected error publishing outside of base uri jail"),
        }

        // Should reject update of file that does not exist
        let file2_update = CurrentFile::new(
            test::rsync("rsync://localhost/repo/alice/file2.txt"),
            &Bytes::from("example content 2 updated"),
        ); // file2 was removed
        let mut delta = PublishDelta::empty();
        delta.add_update(file2_update.as_update(file2.hash()));

        match server.publish(&alice_handle, delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::NoObjectForHashAndOrUri(_))) => {}
            _ => panic!("Expected error when file for update can't be found"),
        }

        // should reject withdraw for file that does not exist
        let mut delta = PublishDelta::empty();
        delta.add_withdraw(file2.as_withdraw());

        match server.publish(&alice_handle, delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::NoObjectForHashAndOrUri(_))) => {} // ok
            _ => panic!("Expected error withdrawing file that does not exist"),
        }

        // should reject publish for file that does exist
        let mut delta = PublishDelta::empty();
        delta.add_publish(file3.as_publish());

        match server.publish(&alice_handle, delta) {
            Err(Error::Rfc8181Delta(PublicationDeltaError::ObjectAlreadyPresent(uri))) => {
                assert_eq!(uri, test::rsync("rsync://localhost/repo/alice/file3.txt"))
            }
            _ => panic!("Expected error publishing file that already exists"),
        }

        //------------------------------------------------------
        // Check that old serials are cleaned
        //------------------------------------------------------

        // This delta was so big, that we are no longer including the
        // deltas for serial 1 and 2
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL));
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 1));

        // Add file 4
        let file4 = CurrentFile::new(test::rsync("rsync://localhost/repo/alice/file4.txt"), &Bytes::from("4"));

        let mut delta = PublishDelta::empty();
        delta.add_publish(file4.as_publish());

        server.publish(&alice_handle, delta).unwrap();
        server.update_rrdp_if_needed().unwrap();
        server.write_repository().unwrap();

        // Should include new snapshot and delta
        assert!(session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 3));
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 3));
        assert!(session_dir_contains_snapshot(&session, RRDP_FIRST_SERIAL + 3));

        // Should still include the delta for serial 3, as delta 4 was small.
        assert!(session_dir_contains_delta(&session, RRDP_FIRST_SERIAL + 2));

        // Removing the publisher should remove its contents
        server.remove_publisher(alice_handle, &actor).unwrap();
        server.update_rrdp_if_needed().unwrap();
        server.write_repository().unwrap();

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

        // We expect that the deltas for serial 3 and 4 are now also out of scope and
        // removed.
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 2));
        assert!(!session_dir_contains_serial(&session, RRDP_FIRST_SERIAL + 3));

        cleanup();
    }

    #[test]
    pub fn repository_session_reset() {
        let (data_dir, cleanup) = test::tmp_dir();
        let storage_uri = test::tmp_storage();
        let server = make_server(&storage_uri, &data_dir);

        // set up server with default repository, and publisher alice
        let alice = publisher_alice(&storage_uri);

        let alice_handle = Handle::from_str("alice").unwrap();
        let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

        let actor = Actor::actor_from_def(ACTOR_DEF_TEST);
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

        let mut delta = PublishDelta::empty();
        delta.add_publish(file1.as_publish());
        delta.add_publish(file2.as_publish());

        server.publish(&alice_handle, delta).unwrap();
        server.update_rrdp_if_needed().unwrap();
        server.write_repository().unwrap();

        // Two files should now appear in the list
        let list_reply = server.list(&alice_handle).unwrap();
        assert_eq!(2, list_reply.elements().len());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file.txt")).is_some());
        assert!(find_in_reply(&list_reply, &test::rsync("rsync://localhost/repo/alice/file2.txt")).is_some());

        // Find RRDP files on disk
        let stats_before = server.repo_stats().unwrap();
        let session_before = stats_before.session();
        let snapshot_before_session_reset =
            find_in_session_and_serial_dir(&data_dir, &session_before, RRDP_FIRST_SERIAL + 1, "snapshot.xml");

        assert!(snapshot_before_session_reset.is_some());

        // Now test that a session reset works...
        server.rrdp_session_reset().unwrap();

        // Should write new session and snapshot
        let stats_after = server.repo_stats().unwrap();
        let session_after = stats_after.session();

        let snapshot_after_session_reset =
            find_in_session_and_serial_dir(&data_dir, &session_after, RRDP_FIRST_SERIAL, "snapshot.xml");
        assert_ne!(snapshot_before_session_reset, snapshot_after_session_reset);

        assert!(snapshot_after_session_reset.is_some());

        // and clean up old dir
        let snapshot_before_session_reset =
            find_in_session_and_serial_dir(&data_dir, &session_before, RRDP_FIRST_SERIAL + 1, "snapshot.xml");

        assert!(snapshot_before_session_reset.is_none());

        cleanup();
    }

    fn session_dir(base_dir: &Path) -> PathBuf {
        let mut rrdp_dir = base_dir.to_path_buf();
        rrdp_dir = rrdp_dir.join("repo/rrdp");

        for entry in fs::read_dir(&rrdp_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy() != "notification.xml" {
                return entry.path();
            }
        }
        panic!("Could not find session dir under: {}", base_dir.to_string_lossy())
    }

    fn session_dir_contains_serial(session_uri: &Path, serial: u64) -> bool {
        let mut path = session_uri.to_path_buf();
        path.push(serial.to_string());
        path.is_dir()
    }

    fn session_dir_contains_delta(session_uri: &Path, serial: u64) -> bool {
        RrdpServer::find_in_serial_dir(session_uri, serial, "delta.xml")
            .unwrap()
            .is_some()
    }

    fn session_dir_contains_snapshot(session_uri: &Path, serial: u64) -> bool {
        RrdpServer::session_dir_snapshot(session_uri, serial).unwrap().is_some()
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
