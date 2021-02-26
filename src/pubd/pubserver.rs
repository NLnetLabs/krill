use std::fs;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use rpki::uri;

use crate::commons::api::PublicationServerUris;
use crate::commons::crypto::{KrillSigner, ProtocolCms, ProtocolCmsBuilder};
use crate::commons::error::Error;
use crate::commons::eventsourcing::{AggregateStore, AggregateStoreError};
use crate::commons::remote::cmslogger::CmsLogger;
use crate::commons::remote::rfc8181;
use crate::commons::remote::rfc8183;
use crate::commons::KrillResult;
use crate::commons::{
    actor::Actor,
    api::{Handle, ListReply, PublishDelta, PublisherDetails, PublisherHandle, RepoInfo, RepositoryHandle},
};
use crate::constants::*;
use crate::daemon::config::Config;
use crate::pubd::{self, CmdDet, RepoStats, RepositoryAccess, RepositoryContentStore};

//------------ PubServer -----------------------------------------------------

/// The Publication Server.
///
/// This component is responsible for:
/// * managing allowed publishers
/// * verifying requests from remote RFC8183 publishers
/// * verifying requests from local (embedded) publishers
/// * updating the RRDP server with any deltas
/// * updating the contents on disk for Rsync
/// * responding to publishers
/// * wrapping responses in RFC8183 for remote publishers
///
pub struct PubServer {
    config: Arc<Config>,
    store: Arc<AggregateStore<RepositoryAccess>>,
    content: Arc<RepositoryContentStore>,
    signer: Arc<KrillSigner>,
}

/// # Constructing
///
impl PubServer {
    pub fn remove_if_empty(config: Arc<Config>, signer: Arc<KrillSigner>) -> Result<Option<Self>, Error> {
        let mut pub_server_dir = config.data_dir.clone();
        pub_server_dir.push(PUBSERVER_DIR);

        let mut repo_instance_dir = pub_server_dir.clone();
        repo_instance_dir.push(PUBSERVER_DFLT);

        let mut backup_pub_server_dir = config.data_dir.clone();
        backup_pub_server_dir.push(PUBSERVER_BACKUP_DIR);

        let mut corrupt_error_msg = "Could not start pre-existing repository server. This points at a corrupted data directory from an old installation.\n".to_string();
        corrupt_error_msg.push_str(
            "However, It looks like your configuration does not require that your run your own repository server.\n",
        );
        corrupt_error_msg.push_str(&format!(
            "Krill will now make a backup of this directory at {}\n",
            backup_pub_server_dir.to_string_lossy()
        ));
        corrupt_error_msg.push_str(
            "If you do not need to run your own repository you may delete this directory and just start Krill again.\n",
        );
        corrupt_error_msg.push_str("If do need to run your own repository then please use your previous installation and contact us at 'rpki-team@nlnetlabs.nl'.\n");

        if repo_instance_dir.exists() {
            if let Ok(server) = PubServer::build(config, signer) {
                if server.publishers()?.is_empty() {
                    info!(
                        "Removing unused repository server directory. Use 'krillpubd' if you need to run a repository."
                    );
                    let _result = fs::remove_dir_all(pub_server_dir);
                    Ok(None)
                } else {
                    warn!("Using pre-existing repository server. Note this will be DEPRECATED. You should use 'krillpubd' in future. See Changelog.md");
                    Ok(Some(server))
                }
            } else {
                if let Err(e) = fs::rename(pub_server_dir, backup_pub_server_dir) {
                    corrupt_error_msg.push_str(&format!("Oops, COULD NOT MAKE BACKUP: {}", e));
                }

                Err(Error::Custom(corrupt_error_msg))
            }
        } else if pub_server_dir.exists() {
            info!("Removing unused repository server directory. Use 'krillpubd' if you need to run a repository.");
            let _result = fs::remove_dir_all(pub_server_dir);
            Ok(None)
        } else {
            Ok(None)
        }
    }

    pub fn build(config: Arc<Config>, signer: Arc<KrillSigner>) -> Result<Self, Error> {
        let store = Arc::new(AggregateStore::<RepositoryAccess>::disk(
            &config.data_dir,
            PUBSERVER_DIR,
        )?);

        let mut force_session_reset = false;

        let default = Self::repository_handle();
        if store.has(&default)? {
            if config.always_recover_data {
                store.recover()?;
                force_session_reset = true;
            } else if let Err(e) = store.warm() {
                error!(
                    "Could not warm up cache, storage seems corrupt, will try to recover!! Error was: {}",
                    e
                );
                store.recover()?;
                force_session_reset = true;
            }
        }

        let content_store = Arc::new(RepositoryContentStore::disk(&config)?);

        let server = PubServer {
            config,
            store,
            content: content_store,
            signer,
        };

        if force_session_reset {
            server.rrdp_session_reset()?;
        }

        Ok(server)
    }
}
/// # Repository Server Management
///
impl PubServer {
    pub fn repository_handle() -> RepositoryHandle {
        Handle::from_str(PUBSERVER_DFLT).unwrap()
    }

    fn repository_access(&self) -> KrillResult<Arc<RepositoryAccess>> {
        let handle = Self::repository_handle();

        match self.store.get_latest(&handle) {
            Ok(repo) => Ok(repo),
            Err(e) => match e {
                AggregateStoreError::UnknownAggregate(_) => Err(Error::RepositoryServerNotEnabled),
                _ => Err(Error::AggregateStoreError(e)),
            },
        }
    }

    pub fn repository_initialised(&self) -> KrillResult<bool> {
        self.store
            .has(&Self::repository_handle())
            .map_err(Error::AggregateStoreError)
    }

    /// Create the publication server, will fail if it was already created.
    pub fn repository_init(&self, uris: PublicationServerUris) -> KrillResult<()> {
        if self.repository_access().is_ok() {
            Err(Error::RepositoryServerAlreadyInitialised)
        } else {
            info!("Creating default repository");

            let (rrdp_base_uri, rsync_jail) = uris.unpack();

            let ini = pubd::PubdIniDet::init(
                &Self::repository_handle(),
                rsync_jail.clone(),
                rrdp_base_uri.clone(),
                self.signer.deref(),
            )?;

            self.store.add(ini)?;

            self.content.init(&self.config.data_dir, rrdp_base_uri, rsync_jail)?;
            self.content.write_repository(&self.config.repository_retention)?;

            Ok(())
        }
    }

    /// Clear the publication server. Will fail if it still
    /// has publishers. Or if it does not exist
    pub fn repository_clear(&self) -> KrillResult<()> {
        let handle = Self::repository_handle();
        if !self.store.has(&handle)? {
            Err(Error::RepositoryServerNotInitialised)
        } else if !self.publishers()?.is_empty() {
            Err(Error::RepositoryServerHasPublishers)
        } else {
            self.store.drop_aggregate(&handle)?;
            self.content.clear()
        }
    }
}

/// # Publication Protocol support
///
impl PubServer {
    /// Handle an RFC8181 request and sign the response
    pub fn rfc8181(&self, publisher_handle: PublisherHandle, msg_bytes: Bytes) -> KrillResult<Bytes> {
        let repository = self.repository_access()?;
        let publisher = repository.get_publisher(&publisher_handle)?;

        let msg = ProtocolCms::decode(msg_bytes.clone(), false).map_err(|e| Error::Rfc8181Decode(e.to_string()))?;
        let cms_logger = CmsLogger::for_rfc8181_rcvd(self.config.rfc8181_log_dir.as_ref(), &publisher_handle);

        msg.validate(publisher.id_cert()).map_err(Error::Rfc8181Validation)?;

        let content = rfc8181::Message::from_signed_message(&msg)?;
        let query = content.into_query()?;

        let (response, should_log_cms) = match query {
            rfc8181::QueryMessage::ListQuery => {
                let list_reply = self.list(&publisher_handle)?;
                (rfc8181::Message::list_reply(list_reply), false)
            }
            rfc8181::QueryMessage::PublishDelta(delta) => match self.publish(publisher_handle, delta) {
                Ok(()) => (rfc8181::Message::success_reply(), true),
                Err(e) => {
                    let error_code = e.to_rfc8181_error_code();
                    let report_error = rfc8181::ReportError::reply(error_code, None);
                    let mut builder = rfc8181::ErrorReply::build_with_capacity(1);
                    builder.add(report_error);
                    (builder.build_message(), true)
                }
            },
        };

        let response_builder =
            ProtocolCmsBuilder::create(&repository.key_id(), self.signer.deref(), response.into_bytes())
                .map_err(Error::signer)?;

        let response_bytes = response_builder.as_bytes();
        if should_log_cms {
            cms_logger.received(&msg_bytes)?;
            cms_logger.reply(&response_bytes)?;
        }

        Ok(response_bytes)
    }

    /// Do an RRDP session reset
    pub fn rrdp_session_reset(&self) -> KrillResult<()> {
        self.content.session_reset(&self.config.repository_retention)
    }

    /// Let a known publisher publish in a repository.
    pub fn publish(&self, name: PublisherHandle, delta: PublishDelta) -> KrillResult<()> {
        let access = self.repository_access()?;
        let publisher = access.get_publisher(&name)?;
        let jail = publisher.base_uri();

        self.content
            .publish(&name, delta, jail, &self.config.repository_retention)
    }

    pub fn repo_stats(&self) -> KrillResult<RepoStats> {
        self.content.stats()
    }

    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        let repository = self.repository_access()?;
        Ok(repository.publishers())
    }

    /// Returns a list reply for a known publisher in a repository
    pub fn list(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        self.content.list_reply(publisher)
    }
}

/// # Manage publishers
///
impl PubServer {
    pub fn repo_info_for(&self, name: &PublisherHandle) -> KrillResult<RepoInfo> {
        let repository = self.repository_access()?;
        repository.repo_info_for(name)
    }

    pub fn get_publisher_details(&self, name: &PublisherHandle) -> KrillResult<PublisherDetails> {
        let access = self.repository_access()?;
        let publisher = access.get_publisher(name)?;
        let id_cert = publisher.id_cert().clone();
        let base_uri = publisher.base_uri().clone();

        let current = self.content.current_objects(name)?.into_elements();

        Ok(PublisherDetails::new(name, id_cert, base_uri, current))
    }

    /// Returns the RFC8183 Repository Response for the publisher
    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher: &PublisherHandle,
    ) -> KrillResult<rfc8183::RepositoryResponse> {
        let repository = self.repository_access()?;
        repository.repository_response(rfc8181_uri, publisher)
    }

    /// Adds a publisher. Will complain if a publisher already exists for this
    /// handle. Will also verify that the base_uri is allowed.
    pub fn create_publisher(&self, req: rfc8183::PublisherRequest, actor: &Actor) -> KrillResult<()> {
        let name = req.publisher_handle().clone();
        let base_uri = { self.repository_access()?.base_uri_for(&name)? };

        let repository_handle = Self::repository_handle();
        let cmd = CmdDet::add_publisher(&repository_handle, req, base_uri, actor);
        self.store.command(cmd)?;

        self.content.add_publisher(name)?;

        Ok(())
    }

    /// Deactivates a publisher. For now this is irreversible, but we may add
    /// re-activation in future. Reason is that we never forget the history
    /// of the old publisher, and if handles are re-used by different
    /// entities that would get confusing.
    pub fn remove_publisher(&self, name: PublisherHandle, actor: &Actor) -> KrillResult<()> {
        let access = self.repository_access()?;
        let publisher = access.get_publisher(&name)?;
        let base_uri = publisher.base_uri();

        self.content
            .remove_publisher(&name, base_uri, &self.config.repository_retention)?;

        let repository_handle = Self::repository_handle();
        let cmd = CmdDet::remove_publisher(&repository_handle, name, actor);
        self.store.command(cmd)?;

        Ok(())
    }
}

/// # Publishing RRDP and rsync
///
impl PubServer {
    /// Update the RRDP files and rsync content on disk.
    pub fn write_repository(&self) -> KrillResult<()> {
        self.content.write_repository(&self.config.repository_retention)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::str::FromStr;
    use std::{path::PathBuf, str::from_utf8};

    use bytes::Bytes;

    use tokio::time::delay_for;

    use super::*;
    use crate::{
        commons::{
            api::rrdp::{PublicationDeltaError, RrdpSession},
            api::{ListElement, PublishDeltaBuilder},
            crypto::{IdCert, IdCertBuilder},
            util::file::{self, CurrentFile},
        },
        pubd::Publisher,
        test::{self, https, init_config, rsync},
    };

    fn publisher_alice(work_dir: &PathBuf) -> Publisher {
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

    fn make_server(work_dir: &PathBuf) -> PubServer {
        enable_test_mode();
        let config = Arc::new(Config::test(work_dir));
        init_config(&config);

        let signer = KrillSigner::build(work_dir).unwrap();
        let signer = Arc::new(signer);

        let pubserver = PubServer::build(config, signer).unwrap();

        let rsync_base = rsync("rsync://localhost/repo/");
        let rrdp_base = https("https://localhost/repo/rrdp/");

        let uris = PublicationServerUris::new(rrdp_base, rsync_base);

        pubserver.repository_init(uris).unwrap();

        pubserver
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

        delay_for(Duration::from_secs(2)).await;

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

        let session = session_dir(&d);

        // Should not include
        assert!(!session_dir_contains_serial(&session, 0));

        // Should include
        assert!(session_dir_contains_serial(&session, 1));
        assert!(session_dir_contains_delta(&session, 1));
        assert!(session_dir_contains_snapshot(&session, 1));
        assert!(session_dir_contains_serial(&session, 2));
        assert!(session_dir_contains_delta(&session, 2));
        assert!(session_dir_contains_snapshot(&session, 2));

        delay_for(Duration::from_secs(2)).await;

        // Add file 4,5,6
        //
        let file4 = CurrentFile::new(test::rsync("rsync://localhost/repo/alice/file4.txt"), &Bytes::from("4"));

        let mut builder = PublishDeltaBuilder::new();
        builder.add_publish(file4.as_publish());
        let delta = builder.finish();

        server.publish(alice_handle.clone(), delta).unwrap();

        // Should include new snapshot and delta
        assert!(session_dir_contains_serial(&session, 3));
        assert!(session_dir_contains_delta(&session, 3));
        assert!(session_dir_contains_snapshot(&session, 3));

        // Should no longer include serial 0 or 1
        // the total size exceeds the snapshot, and they
        // have been retained long enough
        assert!(!session_dir_contains_serial(&session, 0));
        assert!(!session_dir_contains_serial(&session, 1));

        // Should still include
        assert!(session_dir_contains_serial(&session, 2));
        assert!(session_dir_contains_delta(&session, 2));
        assert!(session_dir_contains_snapshot(&session, 2));

        // Removing the publisher should remove its contents
        server.remove_publisher(alice_handle, &actor).unwrap();

        // new snapshot should be published, and should be empty now
        assert!(session_dir_contains_snapshot(&session, 4));
        let snapshot_bytes = file::read(&session_dir_snapshot(&session, 4)).unwrap();
        let snapshot_xml = from_utf8(&snapshot_bytes).unwrap();
        println!("\n\nsnapshot:\n\n{}", snapshot_xml);
        assert!(!snapshot_xml.contains("/alice/"));

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

        fn path_to_snapshot(base_dir: &PathBuf, session: &RrdpSession, serial: u64) -> PathBuf {
            let mut path = base_dir.clone();
            path.push("repo");
            path.push("rrdp");
            path.push(session.to_string());
            path.push(serial.to_string());
            path.push("snapshot.xml");
            path
        }

        // Find RRDP files on disk
        let stats_before = server.repo_stats().unwrap();
        let session_before = stats_before.session();
        let snapshot_before_session_reset = path_to_snapshot(&d, &session_before, 1);

        assert!(snapshot_before_session_reset.exists());

        // Now test that a session reset works...
        server.rrdp_session_reset().unwrap();

        // Should write new session and snapshot
        let stats_after = server.repo_stats().unwrap();
        let session_after = stats_after.session();
        let snapshot_after_session_reset = path_to_snapshot(&d, &session_after, 0);
        assert!(snapshot_after_session_reset.exists());

        // and clean up old dir
        assert!(!snapshot_before_session_reset.exists());

        let _ = fs::remove_dir_all(d);
    }

    fn session_dir(work_dir: &PathBuf) -> PathBuf {
        let mut rrdp_dir = work_dir.clone();
        rrdp_dir.push("repo/rrdp");

        for entry in fs::read_dir(&rrdp_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy() != "notification.xml" {
                return entry.path();
            }
        }
        panic!("Could not find session dir under: {}", work_dir.to_string_lossy())
    }

    fn session_dir_contains_serial(session: &PathBuf, serial: u64) -> bool {
        let mut path = session.clone();
        path.push(serial.to_string());
        path.is_dir()
    }

    fn session_dir_contains_delta(session: &PathBuf, serial: u64) -> bool {
        let mut path = session.clone();
        path.push(format!("{}/delta.xml", serial));
        path.exists()
    }

    fn session_dir_contains_snapshot(session: &PathBuf, serial: u64) -> bool {
        session_dir_snapshot(session, serial).exists()
    }

    fn session_dir_snapshot(session: &PathBuf, serial: u64) -> PathBuf {
        let mut path = session.clone();
        path.push(format!("{}/snapshot.xml", serial));
        path
    }
}
