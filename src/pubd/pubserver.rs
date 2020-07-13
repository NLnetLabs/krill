use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use rpki::uri;

use crate::commons::api::{
    Handle, ListReply, PublishDelta, PublisherDetails, PublisherHandle, RepoInfo, RepositoryHandle,
};
use crate::commons::error::Error;
use crate::commons::eventsourcing::{AggregateStore, AggregateStoreError, DiskAggregateStore};
use crate::commons::remote::builder::SignedMessageBuilder;
use crate::commons::remote::cmslogger::CmsLogger;
use crate::commons::remote::rfc8181;
use crate::commons::remote::rfc8183;
use crate::commons::remote::sigmsg::SignedMessage;
use crate::commons::util::softsigner::OpenSslSigner;
use crate::commons::KrillResult;
use crate::constants::*;
use crate::pubd::{self, CmdDet, RepoStats, Repository};

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
    store: Arc<DiskAggregateStore<Repository>>,
    signer: Arc<RwLock<OpenSslSigner>>,
    rfc8181_log_dir: Option<PathBuf>,
}

/// # Constructing
///
impl PubServer {
    pub fn remove_if_empty(
        rsync_base: &uri::Rsync,
        rrdp_base_uri: uri::Https,         // for the RRDP files
        work_dir: &PathBuf,                // for the aggregate stores
        rfc8181_log_dir: Option<&PathBuf>, // for optional CMS exchange logging
        signer: Arc<RwLock<OpenSslSigner>>,
    ) -> Result<Option<Self>, Error> {
        let mut pub_server_dir = work_dir.clone();
        pub_server_dir.push(PUBSERVER_DIR);
        if pub_server_dir.exists() {
            let server =
                PubServer::build(rsync_base, rrdp_base_uri, work_dir, rfc8181_log_dir, signer)?;
            if server.publishers()?.is_empty() {
                let _result = fs::remove_dir_all(pub_server_dir);
                Ok(None)
            } else {
                Ok(Some(server))
            }
        } else {
            Ok(None)
        }
    }

    pub fn build(
        rsync_base: &uri::Rsync,
        rrdp_base_uri: uri::Https,         // for the RRDP files
        work_dir: &PathBuf,                // for the aggregate stores
        rfc8181_log_dir: Option<&PathBuf>, // for optional CMS exchange logging
        signer: Arc<RwLock<OpenSslSigner>>,
    ) -> Result<Self, Error> {
        let default = Self::repository_handle();

        let store = Arc::new(DiskAggregateStore::<Repository>::new(
            work_dir,
            PUBSERVER_DIR,
        )?);

        if !store.has(&default) {
            info!("Creating default repository");

            let mut signer = signer.write().unwrap();
            let ini = pubd::IniDet::init(
                &default,
                rsync_base.clone(),
                rrdp_base_uri,
                work_dir,
                signer.deref_mut(),
            )?;
            store.add(ini)?;
        }

        Ok(PubServer {
            store,
            signer,
            rfc8181_log_dir: rfc8181_log_dir.cloned(),
        })
    }
}

/// # Publication Protocol support
///
impl PubServer {
    fn repository_handle() -> RepositoryHandle {
        Handle::from_str(PUBSERVER_DFLT).unwrap()
    }

    fn repository(&self) -> KrillResult<Arc<Repository>> {
        let handle = Self::repository_handle();

        match self.store.get_latest(&handle) {
            Ok(repo) => Ok(repo),
            Err(e) => match e {
                AggregateStoreError::UnknownAggregate(_) => Err(Error::PublisherNoEmbeddedRepo),
                _ => Err(Error::AggregateStoreError(e)),
            },
        }
    }

    /// Handle an RFC8181 request and sign the response
    pub fn rfc8181(
        &self,
        publisher_handle: PublisherHandle,
        msg_bytes: Bytes,
    ) -> KrillResult<Bytes> {
        let repository = self.repository()?;
        let publisher = repository.get_publisher(&publisher_handle)?;

        let msg = SignedMessage::decode(msg_bytes.clone(), false)
            .map_err(|e| Error::Rfc8181Decode(e.to_string()))?;
        let cms_logger =
            CmsLogger::for_rfc8181_rcvd(self.rfc8181_log_dir.as_ref(), &publisher_handle);

        msg.validate(publisher.id_cert())
            .map_err(Error::Rfc8181Validation)?;

        let content = rfc8181::Message::from_signed_message(&msg)?;
        let query = content.into_query()?;

        let (response, should_log_cms) = match query {
            rfc8181::QueryMessage::ListQuery => {
                let list_reply = publisher.list_current();
                (rfc8181::Message::list_reply(list_reply), false)
            }
            rfc8181::QueryMessage::PublishDelta(delta) => {
                match self.publish(publisher_handle, delta) {
                    Ok(()) => (rfc8181::Message::success_reply(), true),
                    Err(e) => {
                        let error_code = e.to_rfc8181_error_code();
                        let report_error = rfc8181::ReportError::reply(error_code, None);
                        let mut builder = rfc8181::ErrorReply::build_with_capacity(1);
                        builder.add(report_error);
                        (builder.build_message(), true)
                    }
                }
            }
        };

        let signer = self.signer.read().map_err(Error::signer)?;

        let response_builder = SignedMessageBuilder::create(
            repository.key_id(),
            signer.deref(),
            response.into_bytes(),
        )
        .map_err(Error::signer)?;

        let response_bytes = response_builder.as_bytes();
        if should_log_cms {
            cms_logger.received(&msg_bytes)?;
            cms_logger.reply(&response_bytes)?;
        }

        Ok(response_bytes)
    }

    /// Let a known publisher publish in a repository.
    pub fn publish(&self, publisher: PublisherHandle, delta: PublishDelta) -> KrillResult<()> {
        let repository_handle = Self::repository_handle();
        let cmd = CmdDet::publish(&repository_handle, publisher, delta);
        self.store.command(cmd)?;
        self.write_repository()
    }

    pub fn repo_stats(&self) -> KrillResult<RepoStats> {
        let repo = self.repository()?;
        Ok(repo.stats().clone())
    }

    pub fn publishers(&self) -> KrillResult<Vec<PublisherHandle>> {
        let repository = self.repository()?;
        Ok(repository.publishers())
    }

    /// Returns a list reply for a known publisher in a repository
    pub fn list(&self, publisher: &PublisherHandle) -> KrillResult<ListReply> {
        let repository = self.repository()?;
        let publisher = repository.get_publisher(publisher)?;
        Ok(publisher.list_current())
    }
}

/// # Manage publishers
///
impl PubServer {
    pub fn repo_info_for(&self, publisher: &PublisherHandle) -> KrillResult<RepoInfo> {
        let repository = self.repository()?;
        Ok(repository.repo_info_for(publisher))
    }

    pub fn get_publisher_details(
        &self,
        publisher_handle: &PublisherHandle,
    ) -> KrillResult<PublisherDetails> {
        let repository = self.repository()?;
        repository
            .get_publisher(publisher_handle)
            .map(|p| p.as_api_details(publisher_handle))
    }

    /// Returns the RFC8183 Repository Response for the publisher
    pub fn repository_response(
        &self,
        rfc8181_uri: uri::Https,
        publisher: &PublisherHandle,
    ) -> KrillResult<rfc8183::RepositoryResponse> {
        let repository = self.repository()?;
        repository.repository_response(rfc8181_uri, publisher)
    }

    /// Adds a publisher. Will complain if a publisher already exists for this
    /// handle. Will also verify that the base_uri is allowed.
    pub fn create_publisher(&self, req: rfc8183::PublisherRequest) -> KrillResult<()> {
        let repository_handle = Self::repository_handle();
        let cmd = CmdDet::add_publisher(&repository_handle, req);
        self.store.command(cmd)?;
        Ok(())
    }

    /// Deactivates a publisher. For now this is irreversible, but we may add
    /// re-activation in future. Reason is that we never forget the history
    /// of the old publisher, and if handles are re-used by different
    /// entities that would get confusing.
    pub fn remove_publisher(&self, publisher: PublisherHandle) -> KrillResult<()> {
        let repository_handle = Self::repository_handle();
        let cmd = CmdDet::remove_publisher(&repository_handle, publisher);
        self.store.command(cmd)?;
        self.write_repository()
    }
}

/// # Publishing RRDP and rsync
///
impl PubServer {
    /// Update the RRDP files and rsync content on disk.
    pub fn write_repository(&self) -> KrillResult<()> {
        let repository = self.repository()?;
        repository.write()
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use bytes::Bytes;

    use rpki::crypto::{PublicKeyFormat, Signer};

    use crate::commons::api::rrdp::CurrentObjects;
    use crate::commons::api::rrdp::PublicationDeltaError;
    use crate::commons::api::{ListElement, PublishDeltaBuilder};
    use crate::commons::remote::builder::IdCertBuilder;
    use crate::commons::remote::id::IdCert;
    use crate::commons::util::file::CurrentFile;
    use crate::pubd::Publisher;
    use crate::test;

    use super::*;

    fn server_base_uri() -> uri::Rsync {
        test::rsync("rsync://localhost/repo/")
    }

    fn server_base_http_uri() -> uri::Https {
        test::https("https://localhost/rrdp/")
    }

    fn publisher_alice(work_dir: &PathBuf) -> Publisher {
        let mut signer = OpenSslSigner::build(work_dir).unwrap();

        let key = signer.create_key(PublicKeyFormat::default()).unwrap();
        let id_cert = IdCertBuilder::new_ta_id_cert(&key, &signer).unwrap();

        let base_uri = uri::Rsync::from_str("rsync://localhost/repo/alice/").unwrap();

        Publisher::new(id_cert, base_uri, CurrentObjects::default())
    }

    fn make_publisher_req(handle: &str, id_cert: &IdCert) -> rfc8183::PublisherRequest {
        let handle = Handle::from_str(handle).unwrap();
        rfc8183::PublisherRequest::new(None, handle, id_cert.clone())
    }

    fn make_server(work_dir: &PathBuf) -> PubServer {
        let signer = OpenSslSigner::build(work_dir).unwrap();
        let signer = Arc::new(RwLock::new(signer));

        PubServer::build(
            &server_base_uri(),
            server_base_http_uri(),
            work_dir,
            None,
            signer,
        )
        .unwrap()
    }

    #[test]
    fn should_add_publisher() {
        test::test_under_tmp(|d| {
            let server = make_server(&d);

            let alice = publisher_alice(&d);

            let alice_handle = Handle::from_str("alice").unwrap();
            let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

            server.create_publisher(publisher_req).unwrap();

            let alice_found = server.get_publisher_details(&alice_handle).unwrap();

            assert_eq!(alice_found.base_uri(), alice.base_uri());
            assert_eq!(alice_found.id_cert(), alice.id_cert());
            assert!(alice_found.current_files().is_empty());
        })
    }

    #[test]
    fn should_not_add_publisher_twice() {
        test::test_under_tmp(|d| {
            let server = make_server(&d);

            let alice = publisher_alice(&d);

            let alice_handle = Handle::from_str("alice").unwrap();
            let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

            server.create_publisher(publisher_req.clone()).unwrap();

            match server.create_publisher(publisher_req) {
                Err(Error::PublisherDuplicate(name)) => assert_eq!(name, alice_handle),
                _ => panic!("Expected error"),
            }
        })
    }

    #[test]
    fn should_list_files() {
        test::test_under_tmp(|d| {
            let server = make_server(&d);
            let alice = publisher_alice(&d);

            let alice_handle = Handle::from_str("alice").unwrap();
            let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

            server.create_publisher(publisher_req).unwrap();

            let list_reply = server.list(&alice_handle).unwrap();
            assert_eq!(0, list_reply.elements().len());
        });
    }

    #[test]
    fn should_publish_files() {
        test::test_under_tmp(|d| {
            // set up server with default repository, and publisher alice
            let server = make_server(&d);
            let alice = publisher_alice(&d);

            let alice_handle = Handle::from_str("alice").unwrap();
            let publisher_req = make_publisher_req(alice_handle.as_str(), alice.id_cert());

            server.create_publisher(publisher_req).unwrap();

            // get the file out of a list_reply
            fn find_in_reply<'a>(
                reply: &'a ListReply,
                uri: &uri::Rsync,
            ) -> Option<&'a ListElement> {
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
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file.txt")
            )
            .is_some());
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file2.txt")
            )
            .is_some());

            // Update
            // - update file
            // - withdraw file2
            // - add file 3

            let file1_update = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file.txt"),
                &Bytes::from("example content - updated"),
            );

            let file3 = CurrentFile::new(
                test::rsync("rsync://localhost/repo/alice/file3.txt"),
                &Bytes::from("example content 3"),
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
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file.txt")
            )
            .is_some());
            assert_eq!(
                find_in_reply(
                    &list_reply,
                    &test::rsync("rsync://localhost/repo/alice/file.txt")
                )
                .unwrap()
                .hash(),
                file1_update.hash()
            );
            assert!(find_in_reply(
                &list_reply,
                &test::rsync("rsync://localhost/repo/alice/file3.txt")
            )
            .is_some());

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

            match server.publish(alice_handle, delta) {
                Err(Error::Rfc8181Delta(PublicationDeltaError::ObjectAlreadyPresent(uri))) => {
                    assert_eq!(uri, test::rsync("rsync://localhost/repo/alice/file3.txt"))
                }
                _ => panic!("Expected error publishing file that already exists"),
            }
        });
    }
}
