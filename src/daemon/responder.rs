use std::io;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use bcder::{Captured, Mode};
use bcder::encode::Values;
use rpki::signing::PublicKeyAlgorithm;
use rpki::signing::signer::{Signer, CreateKeyError, KeyUseError};
use rpki::uri;
use crate::daemon::publishers::Publisher;
use crate::remote::id::MyIdentity;
use crate::remote::oob::RepositoryResponse;
use crate::remote::publication::pubmsg::Message;
use crate::remote::builder::IdCertBuilder;
use crate::remote::builder::SignedMessageBuilder;
use crate::signing::softsigner;
use crate::signing::softsigner::OpenSslSigner;
use crate::storage::caching_ks::CachingDiskKeyStore;
use crate::storage::keystore;
use crate::storage::keystore::{Info, Key, KeyStore};
use crate::repo::rrdp;


/// # Naming things in the keystore.
const ACTOR: &'static str = "publication server";

fn my_id_key() -> Key {
    Key::from_str("my_id")
}

const MY_ID_MSG: &'static str = "initialised identity";


//------------ Responder -----------------------------------------------------

/// This type is responsible for managing the PubServer identity as well as
/// wrapping all response messages to publishers.
#[derive(Clone, Debug)]
pub struct Responder {
    // Used for signing responses to publishers
    signer: OpenSslSigner,

    // key value store for server specific stuff
    store: CachingDiskKeyStore,

    // The URI that publishers need to access to publish (see config)
    service_uri: uri::Http,

    // The URI for the notification.xml published by this server (see config)
    rrdp_notification_uri: uri::Http
}


/// # Set up
///
impl Responder {
    pub fn init(
        work_dir: &PathBuf,
        service_uri: &uri::Http,
        rrdp_base_uri: &uri::Http
    ) -> Result<Self, Error> {
        let mut responder_dir = PathBuf::from(work_dir);
        responder_dir.push("responder");
        if ! responder_dir.is_dir() {
            fs::create_dir_all(&responder_dir)?;
        }

        let signer = OpenSslSigner::new(&responder_dir)?;
        let store = CachingDiskKeyStore::new(responder_dir)?;

        let rrdp_notification_uri = rrdp::notification_uri(rrdp_base_uri);

        let mut responder = Responder {
            signer,
            store,
            service_uri: service_uri.clone(),
            rrdp_notification_uri
        };
        responder.init_identity_if_empty()?;

        Ok(responder)
    }

    /// Initialise the publication server identity, if no identity had
    /// been set up. Does nothing otherwise.
    pub fn init_identity_if_empty(&mut self) -> Result<(), Error> {
        match self.my_identity()? {
            Some(_id) => Ok(()),
            None => self.init_identity()
        }
    }

    /// Initialises the identity of this publication server.
    pub fn init_identity(&mut self) -> Result<(), Error> {
        let key_id = self.signer.create_key(&PublicKeyAlgorithm::RsaEncryption)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity::new(ACTOR, id_cert, key_id);

        let key = my_id_key();
        let inf = Info::now(ACTOR, MY_ID_MSG);
        self.store.store(key, my_id, inf)?;
        Ok(())
    }

    fn my_identity(&self) -> Result<Option<Arc<MyIdentity>>, Error> {
        self.store.get(&my_id_key()).map_err(|e| { Error::KeyStoreError(e)})
    }
}

/// # Provisioning
impl Responder {
    pub fn repository_response(
        &self,
        publisher: Arc<Publisher>
    ) -> Result<RepositoryResponse, Error> {

        if let Some(my_id) = self.my_identity()? {
            let tag = publisher.tag();
            let publisher_handle = publisher.name().clone();
            let id_cert = my_id.id_cert().clone();
            let service_uri = publisher.service_uri().clone();
            let sia_base = publisher.base_uri().clone();
            let rrdp_notification_uri = self.rrdp_notification_uri.clone();

            Ok(
                RepositoryResponse::new(
                    tag,
                    publisher_handle,
                    id_cert,
                    service_uri,
                    sia_base,
                    rrdp_notification_uri
                )
            )
        } else {
            Err(Error::Unitialised)
        }
    }

    /// Creates an encoded SignedMessage for a contained Message.
    pub fn sign_msg(&mut self, msg: Message) -> Result<Captured, Error> {
        if let Some(id) = self.my_identity()? {
            let builder = SignedMessageBuilder::new(
                id.key_id(),
                &mut self.signer,
                msg
            )?;
            let enc = builder.encode().to_captured(Mode::Der);
            Ok(enc)
        } else {
            Err(Error::Unitialised)
        }
    }

}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display="{:?}", _0)]
    IoError(io::Error),

    #[fail(display="{:?}", _0)]
    SoftSignerError(softsigner::Error),

    #[fail(display="{:?}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(display="{:?}", _0)]
    CreateKeyError(CreateKeyError),

    #[fail(display="{:?}", _0)]
    KeyUseError(KeyUseError),

    #[fail(display="Identity of server is not initialised.")]
    Unitialised
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<softsigner::Error> for Error {
    fn from(e: softsigner::Error) -> Self {
        Error::SoftSignerError(e)
    }
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
    }
}

impl From<CreateKeyError> for Error {
    fn from(e: CreateKeyError) -> Self {
        Error::CreateKeyError(e)
    }
}

impl From<KeyUseError> for Error {
    fn from(e: KeyUseError) -> Self {
        Error::KeyUseError(e)
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test;


    #[test]
    fn should_have_response_for_publisher() {
        test::test_with_tmp_dir(|d| {

            let service_uri = test::http_uri("http://host/publish");
            let rrdp_uri = test::http_uri("http://host/rrdp/");
            let responder = Responder::init(
                &d,
                &service_uri,
                &rrdp_uri
            ).unwrap();

            let name = "alice".to_string();
            let pr = test::new_publisher_request(name.as_str());
            let tag = None;
            let id_cert = pr.id_cert().clone();
            let base_uri = test::rsync_uri("rsync://host/module/alice/");
            let service_uri = test::http_uri("http://127.0.0\
            .1:3000/rfc8181/alice");

            let publisher = Arc::new(Publisher::new(
                tag,
                name,
                base_uri,
                service_uri,
                id_cert
            ));

            responder.repository_response(publisher).unwrap();
        });
    }

}
