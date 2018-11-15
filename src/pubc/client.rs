//! An RPKI publication protocol (command line) client, useful for testing,
//! in scenarios where a CA just writes its products to disk, and a separate
//! process is responsible for synchronising them to the repository.

//------------ PubClient -----------------------------------------------------

use std::path::PathBuf;
use ext_serde;
use rpki::oob::exchange::PublisherRequest;
use rpki::signing::PublicKeyAlgorithm;
use rpki::signing::builder::IdCertBuilder;
use rpki::signing::signer::CreateKeyError;
use rpki::signing::signer::KeyId;
use rpki::signing::signer::KeyUseError;
use rpki::signing::signer::Signer;
use rpki::remote::idcert::IdCert;
use signing::softsigner;
use signing::softsigner::OpenSslSigner;
use storage::caching_ks::CachingDiskKeyStore;
use storage::keystore::{self, Info, Key, KeyStore};
use std::sync::Arc;

fn actor() -> String {
    "publication client".to_string()
}

fn my_id_key() -> Key {
    Key::from_str("my_id")
}

fn my_id_msg() -> String {
    "initialised identity".to_string()
}

#[derive(Clone, Debug)]
pub struct PubClient {
    // keys
    //   -> keys by id
    signer: OpenSslSigner,

    // key value store
    store: CachingDiskKeyStore,

    //   -> my ID
    //      -> my key id
    //      -> my name/handle
    //      -> my certificate
    //   -> my parent
    //      -> service uri
    //      -> parent id certificate
    //      -> my base uri
    //   -> my directory of interest
    //      (note: we do not keep this state in client, truth is on disk)
    // archive / log
    //   -> my exchanges with the server
}


impl PubClient {
    /// Creates a new publication client
    pub fn new(work_dir: String) -> Result<Self, Error> {
        let store = CachingDiskKeyStore::new(PathBuf::from(&work_dir))?;
        let signer = OpenSslSigner::new(work_dir)?;
        Ok(
            PubClient {
                signer,
                store
            }
        )
    }


    /// Initialises a new publication client, using a new key pair, and
    /// returns a publisher request that can be sent to the server.
    pub fn init(&mut self, name: String) -> Result<(), Error> {
        let key_id = self.signer.create_key(&PublicKeyAlgorithm::RsaEncryption)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity {
            name,
            key_id,
            id_cert
        };

        let key = my_id_key();
        let inf = Info::now(actor(), my_id_msg());
        self.store.store(key, my_id, inf)?;

        Ok(())
    }

    fn my_identity(&self) -> Result<Option<Arc<MyIdentity>>, Error> {
        self.store.get(&my_id_key()).map_err(|e| { Error::KeyStoreError(e)})
    }

    /// Process the publication server parent response.
    pub fn process_parent_id(&mut self) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn publisher_request(&self) -> Result<PublisherRequest, Error> {
        match self.my_identity()? {
            None => Err(Error::Uninitialised),
            Some(arc) => {
                Ok(
                    PublisherRequest::new(
                        None,
                        arc.name.as_str(),
                        arc.id_cert.clone()
                    )
                )
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MyIdentity {
    name: String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert: IdCert,

    #[serde(
    deserialize_with = "ext_serde::de_key_id",
    serialize_with = "ext_serde::ser_key_id")]
    key_id: KeyId
}


//------------ Error ---------------------------------------------------------

#[derive(Debug, Fail)]
pub enum Error {

    #[fail(display="This client is uninitialised.")]
    Uninitialised,

    #[fail(display="{}", _0)]
    SignerError(softsigner::Error),

    #[fail(display="{}", _0)]
    KeyStoreError(keystore::Error),

    #[fail(display="{:?}", _0)]
    CreateKeyError(CreateKeyError),

    #[fail(display="{:?}", _0)]
    KeyUseError(KeyUseError),
}

impl From<softsigner::Error> for Error {
    fn from(e: softsigner::Error) -> Self {
        Error::SignerError(e)
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
    fn should_initialise() {
        test::test_with_tmp_dir(|d| {
            let mut client = PubClient::new(d).unwrap();
            client.init("client".to_string()).unwrap();
            let _pr = client.publisher_request().unwrap();
        });

    }

}