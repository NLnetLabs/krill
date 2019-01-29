use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use bcder::{Captured, Mode};
use bcder::decode;
use bcder::encode::Values;
use clap::{App, Arg, SubCommand};
use rpki::x509::ValidationError;
use rpki::crypto::{PublicKeyFormat, Signer};
use toml;
use crate::api::publication;
use crate::remote::builder;
use crate::remote::builder::{IdCertBuilder, SignedMessageBuilder};
use crate::remote::id::{MyIdentity, MyRepoInfo, ParentInfo};
use crate::remote::rfc8183;
use crate::remote::rfc8181;
use crate::remote::sigmsg::SignedMessage;
use crate::storage::caching_ks::CachingDiskKeyStore;
use crate::storage::keystore::{self, Info, Key, KeyStore};
use crate::util::httpclient;
use crate::util::softsigner::{self, OpenSslSigner};
use pubc;


/// # Some constants for naming resources in the keystore for clients.
const ACTOR: &'static str = "publication client";

fn id_key() -> Key {
    Key::from_str("my_id")
}

fn parent_key() -> Key {
    Key::from_str("my_parent")
}

fn repo_key() -> Key {
    Key::from_str("my_repo")
}

const ID_MSG: &'static str = "initialised identity";
const PARENT_MSG: &'static str ="updated parent info";
const REPO_MSG: &'static str = "update repo info";


//------------ PubClient -----------------------------------------------------

/// An RPKI publication protocol (command line) client, useful for testing,
/// in scenarios where a CA just writes its products to disk, and a separate
/// process is responsible for synchronising them to the repository.
#[derive(Clone, Debug)]
pub struct PubClient {
    // keys
    //   -> keys by id
    signer: OpenSslSigner,

    // key value store
    store: CachingDiskKeyStore,
    //   id_key     -> MyIdentity
    //   parent_key -> ParentInfo
    //   repo_key   -> MyRepoInfo

    //   -> my directory of interest
    //      (note: we do not keep this state in client, truth is on disk)
    // archive / log
    //   -> my exchanges with the server
}


impl PubClient {
    /// Creates a new publication client
    pub fn new(work_dir: &PathBuf) -> Result<Self, Error> {
        let store = CachingDiskKeyStore::new(work_dir.clone())?;
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
    pub fn init(&mut self, name: &str) -> Result<(), Error> {
        let key_id = self.signer.create_key(PublicKeyFormat)?;
        let id_cert = IdCertBuilder::new_ta_id_cert(&key_id, &mut self.signer)?;
        let my_id = MyIdentity::new(name, id_cert, key_id);

        let key = id_key();
        let inf = Info::now(ACTOR, ID_MSG);
        self.store.store(key, my_id, inf)?;

        Ok(())
    }

    fn my_identity(&self) -> Result<Option<Arc<MyIdentity>>, Error> {
        self.store.get(&id_key()).map_err(|e| { Error::KeyStoreError(e)})
    }

    fn get_my_id(&self) -> Result<Arc<MyIdentity>, Error> {
        match self.my_identity()? {
            None => Err(Error::Uninitialised),
            Some(id) => Ok(id)
        }
    }

    fn my_parent(&self) -> Result<Option<Arc<ParentInfo>>, Error> {
        self.store.get(&parent_key()).map_err(|e| {Error::KeyStoreError(e) })
    }

    fn get_my_parent(&self) -> Result<Arc<ParentInfo>, Error> {
        match self.my_parent()? {
            None => Err(Error::Uninitialised),
            Some(p) => Ok(p)
        }
    }

    fn my_repo(&self) -> Result<Option<Arc<MyRepoInfo>>, Error> {
        self.store.get(&repo_key()).map_err(|e| {Error::KeyStoreError(e)})
    }

    fn get_my_repo(&self) -> Result<Arc<MyRepoInfo>, Error> {
        match self.my_repo()? {
            None => Err(Error::Uninitialised),
            Some(r) => Ok(r)
        }
    }

    /// Process the publication server parent response.
    pub fn process_repo_response(
        &mut self,
        response: rfc8183::RepositoryResponse
    ) -> Result<(), Error> {

        // Store parent info
        {
            let parent_val = ParentInfo::new(
                response.publisher_handle().clone(),
                response.id_cert().clone(),
                response.service_uri().clone()
            );
            let parent_info = Info::now(ACTOR, PARENT_MSG);
            let parent_key = parent_key();

            self.store.store(parent_key, parent_val, parent_info)?;
        }

        // Store repo info
        {
            let repo_val = MyRepoInfo::new(
                response.sia_base().clone(),
                response.rrdp_notification_uri().clone()
            );
            let repo_info = Info::now(ACTOR, REPO_MSG);
            let repo_key = repo_key();

            self.store.store(repo_key, repo_val, repo_info)?;
        }

        Ok(())
    }

    /// Makes a publisher request, which can presented as an RFC8183 xml.
    pub fn publisher_request(
        &mut self
    ) -> Result<rfc8183::PublisherRequest, Error> {
        let id = self.get_my_id()?;
        Ok(
            rfc8183::PublisherRequest::new(
                None,
                id.name(),
                id.id_cert().clone()
            )
        )
    }

    /// Sends a list query to the server, and expects a list reply, all
    /// validly signed and all.
    pub fn get_server_list(
        &mut self
    ) -> Result<publication::ListReply, Error> {
        let query = rfc8181::Message::list_query();
        let signed_request = self.sign_request(query)?;

        let reply = self.send_request(signed_request)?.as_reply()?;

        match reply {
            rfc8181::ReplyMessage::ErrorReply(e) => Err(Error::ErrorReply(e)),
            rfc8181::ReplyMessage::SuccessReply  => Err(Error::UnexpectedReply),
            rfc8181::ReplyMessage::ListReply(l)  => Ok(l)
        }
    }


    /// Synchronises a directory to the configured publication server.
    /// Returns an error if there are any hick-ups.
    pub fn sync_dir(&mut self, base_path: &PathBuf) -> Result<(), Error> {
        let repo = self.get_my_repo()?;
        let list_reply = self.get_server_list()?;

        let delta = pubc::create_delta(list_reply, base_path, repo.sia_base())?;

        if ! delta.is_empty() {
            let msg = rfc8181::Message::publish_delta_query(delta);
            let sgn_msg = self.sign_request(msg)?;
            let reply = self.send_request(sgn_msg)?.as_reply()?;

            match reply {
                rfc8181::ReplyMessage::ErrorReply(e) => Err(Error::ErrorReply(e)),
                rfc8181::ReplyMessage::ListReply(_)  => Err(Error::UnexpectedReply),
                rfc8181::ReplyMessage::SuccessReply  => Ok(())
            }
        } else {
            Ok(())
        }
    }


    /// Sends a signed request to the server, and validates and parses the
    /// response.
    fn send_request(
        &mut self,
        req: Captured
    ) -> Result<rfc8181::Message, Error> {
        let parent = self.get_my_parent()?;
        let post_bytes = req.into_bytes();

        let res_bytes = httpclient::post_binary(
            &parent.service_uri().to_string(),
            &post_bytes,
            "application/rpki-publication"
        )?;

        let signed_msg = SignedMessage::decode(res_bytes, true)?;
        signed_msg.validate(parent.id_cert())?;
        rfc8181::Message::from_signed_message(&signed_msg).map_err(|e| {
            Error::MessageError(e)
        })
    }

    /// Sign a request so it can be sent to the publisher.
    fn sign_request(
        &mut self,
        msg: rfc8181::Message
    ) -> Result<Captured, Error> {
        let id = self.get_my_id()?;

        let builder = SignedMessageBuilder::new(
            id.key_id(),
            &mut self.signer,
            msg
        )?;

        let enc = builder.encode().to_captured(Mode::Der);
        Ok(enc)
    }


}

// Primarily used for testing things
impl PartialEq for PubClient {
    fn eq(&self, other: &PubClient) -> bool {
        if let Ok(Some(my_id)) = self.my_identity() {
            if let Ok(Some(other_id)) = other.my_identity() {
                my_id == other_id
            } else {
                false
            }
        } else {
            false
        }
    }
}

impl Eq for PubClient { }


//------------ Config --------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    state_dir: PathBuf,
    mode: RunMode
}

/// # Accessors
impl Config {
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    pub fn mode(&self) -> &RunMode {
        &self.mode
    }
}

/// # Create
impl Config {
    /// Creates the config (at startup). Panics in case of issues.
    pub fn create() -> Result<Self, ConfigError> {
        let m = App::new("NLnet Labs RRDP Client (RFC8181)")
            .version("0.1b")

            .arg(Arg::with_name("state")
                .short("s")
                .long("state")
                .value_name("FILE")
                .help("Specify the directory where this publication client \
                       maintains its state.")
                .required(true))

            .subcommand(SubCommand::with_name("init")
                .about("(Re-)Initialise the identity certificate and key \
                        pair.")
                .arg(Arg::with_name("name")
                    .short("n")
                    .long("name")
                    .value_name("NAME")
                    .help("Specify the name for this publication client.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("request")
                .about("Generate the publisher request XML")
                .arg(Arg::with_name("xml")
                    .short("x")
                    .long("xml")
                    .value_name("FILE")
                    .help("The name of the file to write the request to.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("response")
                .about("Process the repository response XML")
                .arg(Arg::with_name("xml")
                    .short("x")
                    .long("xml")
                    .value_name("FILE")
                    .help("The name of the file containing the response.")
                    .required(true))
            )

            .subcommand(SubCommand::with_name("sync")
                .about("Synchronise the directory specified by '-d'.")
                .arg(Arg::with_name("dir")
                    .short("d")
                    .long("dir")
                    .value_name("FILE")
                    .help("The directory that should be synced to the
                           server. Note that entries here will be relative to
                           the base rsync directory specified in the
                           repository response.")
                    .required(true))
            )

            .get_matches();

        let mut mode = RunMode::Unset;

        if let Some(m) = m.subcommand_matches("init") {
            if let Some(name) = m.value_of("name") {
                mode = RunMode::Init(name.to_string())
            }
        }

        if let Some(m) = m.subcommand_matches("request") {
            if let Some(xml) = m.value_of("xml") {
                let xml = PathBuf::from(xml);
                mode = RunMode::PublisherRequest(xml)
            }
        }
        if let Some(m) = m.subcommand_matches("response") {
            if let Some(xml) = m.value_of("xml") {
                let xml = PathBuf::from(xml);
                mode = RunMode::RepoResponse(xml)
            }
        }
        if let Some(m) = m.subcommand_matches("sync") {
            if let Some(dir) = m.value_of("dir") {
                let dir = PathBuf::from(dir);
                mode = RunMode::Sync(dir)
            }
        }

        let state = m.value_of("state").unwrap(); // safe (required)
        let state_dir = PathBuf::from(state);
        Ok(Config { state_dir, mode})
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum RunMode {
    Unset,
    Init(String),
    PublisherRequest(PathBuf),
    RepoResponse(PathBuf),
    Sync(PathBuf)
}

#[derive(Debug, Display)]
pub enum ConfigError {

    #[display(fmt="{}", _0)]
    IoError(io::Error),

    #[display(fmt="{}", _0)]
    TomlError(toml::de::Error),
}

impl From<io::Error> for ConfigError {
    fn from(e: io::Error) -> Self {
        ConfigError::IoError(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::TomlError(e)
    }
}



//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {

    #[display(fmt="This client is uninitialised.")]
    Uninitialised,

    #[display(fmt="{}", _0)]
    SignerError(softsigner::SignerError),

    #[display(fmt="{}", _0)]
    KeyStoreError(keystore::Error),

    #[display(fmt="{}", _0)]
    ValidationError(ValidationError),

    #[display(fmt="Cannot parse message: {}", _0)]
    MessageError(rfc8181::MessageError),

    #[display(fmt="Cannot decode reply: {}", _0)]
    DecodeError(decode::Error),

    #[display(fmt="Received error from server: {:?}", _0)]
    ErrorReply(rfc8181::ErrorReply),

    #[display(fmt="Received unexpected reply (list vs success)")]
    UnexpectedReply,

    #[display(fmt="{}", _0)]
    BuilderError(builder::Error<softsigner::SignerError>),

    #[display(fmt="{}", _0)]
    HttpClientError(httpclient::Error),

    #[display(fmt="{}", _0)]
    PubcError(pubc::Error),
}

impl From<softsigner::SignerError> for Error {
    fn from(e: softsigner::SignerError) -> Self {
        Error::SignerError(e)
    }
}

impl From<keystore::Error> for Error {
    fn from(e: keystore::Error) -> Self {
        Error::KeyStoreError(e)
    }
}

impl From<ValidationError> for Error {
    fn from(e: ValidationError) -> Self {
        Error::ValidationError(e)
    }
}

impl From<decode::Error> for Error {
    fn from(e: decode::Error) -> Self {
        Error::DecodeError(e)
    }
}

impl From<rfc8181::MessageError> for Error {
    fn from(e: rfc8181::MessageError) -> Self {
        Error::MessageError(e)
    }
}

impl From<builder::Error<softsigner::SignerError>> for Error {
    fn from(e: builder::Error<softsigner::SignerError>) -> Self {
        Error::BuilderError(e)
    }
}

impl From<httpclient::Error> for Error {
    fn from(e: httpclient::Error) -> Self { Error::HttpClientError(e) }
}

impl From<pubc::Error> for Error {
    fn from(e: pubc::Error) -> Self { Error::PubcError(e) }
}

// Tested in integration tests in tests folder