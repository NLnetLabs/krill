use std::{
    convert::{TryFrom, TryInto},
    net::TcpStream,
    ops::Deref,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

use backoff::ExponentialBackoff;
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use kmip::{
    client::{Client, ClientCertificate},
    types::{
        common::{KeyMaterial, ObjectType, Operation},
        response::{ManagedObject, RNGRetrieveResponsePayload},
    },
};
use openssl::ssl::SslStream;
use r2d2::PooledConnection;
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, SigningError,
};

use crate::commons::{
    api::{Handle, Timestamp},
    crypto::{
        dispatch::signerinfo::SignerMapper,
        signers::{
            kmip::connpool::ConnectionManager,
            probe::{ProbeError, ProbeStatus, StatefulProbe},
            util,
        },
        SignerError,
    },
    error::KrillIoError,
};

//------------ Types and constants ------------------------------------------------------------------------------------

/// The time to wait between an initial and subsequent attempt at sending a request to the KMIP server.
const RETRY_REQ_AFTER: Duration = Duration::from_secs(2);

/// How much longer should we wait from one request attempt to the next compared to the previous wait?
const RETRY_REQ_AFTER_MULTIPLIER: f64 = 1.5;

/// The maximum amount of time to keep retrying a failed request.
const RETRY_REQ_UNTIL_MAX: Duration = Duration::from_secs(30);

/// The maximum number of concurrent connections to the KMIP server to pool.
const MAX_CONCURRENT_SERVER_CONNECTIONS: u32 = 5;

/// A KMIP client that uses a specific TLS and TCP stream implementation. Currently set to [SslStream] from the
/// [openssl] crate. This will be a different type if we switch to different TCP and/or TLS implementations or to an
/// async implementation, but the client interface will remain the same.
pub type KmipTlsClient = Client<SslStream<TcpStream>>;

fn default_kmip_port() -> u16 {
    // From: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820682
    //   "KMIP servers using the Basic Authentication Suite SHOULD use TCP port number 5696, as assigned by IANA, to
    //    receive and send KMIP messages. KMIP clients using the Basic Authentication Suite MAY use the same 5696 TCP
    //    port number."
    5696
}

#[derive(Clone, Debug, Deserialize)]
pub struct KmipSignerConfig {
    pub host: String,

    #[serde(default = "default_kmip_port")]
    pub port: u16,

    #[serde(default)]
    pub insecure: bool,

    #[serde(default)]
    pub deficient: bool,

    #[serde(default)]
    pub server_cert_path: Option<PathBuf>,

    #[serde(default)]
    pub server_ca_cert_path: Option<PathBuf>,

    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,

    #[serde(default)]
    pub client_cert_private_key_path: Option<PathBuf>,

    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug)]
struct ConnectionSettings {
    client: kmip::client::ConnectionSettings,

    deficient: bool,
}

impl TryFrom<&KmipSignerConfig> for ConnectionSettings {
    type Error = SignerError;

    fn try_from(conf: &KmipSignerConfig) -> Result<Self, Self::Error> {
        let host = conf.host.clone();
        let port = conf.port;
        let username = conf.username.clone();
        let password = conf.password.clone();
        let insecure = conf.insecure;

        let client_cert = match &conf.client_cert_path {
            Some(cert_path) => {
                let cert_bytes = read_binary_file(cert_path)?;
                let key_bytes = match &conf.client_cert_private_key_path {
                    Some(key_path) => Some(read_binary_file(key_path)?),
                    None => None,
                };
                Some(ClientCertificate::SeparatePem { cert_bytes, key_bytes })
            }
            None => None,
        };

        let server_cert = match &conf.server_cert_path {
            Some(cert_path) => Some(read_binary_file(cert_path)?),
            None => None,
        };

        let ca_cert = match &conf.server_ca_cert_path {
            Some(cert_path) => Some(read_binary_file(cert_path)?),
            None => None,
        };

        let client_conn_settings = kmip::client::ConnectionSettings {
            host,
            port,
            username,
            password,
            insecure,
            client_cert,
            server_cert,
            ca_cert,
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            max_response_bytes: Some(64 * 1024),
        };

        Ok(ConnectionSettings {
            client: client_conn_settings,
            deficient: conf.deficient,
        })
    }
}

fn read_binary_file(file_path: &PathBuf) -> Result<Vec<u8>, SignerError> {
    Ok(std::fs::read(file_path).map_err(|err| {
        SignerError::IoError(KrillIoError::new(format!("Failed to read file '{:?}'", file_path), err))
    })?)
}

//------------ The KMIP signer management interface -------------------------------------------------------------------

#[derive(Debug)]
pub struct KmipSigner {
    name: String,

    handle: RwLock<Option<Handle>>,

    mapper: Arc<SignerMapper>,

    /// A probe dependent interface to the KMIP server.
    server: Arc<StatefulProbe<ConnectionSettings, SignerError, UsableServerState>>,
}

impl KmipSigner {
    /// Creates a new instance of KmipSigner.
    pub fn build(name: &str, conf: &KmipSignerConfig, mapper: Arc<SignerMapper>) -> Result<Self, SignerError> {
        // Signer initialization should not block Krill startup. As such we delaying contacting the KMIP server until
        // first use. The downside of this approach is that we won't detect any issues until that point.

        let server = Arc::new(StatefulProbe::new(
            name.to_string(),
            Arc::new(conf.try_into()?),
            Duration::from_secs(30),
        ));

        let s = KmipSigner {
            name: name.to_string(),
            handle: RwLock::new(None),
            mapper: mapper.clone(),
            server,
        };

        Ok(s)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_handle(&self, handle: Handle) {
        let mut writable_handle = self.handle.write().unwrap();
        if writable_handle.is_some() {
            panic!("Cannot set signer handle as handle is already set");
        }
        *writable_handle = Some(handle);
    }

    pub fn get_info(&self) -> Option<String> {
        if let Ok(status) = self.server.status(Self::probe_server) {
            if let Ok(state) = status.state() {
                return Some(state.conn_info.clone());
            }
        }
        None
    }

    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        let (public_key, kmip_key_pair_ids) = self.build_key(PublicKeyFormat::Rsa)?;
        let internal_key_id = kmip_key_pair_ids.private_key_id.to_string();
        Ok((public_key, internal_key_id))
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        self.sign_with_key(signer_private_key_id, SignatureAlgorithm::default(), challenge.as_ref())
    }

    /// Returns true if the KMIP server supports generation of random numbers, false otherwise.
    pub fn supports_random(&self) -> bool {
        if let Ok(status) = self.server.status(Self::probe_server) {
            if let Ok(state) = status.state() {
                return state.supports_random_number_generation;
            }
        }
        false
    }
}

//------------ Probe based server access ------------------------------------------------------------------------------

/// The details needed to interact with a usable KMIP server.
#[derive(Clone, Debug)]
struct UsableServerState {
    /// A pool of TCP + TLS clients for connecting to the KMIP server
    pool: r2d2::Pool<ConnectionManager>,

    /// Does the KMIP server support the RNG Retrieve operation (for generating random values)?
    supports_random_number_generation: bool,

    conn_info: String,
}

impl UsableServerState {
    pub fn new(
        pool: r2d2::Pool<ConnectionManager>,
        supports_random_number_generation: bool,
        conn_info: String,
    ) -> UsableServerState {
        UsableServerState {
            pool,
            supports_random_number_generation,
            conn_info,
        }
    }

    pub fn get_connection(&self) -> Result<PooledConnection<ConnectionManager>, SignerError> {
        let conn = self.pool.get()?;
        Ok(conn)
    }
}

impl KmipSigner {
    /// Verify if the configured KMIP server is contactable and supports the required capabilities.
    fn probe_server(
        name: String,
        status: &ProbeStatus<ConnectionSettings, SignerError, UsableServerState>,
    ) -> Result<UsableServerState, ProbeError<SignerError>> {
        let conn_settings = status.config()?;
        debug!(
            "[{}] Probing server at {}:{}",
            name, conn_settings.client.host, conn_settings.client.port
        );

        // Attempt a one-off connection to check if we should abort due to a configuration error (e.g. unusable
        // certificate) that will never work, and to determine the capabilities of the server (which may affect our
        // behaviour).
        let conn = ConnectionManager::connect_one_off(&conn_settings.client).map_err(|err| {
            match err {
                // Fatal error
                kmip::client::Error::ConfigurationError(err) => {
                    error!("[{}] Failed to connect KMIP server: Configuration error: {}", name, err);
                    ProbeError::CompletedUnusable
                }

                // I/O error attempting to contact the server or a problem on an internal problem at the server, not
                // necessarily fatal or a reason to abort creating the pool.
                kmip::client::Error::ServerError(err) => {
                    let err_msg = format!("[{}] Failed to connect to server: Server error: {}", name, err);
                    error!("{}", err_msg);
                    ProbeError::CallbackFailed(SignerError::KmipError(err_msg))
                }

                // Impossible errors: we didn't yet try to send a request or receive a response
                kmip::client::Error::SerializeError(err)
                | kmip::client::Error::RequestWriteError(err)
                | kmip::client::Error::ResponseReadError(err)
                | kmip::client::Error::DeserializeError(err)
                | kmip::client::Error::InternalError(err)
                | kmip::client::Error::Unknown(err)
                | kmip::client::Error::ItemNotFound(err) => {
                    error!("[{}] Failed to connect KMIP server: Unexpected error: {}", name, err);
                    ProbeError::CompletedUnusable
                }

                other => {
                    error!("[{}] Failed to connect KMIP server: Unexpected error: {}", name, other);
                    ProbeError::CompletedUnusable
                }
            }
        })?;

        // We managed to establish a TCP+TLS connection to the KMIP server. Send it a Query request to discover how
        // it calls itself and which KMIP operations it supports.
        let server_properties = conn
            .query()
            .map_err(|err| ProbeError::CallbackFailed(SignerError::KmipError(err.to_string())))?;
        let supported_operations = server_properties.operations.unwrap_or_default();

        // Check whether or not the KMIP operations that we require are supported by the server
        let mut unsupported_operations = Vec::new();
        for required_op in &[
            Operation::CreateKeyPair,
            Operation::Activate,
            Operation::Sign,
            Operation::Revoke,
            Operation::Destroy,
            Operation::Get,
            Operation::ModifyAttribute,
        ] {
            if !supported_operations.contains(required_op) {
                unsupported_operations.push(required_op.to_string());
            }
        }

        // Warn about and (optionally) fail due to the lack of any unsupported operations.
        if !unsupported_operations.is_empty() {
            // Hard fail due to unsupported operations, unless our configuration tells us to try using this server
            // anyway. For example, PyKMIP 0.10.0 does not include the ModifyAttribute operation in the set of
            // supported operations even though it does support it. Without this flag we would not be able to use
            // PyKMIP with Krill!
            if conn_settings.deficient {
                warn!(
                    "[{}] Ignoring KMIP server lacking support for one or more required operations: {}",
                    name,
                    unsupported_operations.join(",")
                );
            } else {
                error!(
                    "[{}] KMIP server lacks support for one or more required operations: {}",
                    name,
                    unsupported_operations.join(",")
                );
                return Err(ProbeError::CompletedUnusable);
            }
        }

        // Switch from probing the server to using it.
        // -------------------------------------------

        let server_identification = server_properties.vendor_identification.unwrap_or("Unknown".into());

        // Success! We can use this server. Announce it and switch our status to KmipSignerStatus::Usable.
        info!(
            "[{}] Using KMIP server '{}' at {}:{}",
            name, server_identification, conn_settings.client.host, conn_settings.client.port
        );

        let supports_rng_retrieve = supported_operations.contains(&Operation::RNGRetrieve);
        let conn_info = format!(
            "KMIP Signer [vendor: {}, host: {}, port: {}]",
            server_identification, conn_settings.client.host, conn_settings.client.port
        );
        let pool = ConnectionManager::create_connection_pool(
            Arc::new(conn_settings.client.clone()),
            MAX_CONCURRENT_SERVER_CONNECTIONS,
        )?;
        let state = UsableServerState::new(pool, supports_rng_retrieve, conn_info);

        Ok(state)
    }
}

//------------ Connection related functions ---------------------------------------------------------------------------

impl KmipSigner {
    /// Get a connection to the KMIP server from the pool, if the server is usable.
    fn connect(&self) -> Result<PooledConnection<ConnectionManager>, SignerError> {
        let conn = self.server.status(Self::probe_server)?.state()?.get_connection()?;
        Ok(conn)
    }

    /// Perform some operation using a KMIP server pool connection.
    ///
    /// Fails if the KMIP server is not [KmipSignerStatus::Usable]. If the operation fails due to a transient
    /// connection error, retry with backoff upto a defined retry limit.
    fn with_conn<T, F>(&self, desc: &str, do_something_with_conn: F) -> Result<T, SignerError>
    where
        F: FnOnce(&KmipTlsClient) -> Result<T, kmip::client::Error> + Copy,
    {
        // Define the backoff policy to use
        let backoff_policy = ExponentialBackoff {
            initial_interval: RETRY_REQ_AFTER,
            multiplier: RETRY_REQ_AFTER_MULTIPLIER,
            max_elapsed_time: Some(RETRY_REQ_UNTIL_MAX),
            ..Default::default()
        };

        // Define a notify callback to customize messages written to the logger
        let notify = |err, next: Duration| {
            warn!("{} failed, retrying in {} seconds: {}", desc, next.as_secs(), err);
        };

        // Define an operation to (re)try
        let op = || {
            // First get a (possibly already existing) connection from the pool
            let conn = self.connect()?;

            // Next, try to execute the callers operation using the connection. If it fails, examine the cause of
            // failure to determine if it should be a hard-fail (no more retries) or if we should try again.
            Ok((do_something_with_conn)(conn.deref()).map_err(retry_on_connection_error)?)
        };

        // Don't even bother going round the retry loop if we haven't yet successfully connected to the KMIP server
        // and verified its capabilities:
        let _ = self.server.status(Self::probe_server)?;

        // Try (and retry if needed) the requested operation.
        Ok(backoff::retry_notify(backoff_policy, op, notify)?)
    }
}

/// The status of a key.
///
/// KMIP servers require that a key be activated before it can be used for signing and be inactive (revoked) before it
/// can be deleted.
#[derive(Debug, PartialEq)]
pub(super) enum KeyStatus {
    /// The key is inactive.
    Inactive,

    /// The key was activated.
    Active,
}

pub(super) struct KmipKeyPairIds {
    pub public_key_id: String,
    pub private_key_id: String,
}

//------------ High level helper functions for use by the public Signer interface implementation ----------------------

impl KmipSigner {
    /// Remember that the given KMIP public and private key pair IDs correspond to the given KeyIdentifier.
    pub(super) fn remember_kmip_key_ids(
        &self,
        key_id: &KeyIdentifier,
        kmip_key_ids: KmipKeyPairIds,
    ) -> Result<(), SignerError> {
        // TODO: Don't assume colons cannot appear in HSM key ids.
        let internal_key_id = format!("{}:{}", kmip_key_ids.public_key_id, kmip_key_ids.private_key_id);

        let readable_handle = self.handle.read().unwrap();
        let signer_handle = readable_handle.as_ref().ok_or(SignerError::Other(
            "KMIP: Failed to record signer key: Signer handle not set".to_string(),
        ))?;
        self.mapper
            .add_key(signer_handle, key_id, &internal_key_id)
            .map_err(|err| SignerError::KmipError(format!("Failed to record signer key: {}", err)))?;

        Ok(())
    }

    /// Given a KeyIdentifier lookup the corresponding KMIP public and private key pair IDs.
    pub(super) fn lookup_kmip_key_ids(&self, key_id: &KeyIdentifier) -> Result<KmipKeyPairIds, KeyError<SignerError>> {
        // split_once isn't available until Rust 1.52
        pub fn split_once<'a>(s: &'a str, delimiter: char) -> Option<(&'a str, &'a str)> {
            let (start, end) = s.split_at(s.find(delimiter)?);
            Some((&start[..=(start.len() - 1)], &end[1..]))
        }

        let readable_handle = self.handle.read().unwrap();
        let signer_handle = readable_handle.as_ref().ok_or(KeyError::KeyNotFound)?;

        let internal_key_id = self
            .mapper
            .get_key(signer_handle, key_id)
            .map_err(|_| KeyError::KeyNotFound)?;

        let (public_key_id, private_key_id) = split_once(&internal_key_id, ':').unwrap();

        Ok(KmipKeyPairIds {
            public_key_id: public_key_id.to_string(),
            private_key_id: private_key_id.to_string(),
        })
    }

    /// Create a key pair in the KMIP server in the requested format and make it ready for use by Krill.
    pub(super) fn build_key(&self, algorithm: PublicKeyFormat) -> Result<(PublicKey, KmipKeyPairIds), SignerError> {
        // https://tools.ietf.org/html/rfc6485#section-3: Asymmetric Key Pair Formats
        //   "The RSA key pairs used to compute the signatures MUST have a 2048-bit
        //    modulus and a public exponent (e) of 65,537."

        if !matches!(algorithm, PublicKeyFormat::Rsa) {
            return Err(SignerError::KmipError(format!(
                "Algorithm {:?} not supported while creating key",
                &algorithm
            )));
        }

        // Give keys a Krill specific but random name initially. Once we have created them we can determine the SHA-1
        // of their X.509 SubjectPublicKeyInfo aka the Krill KeyIdentifier and use that in the name instead of the
        // random component.

        // The name given to a key is purely for our own use, the KMIP server doesn't care about it. We give keys a
        // name that clearly indicates they relate to Krill as this may be helpful to the KMIP server operator. Once
        // the key is created we rename it to include its Krill KeyIdentifier (aka the SHA-1 of the X.509
        // SubjectPublicKeyInfo) so that we can relate the key back to its usage in Krill. We include the Unix seconds
        // since 1970-01-01 timestamp in the name initially just as some rough at-a-glance indication of when it was
        // created and to differentiate it from other keys with the same name (of which there should be none as they
        // key should either be renamed after creation or should have been deleted at some point).
        let prefix = format!("krill_new_key_{}", Timestamp::now());
        let private_key_name = format!("{}_priv", prefix);
        let public_key_name = format!("{}_pub", prefix);

        // Create the RSA key pair
        let kmip_key_pair_ids = self.create_rsa_key_pair(private_key_name, public_key_name)?;

        // Prepare the new keys for use, and attempt to destroy them if anything goes wrong
        let public_key = self
            .prepare_keypair_for_use(&kmip_key_pair_ids.private_key_id, &kmip_key_pair_ids.public_key_id)
            .or_else(|err| {
                let _ = self.destroy_key_pair(&kmip_key_pair_ids, KeyStatus::Inactive);
                Err(SignerError::KmipError(err.to_string()))
            })?;

        Ok((public_key, kmip_key_pair_ids))
    }

    /// Create an RSA key pair in the KMIP server.
    fn create_rsa_key_pair(
        &self,
        private_key_name: String,
        public_key_name: String,
    ) -> Result<KmipKeyPairIds, SignerError> {
        let (private_key_id, public_key_id) = self.with_conn("create key pair", |conn| {
            conn.create_rsa_key_pair(2048, private_key_name.clone(), public_key_name.clone())
        })?;

        let kmip_key_ids = KmipKeyPairIds {
            public_key_id,
            private_key_id,
        };

        Ok(kmip_key_ids)
    }

    /// Make the given KMIP private and public key pair ready for use by Krill.
    fn prepare_keypair_for_use(&self, private_key_id: &str, public_key_id: &str) -> Result<PublicKey, SignerError> {
        // Create a public key object for the public key
        let public_key = self.get_public_key_from_id(&public_key_id)?;

        // Determine names for the public and private key that allow them to be related back to their usage in Krill
        // TODO: Give even more helpful names to the keys such as the name of the CA they were created for?
        let hex_key_id = hex::encode(public_key.key_identifier());
        let new_public_key_name = format!("krill-public-key-{}", hex_key_id);
        let new_private_key_name = format!("krill-private-key-{}", hex_key_id);

        // Rename the keys to their new names
        self.with_conn("rename key", |conn| {
            conn.rename_key(public_key_id, new_public_key_name.clone())
        })?;

        self.with_conn("rename key", |conn| {
            conn.rename_key(private_key_id, new_private_key_name.clone())
        })?;

        // Activate the private key so that it can be used for signing. Do this last otherwise if there is a problem
        // with preparing the key pair for use we have to deactivate the private key before we can destroy it.
        self.with_conn("activate key", |conn| conn.activate_key(&private_key_id))?;

        Ok(public_key)
    }

    /// Get the RSA public bytes for the given KMIP server public key.
    fn get_rsa_public_key_bytes(&self, public_key_id: &str) -> Result<Bytes, SignerError> {
        let response_payload = self.with_conn("get key", |conn| conn.get_key(public_key_id))?;

        if response_payload.object_type != ObjectType::PublicKey {
            return Err(SignerError::KmipError(format!(
                "Failed to get key material: unsupported object type '{:?}' returned by KMIP Get operation for public key with ID '{}'",
                response_payload.object_type, public_key_id)));
        }

        let key_material = match response_payload.cryptographic_object {
            ManagedObject::PublicKey(public_key) => public_key.key_block.key_value.key_material,
            _ => {
                return Err(SignerError::KmipError(format!(
                    "Failed to get key material: unsupported cryptographic object type returned by KMIP Get operation for public key with ID '{}'",
                    public_key_id)));
            }
        };

        let rsa_public_key_bytes = match key_material {
            KeyMaterial::Bytes(bytes) => bytes::Bytes::from(bytes),
            KeyMaterial::TransparentRSAPublicKey(pub_key) => {
                util::rsa_public_key_bytes_from_parts(&pub_key.modulus, &pub_key.public_exponent)?
            }
            KeyMaterial::TransparentRSAPrivateKey(priv_key) => {
                if let Some(public_exponent) = priv_key.public_exponent {
                    util::rsa_public_key_bytes_from_parts(&priv_key.modulus, &public_exponent)?
                } else {
                    return Err(SignerError::KmipError(format!(
                        "Failed to get key material: missing exponent in transparent RSA private key returned by KMIP Get operation for public key with ID '{}'",
                        public_key_id)));
                }
            }
            _ => {
                return Err(SignerError::KmipError(format!(
                    "Failed to get key material: unsupported key material type {:?} returned by KMIP Get operation for public key with ID '{}'",
                    key_material, public_key_id)));
            }
        };

        Ok(rsa_public_key_bytes)
    }

    pub(super) fn get_public_key_from_id(&self, public_key_id: &str) -> Result<PublicKey, SignerError> {
        let rsa_public_key_bytes = self.get_rsa_public_key_bytes(public_key_id)?;

        let subject_public_key = bcder::BitString::new(0, rsa_public_key_bytes);

        let subject_public_key_info =
            bcder::encode::sequence((PublicKeyFormat::Rsa.encode(), subject_public_key.encode()));

        let mut subject_public_key_info_source: Vec<u8> = Vec::new();
        subject_public_key_info
            .write_encoded(bcder::Mode::Der, &mut subject_public_key_info_source)
            .map_err(|err| {
                SignerError::KmipError(format!(
                    "Failed to create DER encoded SubjectPublicKeyInfo from constituent parts: {}",
                    err
                ))
            })?;

        let public_key = PublicKey::decode(subject_public_key_info_source.as_slice()).map_err(|err| {
            SignerError::KmipError(format!(
                "Failed to create public key from the DER encoded SubjectPublicKeyInfo: {}",
                err
            ))
        })?;

        Ok(public_key)
    }

    pub(super) fn sign_with_key(
        &self,
        private_key_id: &str,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Signature, SignerError> {
        if algorithm.public_key_format() != PublicKeyFormat::Rsa {
            return Err(SignerError::KmipError(format!(
                "Algorithm '{:?}' not supported",
                algorithm.public_key_format()
            )));
        }

        let signed = self.with_conn("sign", |conn| conn.sign(&private_key_id, data))?;

        let sig = Signature::new(SignatureAlgorithm::default(), Bytes::from(signed.signature_data));

        Ok(sig)
    }

    pub(super) fn destroy_key_pair(
        &self,
        kmip_key_pair_ids: &KmipKeyPairIds,
        mode: KeyStatus,
    ) -> Result<(), SignerError> {
        let mut res = self.with_conn("destroy key", |conn| conn.destroy_key(&kmip_key_pair_ids.public_key_id));

        if let Err(err) = &res {
            warn!(
                "[{}] Failed to destroy KMIP public key '{}': {}",
                self.name, &kmip_key_pair_ids.public_key_id, err
            );
        }

        let mut deactivated = true;
        if mode == KeyStatus::Active {
            // TODO: it's unclear from the KMIP 1.2 specification if this can fail because the key is already revoked.
            // If that is a possible failure scenario we should not abort here but instead continue to delete the key.
            let res2 = self.with_conn("revoke key", |conn| conn.revoke_key(&kmip_key_pair_ids.private_key_id));

            if let Err(err) = &res2 {
                deactivated = false;
                warn!(
                    "[{}] Failed to revoke KMIP private key '{}': {}",
                    self.name, &kmip_key_pair_ids.private_key_id, err
                );
            }

            res = res.and(res2);
        }

        if deactivated {
            // TODO: This can fail if the key is not in the correct state, e.g. one cause can be if the key is not
            // revoked. We don't expect this because we assume we know whether we activated or revoked the key or not
            // but if for some reason the key exists, we think it does not require revocation but actually it does,
            // then we would fail here. In such a case we could attempt to revoke and retry, but that assumes we can
            // detect that specific failure scenario.
            let res3 = self.with_conn("destroy key", |conn| {
                conn.destroy_key(&kmip_key_pair_ids.private_key_id)
            });

            if let Err(err) = &res3 {
                warn!(
                    "[{}] Failed to destroy KMIP private key '{}': {}",
                    self.name, &kmip_key_pair_ids.private_key_id, err
                );
            }

            res = res.and(res3);
        }

        res
    }

    pub(super) fn get_random_bytes(&self, num_bytes_wanted: usize) -> Result<Vec<u8>, SignerError> {
        if !self.supports_random() {
            return Err(SignerError::KmipError(
                "The KMIP server does not support random number generation".to_string(),
            ));
        }
        let res: RNGRetrieveResponsePayload = self.with_conn("rng retrieve", |conn: &KmipTlsClient| {
            conn.rng_retrieve(num_bytes_wanted as i32)
        })?;

        Ok(res.data)
    }
}

//------------ Functions required to exist by the `SignerProvider` ----------------------------------------------------

// Implement the functions defined by the `Signer` trait because `SignerProvider` expects to invoke them, but as the
// dispatching is not trait based we don't actually have to implement the `Signer` trait.

impl KmipSigner {
    pub fn create_key(&self, algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        let (key, kmip_key_pair_ids) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.remember_kmip_key_ids(&key_id, kmip_key_pair_ids)?;
        Ok(key_id)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<SignerError>> {
        let kmip_key_pair_ids = self.lookup_kmip_key_ids(key_id)?;
        self.get_public_key_from_id(&kmip_key_pair_ids.public_key_id)
            .map_err(|err| KeyError::Signer(err))
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        let kmip_key_pair_ids = self.lookup_kmip_key_ids(key_id)?;

        let mut res = self
            .destroy_key_pair(&kmip_key_pair_ids, KeyStatus::Active)
            .map_err(|err| match err {
                SignerError::KeyNotFound => KeyError::KeyNotFound,
                _ => KeyError::Signer(err),
            });

        if let Err(err) = &res {
            warn!(
                "[{}] Failed to completely destroy KMIP key pair with ID {} (KMIP public key ID: {}, KMIP private key ID: {}): {}",
                        self.name, key_id, kmip_key_pair_ids.public_key_id, kmip_key_pair_ids.private_key_id, err
            );
        }

        // remove the key from the signer mapper as well
        if let Some(signer_handle) = self.handle.read().unwrap().as_ref() {
            let res2 = self
                .mapper
                .remove_key(signer_handle, key_id)
                .map_err(|err| KeyError::Signer(SignerError::Other(err.to_string())));

            if let Err(err) = &res2 {
                warn!(
                    "[{}] Failed to remove mapping for key with ID {}: {}",
                    self.name, key_id, err
                );
            }

            res = res.and(res2);
        }

        res
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<SignerError>> {
        let kmip_key_pair_ids = self.lookup_kmip_key_ids(key_id)?;

        let signature = self
            .sign_with_key(&kmip_key_pair_ids.private_key_id, algorithm, data.as_ref())
            .map_err(|err| {
                SigningError::Signer(SignerError::KmipError(format!(
                    "Signing data failed for Krill KeyIdentifier '{}' and KMIP private key id '{}': {}",
                    key_id, kmip_key_pair_ids.private_key_id, err
                )))
            })?;

        Ok(signature)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        // TODO: Is it possible to use a KMIP batch request to implement the create, activate, sign, deactivate, delete
        // in one round-trip to the server?
        let (key, kmip_key_pair_ids) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature_res = self
            .sign_with_key(&kmip_key_pair_ids.private_key_id, algorithm, data.as_ref())
            .map_err(|err| SignerError::KmipError(format!("One-off signing of data failed: {}", err)));

        let _ = self.destroy_key_pair(&kmip_key_pair_ids, KeyStatus::Active);

        let signature = signature_res?;

        Ok((signature, key))
    }

    pub fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        let random_bytes = self.get_random_bytes(target.len())?;

        target.copy_from_slice(&random_bytes);

        Ok(())
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Retry with backoff related helper impls/fns:
// --------------------------------------------------------------------------------------------------------------------

impl From<kmip::client::Error> for SignerError {
    fn from(err: kmip::client::Error) -> Self {
        match err {
            kmip::client::Error::ItemNotFound(_) => SignerError::KeyNotFound,
            _ => SignerError::KmipError(format!("Client error: {}", err)),
        }
    }
}

impl From<backoff::Error<SignerError>> for SignerError {
    fn from(err: backoff::Error<SignerError>) -> Self {
        match err {
            backoff::Error::Permanent(err) => err,
            backoff::Error::Transient(err) => err,
        }
    }
}

fn retry_on_connection_error<E>(err: kmip::client::Error) -> backoff::Error<E>
where
    E: From<kmip::client::Error>,
{
    if err.is_connection_error() {
        backoff::Error::Transient(err.into())
    } else {
        backoff::Error::Permanent(err.into())
    }
}
