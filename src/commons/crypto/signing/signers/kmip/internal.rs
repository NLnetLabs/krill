use std::{
    net::TcpStream,
    ops::Deref,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::{Duration, Instant},
};

use backoff::ExponentialBackoff;
use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use kmip::{
    client::{Client, ClientCertificate, ConnectionSettings},
    types::{
        common::{KeyMaterial, ObjectType, Operation},
        response::{ManagedObject, RNGRetrieveResponsePayload},
    },
};
use openssl::ssl::SslStream;
use r2d2::PooledConnection;
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer,
};

use crate::commons::{
    api::{Handle, Timestamp},
    crypto::{
        dispatch::signerinfo::SignerMapper,
        signers::{kmip::connpool::ConnectionManager, util},
        SignerError,
    },
};

//------------ Types and constants ------------------------------------------------------------------------------------

/// The time to wait between attempts to initially connect to the KMIP server to verify our connection settings and the
/// server capabilities.
const RETRY_INIT_EVERY: Duration = Duration::from_secs(30);

/// The time to wait between an initial and subsequent attempt at sending a request to the KMIP server.
const RETRY_REQ_AFTER: Duration = Duration::from_secs(2);

/// How much longer should we wait from one request attempt to the next compared to the previous wait?
const RETRY_REQ_AFTER_MULTIPLIER: f64 = 1.5;

/// The maximum amount of time to keep retrying a failed request.
const RETRY_REQ_UNTIL_MAX: Duration = Duration::from_secs(30);

/// The maximum number of concurrent connections to the KMIP server to pool.
const MAX_CONCURRENT_SERVER_CONNECTIONS: u32 = 5;

/// TODO: Make this a configuration setting. For now set it to false because PyKMIP 0.10.0 says it doesn't support the
/// `ModifyAttribute` but sending a modify attribute request succeeds.
const IGNORE_MISSING_CAPABILITIES: bool = false;

/// A KMIP client that uses a specific TLS and TCP stream implementation. Currently set to [SslStream] from the
/// [openssl] crate. This will be a different type if we switch to different TCP and/or TLS implementations or to an
/// async implementation, but the client interface will remain the same.
pub type KmipTlsClient = Client<SslStream<TcpStream>>;

//------------ The KMIP signer management interface -------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct KmipSigner {
    name: String,

    handle: Option<Handle>,

    mapper: Arc<SignerMapper>,

    /// A probe dependent interface to the KMIP server.
    server: Arc<RwLock<ProbingServerConnector>>,
}

impl KmipSigner {
    /// Creates a new instance of KmipSigner.
    pub fn build(name: &str, mapper: Arc<SignerMapper>) -> Result<Self, SignerError> {
        let conn_settings = Self::get_test_connection_settings();
        let server = Arc::new(RwLock::new(ProbingServerConnector::new(conn_settings)));

        let s = KmipSigner {
            name: name.to_string(),
            handle: None,
            mapper: mapper.clone(),
            server,
        };

        Ok(s)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_handle(&self) -> Option<Handle> {
        self.handle.clone()
    }

    pub fn set_handle(&mut self, handle: Handle) {
        if self.handle.is_some() {
            panic!("Cannot set signer handle as handle is already set");
        }
        self.handle = Some(handle);
    }

    pub fn get_info(&self) -> Option<String> {
        match self.server() {
            Ok(status) => Some(status.state().conn_info.clone()),
            Err(_) => None,
        }
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        internal_key_id: String,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        self.sign_with_key(&internal_key_id, SignatureAlgorithm::default(), challenge.as_ref())
    }

    pub fn create_registration_key(&mut self) -> Result<(PublicKey, String), SignerError> {
        let (public_key, kmip_key_pair_ids) = self.build_key(PublicKeyFormat::Rsa)?;
        let internal_key_id = kmip_key_pair_ids.private_key_id.to_string();
        Ok((public_key, internal_key_id))
    }

    /// Returns true if the KMIP server supports generation of random numbers, false otherwise.
    pub fn supports_random(&self) -> bool {
        match self.server() {
            Ok(status) => status.state().supports_rng_retrieve,
            Err(_) => false,
        }
    }

    // TODO: Remove me once we support passing configuration in to `fn build()`.
    fn get_test_connection_settings() -> ConnectionSettings {
        let client_cert = ClientCertificate::SeparatePem {
            cert_bytes: include_bytes!("../../../../../../test-resources/pykmip/server.crt").to_vec(),
            key_bytes: Some(include_bytes!("../../../../../../test-resources/pykmip/server.key").to_vec()),
        };
        let server_cert = include_bytes!("../../../../../../test-resources/pykmip/server.crt").to_vec();
        let ca_cert = include_bytes!("../../../../../../test-resources/pykmip/ca.crt").to_vec();

        ConnectionSettings {
            host: "127.0.0.1".to_string(),
            port: 5696,
            username: None,
            password: None,
            insecure: true,
            client_cert: Some(client_cert),
            server_cert: Some(server_cert),
            ca_cert: Some(ca_cert),
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            max_response_bytes: Some(64 * 1024),
        }
    }
}

//------------ Probe based server access ------------------------------------------------------------------------------

/// Probe status based access to the KMIP server.
///
/// To avoid blocking Krill startup due to HSM connection timeout or failure we start in a `Pending` status which
/// signifies that we haven't yet verified that we can connect to the HSM or that it supports the capabilities that we
/// require.
///
/// At some point later once an initial connection has been established the KMIP signer changes status to either
/// `Usable` or `Unusable` based on what was discovered about the KMIP server.
#[derive(Clone, Debug)]
enum ProbingServerConnector {
    /// We haven't yet been able to connect to the HSM using the TCP+TLS+KMIP protocol. If there was already a failed
    /// attempt to connect the timestamp of the attempt is remembered so that we can choose to space out connection
    /// attempts rather than attempt to connect every time Krill tries to use the signer.
    Probing {
        // The connection settings are not optional but are stored in an Option so that we can "take" them out when
        // moving from the Probing status for use in the Usable status.
        conn_settings: Option<ConnectionSettings>,
        last_probe_time: Option<Instant>,
    },

    /// The HSM was successfully probed but found to be lacking required capabilities and is thus unusable by Krill.
    Unusable,

    /// The HSM was successfully probed and confirmed to have the required capabilities.
    ///
    /// Note that this does not mean that the HSM is currently contactable, only that we were able to contact it at
    /// least once since Krill was started. If the domain name/IP address used to connect to Krill now point to a
    /// different HSM instance the previously determined conclusion that the HSM is usable may no longer be valid.
    ///
    /// In this status we keep state concerning our relationship with the HSM.
    Usable(UsableServerState),
}

impl ProbingServerConnector {
    /// Create a new connector to a KMIP server that hasn't been probed yet.
    pub fn new(conn_settings: ConnectionSettings) -> Self {
        ProbingServerConnector::Probing {
            conn_settings: Some(conn_settings),
            last_probe_time: None,
        }
    }

    /// Marks now as the last probe attempt timestamp.
    ///
    /// Calling this function while not in the Probing state will result in a panic.
    pub fn mark(&self) -> Result<(), SignerError> {
        match self {
            #[rustfmt::skip]
            ProbingServerConnector::Probing { mut last_probe_time, .. } => {
                last_probe_time.replace(Instant::now());
                Ok(())
            }
            _ => Err(SignerError::KmipError(
                "Internal error: cannot mark last probe time as probing has already finished.".into(),
            )),
        }
    }

    pub fn conn_settings(&self) -> &ConnectionSettings {
        match self {
            ProbingServerConnector::Probing { conn_settings, .. } => conn_settings.as_ref().unwrap(),
            _ => unreachable!(),
        }
    }

    pub fn take_conn_settings(&mut self) -> ConnectionSettings {
        match self {
            ProbingServerConnector::Probing { conn_settings, .. } => conn_settings.take().unwrap(),
            _ => unreachable!(),
        }
    }

    /// Helper function to retrieve the state associated with status Usable. Only called when in status `Usable`.
    /// Calling this function while in another state will result in a panic.
    pub fn state(&self) -> &UsableServerState {
        match self {
            ProbingServerConnector::Usable(state) => state,
            _ => unreachable!(),
        }
    }
}

/// The details needed to interact with a usable KMIP server.
#[derive(Clone, Debug)]
struct UsableServerState {
    /// A pool of TCP + TLS clients for connecting to the KMIP server
    pool: r2d2::Pool<ConnectionManager>,

    /// Does the KMIP server support the RNG Retrieve operation (for generating random values)?
    supports_rng_retrieve: bool,

    conn_info: String,
}

impl UsableServerState {
    pub fn new(
        pool: r2d2::Pool<ConnectionManager>,
        supports_rng_retrieve: bool,
        conn_info: String,
    ) -> UsableServerState {
        UsableServerState {
            pool,
            supports_rng_retrieve,
            conn_info,
        }
    }
}

impl KmipSigner {
    /// Get a read lock on the Usable server status, if the server is usable.
    ///
    /// Returns `Ok` with the status read lock if the KMIP server is usable, otherwise returns an `Err` because the
    /// server is unusable or we haven't yet been able to establish if it is usable or not.
    ///
    /// Will try probing again if we didn't already manage to connect to the server and the delay period between probes
    /// has elapsed.
    fn server(&self) -> Result<RwLockReadGuard<ProbingServerConnector>, SignerError> {
        fn get_server_if_usable(
            status: RwLockReadGuard<ProbingServerConnector>,
        ) -> Option<Result<RwLockReadGuard<ProbingServerConnector>, SignerError>> {
            // Check the status through the unlocked read lock
            match &*status {
                ProbingServerConnector::Usable(_) => {
                    // KMIP server has been confirmed as usable, return the read-lock granting access to the current
                    // status and via it the current state of our relationship with the KMIP server.
                    Some(Ok(status))
                }

                ProbingServerConnector::Unusable => {
                    // KMIP server has been confirmed as unusable, fail.
                    Some(Err(SignerError::KmipError("KMIP server is unusable".into())))
                }

                ProbingServerConnector::Probing { last_probe_time, .. } => {
                    // We haven't yet established whether the KMIP server is usable or not. If we haven't yet checked or we
                    // haven't tried checking again for a while, then try contacting it again. If we can't establish
                    // whether or not the server is usable, return an error.
                    if !is_time_to_check(RETRY_INIT_EVERY, *last_probe_time) {
                        Some(Err(SignerError::KmipError("KMIP server is not yet available".into())))
                    } else {
                        None
                    }
                }
            }
        }

        // Return the current status or attempt to set it by probing the server
        let status = self.server.read().expect("KMIP status lock is poisoned");
        get_server_if_usable(status).unwrap_or_else(|| {
            self.probe_server()
                .and_then(|_| Ok(self.server.read().expect("KMIP status lock is poisoned")))
                .map_err(|err| SignerError::KmipError(format!("KMIP server is not yet available: {}", err)))
        })
    }

    /// Verify if the configured KMIP server is contactable and supports the required capabilities.
    fn probe_server(&self) -> Result<(), SignerError> {
        // Hold a write lock for the duration of our attempt to verify the KMIP server so that no other attempt occurs
        // at the same time. Bail out if another thread is performing a probe and has the lock. This is the same result
        // as when attempting to use the KMIP server between probe retries.
        let mut status = self
            .server
            .try_write()
            .map_err(|_| SignerError::KmipError("KMIP server is not yet available".into()))?;

        // Update the timestamp of our last attempt to contact the KMIP server. This is used above to know when we have
        // waited long enough before attempting to contact the server again. This also guards against attempts to probe
        // when probing has already finished as mark() will fail in that case.
        status.mark()?;

        let conn_settings = status.conn_settings();
        debug!("Probing server at {}:{}", conn_settings.host, conn_settings.port);

        // Attempt a one-off connection to check if we should abort due to a configuration error (e.g. unusable
        // certificate) that will never work, and to determine the capabilities of the server (which may affect our
        // behaviour).
        let conn = ConnectionManager::connect_one_off(conn_settings).map_err(|err| {
            let reason = match err {
                // Fatal error
                kmip::client::Error::ConfigurationError(err) => {
                    format!("Failed to connect KMIP server: Configuration error: {}", err)
                }

                // Impossible errors: we didn't yet try to send a request or receive a response
                kmip::client::Error::SerializeError(err)
                | kmip::client::Error::RequestWriteError(err)
                | kmip::client::Error::ResponseReadError(err)
                | kmip::client::Error::DeserializeError(err)
                | kmip::client::Error::InternalError(err)
                | kmip::client::Error::Unknown(err) => {
                    format!("Failed to connect KMIP server: Unexpected error: {}", err)
                }

                // I/O error attempting to contact the server or a problem on an internal problem at the server, not
                // necessarily fatal or a reason to abort creating the pool.
                kmip::client::Error::ServerError(err) => {
                    format!("Failed to connect KMIP server: Server error: {}", err)
                }
            };

            SignerError::KmipError(reason)
        })?;

        // We managed to establish a TCP+TLS connection to the KMIP server. Send it a Query request to discover how
        // it calls itself and which KMIP operations it supports.
        let server_properties = conn.query().map_err(|err| SignerError::KmipError(err.to_string()))?;
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
            warn!(
                "KMIP server lacks support for one or more required operations: {}",
                unsupported_operations.join(",")
            );

            // Hard fail due to unsupported operations, unless our configuration tells us to try using this server
            // anyway. For example, PyKMIP 0.10.0 does not include the ModifyAttribute operation in the set of
            // supported operations even though it does support it. Without this flag we would not be able to use
            // PyKMIP with Krill!
            if IGNORE_MISSING_CAPABILITIES {
                *status = ProbingServerConnector::Unusable;
                return Err(SignerError::KmipError("KMIP server is unusable".to_string()));
            }
        }

        // Switch from probing the server to using it.
        // -------------------------------------------

        let server_identification = server_properties.vendor_identification.unwrap_or("Unknown".into());

        // Take the ConnectionSettings out of the Probing status so that we can move it to the Usable status. (we
        // could clone it but it potentially contains a lot of certificate and key byte data and is about to get
        // dropped when we change status which is silly when we still need it, instead take it with us to the new
        // status)
        let conn_settings = status.take_conn_settings();

        // Success! We can use this server. Announce it and switch our status to KmipSignerStatus::Usable.
        info!(
            "Using KMIP server '{}' at {}:{}",
            server_identification, conn_settings.host, conn_settings.port
        );

        let supports_rng_retrieve = supported_operations.contains(&Operation::RNGRetrieve);
        let conn_info = format!(
            "KMIP Signer [vendor: {}, host: {}, port: {}]",
            server_identification, conn_settings.host, conn_settings.port
        );
        let pool = ConnectionManager::create_connection_pool(conn_settings, MAX_CONCURRENT_SERVER_CONNECTIONS)?;
        let state = UsableServerState::new(pool, supports_rng_retrieve, conn_info);

        *status = ProbingServerConnector::Usable(state);
        Ok(())
    }
}

//------------ Connection related functions ---------------------------------------------------------------------------

impl KmipSigner {
    /// Get a connection to the KMIP server from the pool, if the server is usable.
    fn connect(&self) -> Result<PooledConnection<ConnectionManager>, SignerError> {
        let conn = self.server()?.state().pool.get()?;
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
        let _ = self.server()?;

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

// High level helper functions for use by the public Signer interface implementation
impl KmipSigner {
    /// Remember that the given KMIP public and private key pair IDs correspond to the given KeyIdentifier.
    pub(super) fn remember_kmip_key_ids(
        &self,
        key_id: &KeyIdentifier,
        kmip_key_ids: KmipKeyPairIds,
    ) -> Result<(), SignerError> {
        // TODO: Don't assume colons cannot appear in HSM key ids.
        let internal_key_id = format!("{}:{}", kmip_key_ids.public_key_id, kmip_key_ids.private_key_id);

        self.mapper
            .add_key(self.handle.as_ref().unwrap(), key_id, &internal_key_id)
            .map_err(|err| SignerError::KmipError(format!("Failed to record signer key: {}", err)))?;

        Ok(())
    }

    /// Given a KeyIdentifier lookup the corresponding KMIP public and private key pair IDs.
    pub(super) fn lookup_kmip_key_ids(
        &self,
        key_id: &KeyIdentifier,
    ) -> Result<KmipKeyPairIds, KeyError<<KmipSigner as Signer>::Error>> {
        let internal_key_id = self
            .mapper
            .get_key(self.handle.as_ref().unwrap(), key_id)
            .map_err(|_| KeyError::KeyNotFound)?;

        let (public_key_id, private_key_id) = internal_key_id.split_once(':').unwrap();

        Ok(KmipKeyPairIds {
            public_key_id: public_key_id.to_string(),
            private_key_id: private_key_id.to_string(),
        })
    }

    /// Create a key pair in the KMIP server in the requested format and make it ready for use by Krill.
    pub(super) fn build_key(&self, algorithm: PublicKeyFormat) -> Result<(PublicKey, KmipKeyPairIds), SignerError> {
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
        let (private_key_id, public_key_id) = self
            .with_conn("create key pair", |conn| {
                conn.create_rsa_key_pair(2048, private_key_name.clone(), public_key_name.clone())
            })
            .map_err(|err| SignerError::KmipError(format!("Failed to create RSA key pair: {}", err)))?;

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
        })
        .map_err(|err| {
            SignerError::KmipError(format!(
                "Failed to set name on new public key '{}': {}",
                public_key_id, err
            ))
        })?;

        self.with_conn("rename key", |conn| {
            conn.rename_key(private_key_id, new_private_key_name.clone())
        })
        .map_err(|err| {
            SignerError::KmipError(format!(
                "Failed to set name on new private key '{}': {}",
                private_key_id, err
            ))
        })?;

        // Activate the private key so that it can be used for signing. Do this last otherwise if there is a problem
        // with preparing the key pair for use we have to deactivate the private key before we can destroy it.
        self.with_conn("activate key", |conn| conn.activate_key(&private_key_id))
            .map_err(|err| {
                SignerError::KmipError(format!(
                    "Failed to activate new private key '{}': {}",
                    private_key_id, err
                ))
            })?;

        Ok(public_key)
    }

    /// Get the RSA public bytes for the given KMIP server public key.
    fn get_rsa_public_key_bytes(&self, public_key_id: &str) -> Result<Bytes, SignerError> {
        let response_payload = self
            .with_conn("get key", |conn| conn.get_key(public_key_id))
            .map_err(|err| {
                SignerError::KmipError(format!(
                    "Failed to get key material for public key with ID '{}': {:?}",
                    public_key_id, err
                ))
            })?;

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

        let signed = self
            .with_conn("sign", |conn| conn.sign(&private_key_id, data))
            .map_err(|err| SignerError::KmipError(format!("Signing failed: {}", err)))?;

        let sig = Signature::new(SignatureAlgorithm::default(), Bytes::from(signed.signature_data));

        Ok(sig)
    }

    pub(super) fn destroy_key_pair(
        &self,
        kmip_key_pair_ids: &KmipKeyPairIds,
        mode: KeyStatus,
    ) -> Result<bool, SignerError> {
        let mut success = true;

        if let Err(err) = self.with_conn("destroy key", |conn| conn.destroy_key(&kmip_key_pair_ids.public_key_id)) {
            success = false;
            warn!(
                "Failed to destroy KMIP public key '{}': {}",
                &kmip_key_pair_ids.public_key_id, err
            );
        }

        let mut deactivated = true;
        if mode == KeyStatus::Active {
            // TODO: it's unclear from the KMIP 1.2 specification if this can fail because the key is already revoked.
            // If that is a possible failure scenario we should not abort here but instead continue to delete the key.
            if let Err(err) = self.with_conn("revoke key", |conn| conn.revoke_key(&kmip_key_pair_ids.private_key_id)) {
                success = false;
                deactivated = false;
                warn!(
                    "Failed to revoke KMIP private key '{}': {}",
                    &kmip_key_pair_ids.private_key_id, err
                );
            }
        }

        if deactivated {
            // TODO: This can fail if the key is not in the correct state, e.g. one cause can is if the key is not
            // revoked. We don't expect this because we assume we know whether we activated or revoked the key or not
            // but if for some reason the key exists, we think it does not require revocation but actually it does,
            // then we would fail here. In such a case we could attempt to revoke and retry, but that assumes we can
            // detect that specific failure scenario.
            if let Err(err) = self.with_conn("destroy key", |conn| {
                conn.destroy_key(&kmip_key_pair_ids.private_key_id)
            }) {
                success = false;
                warn!(
                    "Failed to destroy KMIP private key '{}': {}",
                    &kmip_key_pair_ids.private_key_id, err
                );
            }
        }

        Ok(success)
    }

    pub(super) fn get_random_bytes(&self, num_bytes_wanted: usize) -> Result<Vec<u8>, <KmipSigner as Signer>::Error> {
        if !self.supports_random() {
            return Err(SignerError::KmipError(
                "The KMIP server does not support random number generation".to_string(),
            ));
        }
        let res: RNGRetrieveResponsePayload = self
            .with_conn("rng retrieve", |conn: &KmipTlsClient| {
                conn.rng_retrieve(num_bytes_wanted as i32)
            })
            .map_err(|err| SignerError::KmipError(format!("Failed to retrieve random bytes: {:?}", err)))?;

        Ok(res.data)
    }
}

fn is_time_to_check(time_between_checks: Duration, possible_lack_check_time: Option<Instant>) -> bool {
    match possible_lack_check_time {
        None => true,
        Some(instant) => Instant::now().saturating_duration_since(instant) > time_between_checks,
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Retry with backoff related helper impls/fns:
// --------------------------------------------------------------------------------------------------------------------

impl From<kmip::client::Error> for SignerError {
    fn from(err: kmip::client::Error) -> Self {
        SignerError::KmipError(format!("Client error: {}", err))
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
