use std::{
    path::Path,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::{Duration, Instant},
};

use backoff::ExponentialBackoff;

use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use pkcs11::types::*;
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm,
};

use crate::commons::{
    api::Handle,
    crypto::{
        dispatch::signerinfo::SignerMapper,
        signers::{
            pkcs11::{context::Pkcs11Context, session::Pkcs11Session},
            util,
        },
        SignerError,
    },
};

//------------ Types and constants ------------------------------------------------------------------------------------

/// The time to wait between attempts to initially connect to the PKCS#11 server to verify our connection settings and the
/// server capabilities.
const RETRY_INIT_EVERY: Duration = Duration::from_secs(30);

/// The time to wait between an initial and subsequent attempt at sending a request to the PKCS#11 server.
const RETRY_REQ_AFTER: Duration = Duration::from_secs(2);

/// How much longer should we wait from one request attempt to the next compared to the previous wait?
const RETRY_REQ_AFTER_MULTIPLIER: f64 = 1.5;

/// The maximum amount of time to keep retrying a failed request.
const RETRY_REQ_UNTIL_MAX: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginMode {
    // The token can do cryptographic operations such as signing without requiring C_Login to be called first, and so a
    // user pin is also not required.
    LoginNotRequired,

    // The token requires that C_Login be called prior to performing any cryptographic operations such as signing. A
    // correct user pin may be needed for the login to succeed.
    LoginRequired,
}

// Placeholder struct
#[derive(Clone, Debug)]
struct ConnectionSettings {
    context: Arc<RwLock<Pkcs11Context>>,

    // For some PKCS#11 libraries it is easy, or only possible, to connect by slot ID (rather than slot label). If
    // `slot_id` is Some then `slot_label` is ignored. One of `slot_id` or `slot_label` must be Some.
    slot_id: Option<CK_SLOT_ID>,

    // Some PKCS#11 libraries support labeling slots for easy identification, others not only support it be make it
    // necessary to use labelled slots because the slot ID is not so obvious (e.g. with SoftHSMv2 slot 0 has a seemingly
    // random actual slot ID generated when the slot is initialized) or is dynamic (apparently the OpenDNSSec project
    // has encountered this). However, not all libraries support labeling of slots, e.g. the YubiHSM PKCS#11 library
    // uses simple integer slot IDs (slot 0, 1, etc). When `slot_label` is Some and `slot_id` is None then the list of
    // available slots will be queried via C_GetSlotList and the slot id of the first slot whose label matches the
    // given Some(slot_label) value will be used to connect to the HSM.
    slot_label: Option<String>,

    // The user pin is optional, it may be possible to login without it. Quoting the PKCS#11 v2.20 specificiation for
    // the C_Login operation:
    //
    //   "If the token has a “protected authentication path”, as indicated by the CKF_PROTECTED_AUTHENTICATION_PATH
    //    flag in its CK_TOKEN_INFO being set, then that means that there is some way for a user to be authenticated to
    //    the token without having the application send a PIN through the Cryptoki library. One such possibility is that
    //    the user enters a PIN on a PINpad on the token itself, or on the slot device. Or the user might not even use a
    //    PIN—authentication could be achieved by some fingerprint-reading device, for example. To log into a token with
    //    a protected authentication path, the pPin parameter to C_Login should be NULL_PTR."
    user_pin: Option<String>,

    login_mode: LoginMode,
}

#[derive(Debug)]
pub struct Pkcs11Signer {
    name: String,

    handle: RwLock<Option<Handle>>,

    mapper: Arc<SignerMapper>,

    /// A probe dependent interface to the PKCS#11 server.
    server: Arc<RwLock<ProbingServerConnector>>,
}

impl Pkcs11Signer {
    /// Creates a new instance of Pkcs11Signer.
    pub fn build(name: &str, mapper: Arc<SignerMapper>) -> Result<Self, SignerError> {
        // Signer initialization should not block Krill startup. As such we verify that we are able to load the PKCS#11
        // library don't we initialize the PKCS#11 interface yet because we don't know what it's code will do. If it
        // were to block while trying to connect to a remote server it would block Krill from starting up completely.
        // If the remote server is down and the library has logic to  delay and retry, or lacks appropriate timeouts of
        // connection attempts, we could get stuck for a while. Instead we defer initialization of the library until
        // first use. The downside of this approach is that we won't detect any issues until that point. Another reason
        // not to initialize the PKCS#11 library here is that if there are multiple instances of the Pkcs11Signer only
        // the first of them should call the PKCS#11 C_Initialize() function as the PKCS#11 v2.20 specification states
        // that "Note that exactly one call to C_Initialize should be made for each application (as opposed to one call
        // for every thread, for example)". At least, for the same PKCS#11 library that is. If two instances of
        // Pkcs11Signer each use a different PKCS#11 library, e.g. one uses the SoftHSMv2 library and the other uses the
        // AWS CloudHSM library, presumably they both need initlaizing within the same instance of the Krill
        // "application".

        // TODO: Use the supplied configuration settings instead of hard-coded test settings.
        let conn_settings = Self::get_test_connection_settings()?;

        let server = Arc::new(RwLock::new(ProbingServerConnector::new(conn_settings)));

        let s = Pkcs11Signer {
            name: name.to_string(),
            handle: RwLock::new(None),
            mapper: mapper.clone(),
            server,
        };

        Ok(s)
    }

    pub fn supports_random(&self) -> bool {
        // The PKCS#11 C_SeedRandom() and C_GenerateRandom() functions are allowed to return CKR_RANDOM_NO_RNG to
        // indicate "that the specified token doesn’t have a random number generator". The C_SeedRandom() function can
        // also return CKR_RANDOM_SEED_NOT_SUPPORTED. Thus it is not a given that the provider is able to generate
        // random numbers. In theory the provider can also fail to implement the random functions entirely but the
        // Rust PKCS11 crate `Ctx::new()` function requires these functions to be supported or else it will fail and
        // we would never get to this point.
        false // TODO
    }

    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        let (public_key, _, _, internal_key_id) = self.build_key(PublicKeyFormat::Rsa)?;
        Ok((public_key, internal_key_id))
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        let priv_handle = self.find_key(key_id, CKO_PRIVATE_KEY).map_err(|err| match err {
            KeyError::KeyNotFound => SignerError::KeyNotFound,
            KeyError::Signer(err) => err,
        })?;
        self.sign_with_key(priv_handle, SignatureAlgorithm::default(), challenge.as_ref())
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_handle(&self, handle: crate::commons::api::Handle) {
        let mut writable_handle = self.handle.write().unwrap();
        if writable_handle.is_some() {
            panic!("Cannot set signer handle as handle is already set");
        }
        *writable_handle = Some(handle);
    }

    pub fn get_info(&self) -> Option<String> {
        match self.server() {
            Ok(status) => Some(status.state().conn_info.clone()),
            Err(_) => None,
        }
    }

    fn get_test_connection_settings() -> Result<ConnectionSettings, SignerError> {
        let context = Pkcs11Context::get_or_load(Path::new("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"))?;
        let slot_id = Option::<CK_SLOT_ID>::None;
        let slot_label = Some("My token 1".to_string());
        let user_pin = Some("1234".to_string());
        let login_mode = LoginMode::LoginRequired;

        Ok(ConnectionSettings {
            context,
            slot_id,
            slot_label,
            user_pin,
            login_mode,
        })
    }
}

//------------ Probe based server access ------------------------------------------------------------------------------

/// Probe status based access to the PKCS#11 server.
///
/// To avoid blocking Krill startup due to HSM connection timeout or failure we start in a `Pending` status which
/// signifies that we haven't yet verified that we can connect to the HSM or that it supports the capabilities that we
/// require.
///
/// At some point later once an initial connection has been established the PKCS#11 signer changes status to either
/// `Usable` or `Unusable` based on what was discovered about the PKCS#11 server.
#[derive(Debug)]
enum ProbingServerConnector {
    /// We haven't yet been able to connect to the HSM. If there was already a failed attempt to connect the timestamp
    /// of the attempt is remembered so that we can choose to space out connection attempts rather than attempt to
    /// connect every time Krill tries to use the signer.
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
    /// Create a new connector to a server that hasn't been probed yet.
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
            _ => Err(SignerError::Pkcs11Error(
                "Internal error: cannot mark last probe time as probing has already finished.".into(),
            )),
        }
    }

    pub fn conn_settings(&self) -> &ConnectionSettings {
        match &self {
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

/// The details needed to interact with a usable PKCS#11 server.
#[derive(Debug)]
struct UsableServerState {
    context: Arc<RwLock<Pkcs11Context>>,

    /// Does the server support generation of random numbers?
    supports_random_number_generation: bool,

    conn_info: String,

    slot_id: CK_SLOT_ID,

    login_mode: LoginMode,

    /// When login_mode is NOT LoginMode::LoginRequired this will be None.
    /// 
    /// Section 11.6 "Session management functions" of the PKCS#11 v2.20 specification says:
    ///   "Call C_Login to log the user into the token. Since all sessions an application has with a token have a
    ///    shared login state, C_Login only needs to be called for one of the sessions."
    ///
    /// Therefore we hold a reference to the login session so that all future sessions are considered logged in.
    /// The Drop impl for Pkcs11Session will log the session out if logged in.
    login_session: Option<Pkcs11Session>,
}

impl UsableServerState {
    pub fn new(
        supports_random_number_generation: bool,
        context: Arc<RwLock<Pkcs11Context>>,
        conn_info: String,
        slot_id: CK_SLOT_ID,
        login_mode: LoginMode,
        login_session: Option<Pkcs11Session>,
    ) -> UsableServerState {
        UsableServerState {
            context,
            supports_random_number_generation,
            conn_info,
            slot_id,
            login_mode,
            login_session,
        }
    }

    pub fn get_connection(&self) -> Result<Pkcs11Session, pkcs11::errors::Error> {
        Pkcs11Session::new(self.context.clone(), self.slot_id)
    }
}

impl Pkcs11Signer {
    /// Get a read lock on the Usable server status, if the server is usable.
    ///
    /// Returns `Ok` with the status read lock if the server is usable, otherwise returns an `Err` because the
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
                    // The server has been confirmed as usable, return the read-lock granting access to the current
                    // status and via it the current state of our relationship with the server.
                    Some(Ok(status))
                }

                ProbingServerConnector::Unusable => {
                    // The server has been confirmed as unusable, fail.
                    Some(Err(SignerError::PermanentlyUnusable))
                }

                ProbingServerConnector::Probing { last_probe_time, .. } => {
                    // We haven't yet established whether the  server is usable or not. If we haven't yet checked or we
                    // haven't tried checking again for a while, then try contacting it again. If we can't establish
                    // whether or not the server is usable, return an error.
                    if !is_time_to_check(RETRY_INIT_EVERY, *last_probe_time) {
                        Some(Err(SignerError::TemporarilyUnavailable))
                    } else {
                        None
                    }
                }
            }
        }

        // Return the current status or attempt to set it by probing the server
        let status = self.server.read().unwrap();
        get_server_if_usable(status).unwrap_or_else(|| {
            self.probe_server()
                .and_then(|_| Ok(self.server.read().unwrap()))
                .map_err(|_| SignerError::TemporarilyUnavailable)
        })
    }

    /// Verify if the configured server is contactable and supports the required capabilities.
    fn probe_server(&self) -> Result<(), SignerError> {
        // Hold a write lock for the duration of our attempt to verify the server so that no other attempt occurs
        // at the same time. Bail out if another thread is performing a probe and has the lock. This is the same result
        // as when attempting to use the server between probe retries.
        let signer_name = &self.name;

        let mut status = self
            .server
            .try_write()
            .map_err(|_| SignerError::TemporarilyUnavailable)?;

        // Update the timestamp of our last attempt to contact the server. This is used above to know when we have
        // waited long enough before attempting to contact the server again. This also guards against attempts to probe
        // when probing has already finished as mark() will fail in that case.
        status.mark()?;

        let (res, lib_name) = {
            let conn_settings = status.conn_settings();
            let mut writable_ctx = conn_settings.context.write().unwrap();
            let lib_name = writable_ctx.get_lib_file_name();

            debug!("[{}] Probing server using library '{}'", signer_name, lib_name);
            let res = writable_ctx.initialize_if_not_already();

            (res, lib_name)
        };

        if let Err(err) = res {
            if matches!(err, SignerError::PermanentlyUnusable) {
                error!(
                    "[{}] Unable to initialize PKCS#11 info for library '{}': {}",
                    signer_name, lib_name, err
                );
                *status = ProbingServerConnector::Unusable;
            }
            return Err(err);
        }

        // Note: We don't need to check for supported functions because the `pkcs11` Rust crate `fn new()` already
        // requires that all of the functions that we need are supported. In fact it checks for so many functions I
        // wonder if it might not fail on some customer deployments, but perhaps it checks only for functions required
        // by the PKCS#11 specification...?

        let (cryptoki_info, slot_id, _slot_info, token_info, user_pin) = {
            let conn_settings = status.conn_settings();
            let readable_ctx = conn_settings.context.read().unwrap();

            let cryptoki_info = readable_ctx.get_info().map_err(|err| {
                error!(
                    "[{}] Unable to read PKCS#11 info for library '{}': {}",
                    signer_name, lib_name, err
                );
                SignerError::PermanentlyUnusable
            })?;

            trace!("[{}] C_GetInfo(): {:?}", signer_name, cryptoki_info);

            let slot_id = if let Some(slot_id) = conn_settings.slot_id {
                slot_id
            } else if let Some(slot_label) = &conn_settings.slot_label {
                fn has_token_label(
                    signer_name: &str,
                    ctx: &RwLockReadGuard<Pkcs11Context>,
                    slot_id: CK_SLOT_ID,
                    slot_label: &str,
                ) -> bool {
                    match ctx.get_token_info(slot_id) {
                        Ok(info) => info.label.to_string() == slot_label,
                        Err(err) => {
                            warn!(
                                "[{}] Failed to obtain token info for PKCS#11 slot id '{}': {}",
                                signer_name, slot_id, err
                            );
                            false
                        }
                    }
                }

                let slot_id = readable_ctx
                    .get_slot_list(true)
                    .map_err(|err| {
                        error!(
                            "[{}] Failed to enumerate PKCS#11 slots for library '{}': {}",
                            signer_name, lib_name, err
                        );
                        SignerError::PermanentlyUnusable
                    })?
                    .into_iter()
                    .find(|&slot_id| has_token_label(signer_name, &readable_ctx, slot_id, &slot_label));

                match slot_id {
                    Some(slot_id) => slot_id,
                    None => {
                        error!(
                            "[{}] No PKCS#11 slot found for library '{}' with label '{}'",
                            signer_name, lib_name, slot_label
                        );
                        return Err(SignerError::PermanentlyUnusable);
                    }
                }
            } else {
                error!(
                    "[{}] No PKCS#11 slot id or label specified for library '{}'",
                    signer_name, lib_name
                );
                return Err(SignerError::PermanentlyUnusable);
            };

            let slot_info = readable_ctx.get_slot_info(slot_id).map_err(|err| {
                error!(
                    "[{}] Unable to read PKCS#11 slot info for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );
                SignerError::PermanentlyUnusable
            })?;

            trace!("[{}] C_GetSlotInfo(): {:?}", signer_name, slot_info);

            let token_info = readable_ctx.get_token_info(slot_id).map_err(|err| {
                error!(
                    "[{}] Unable to read PKCS#11 token info for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );
                SignerError::PermanentlyUnusable
            })?;

            trace!("[{}] C_GetTokenInfo(): {:?}", signer_name, token_info);

            let user_pin = conn_settings.user_pin.clone();

            (cryptoki_info, slot_id, slot_info, token_info, user_pin)
        };

        // TODO: check for RSA key pair support?

        let login_session = if status.conn_settings().login_mode == LoginMode::LoginRequired {
            let login_session = Pkcs11Session::new(status.conn_settings().context.clone(), slot_id).map_err(|err| {
                error!(
                    "[{}] Unable to open PKCS#11 session for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );
                SignerError::PermanentlyUnusable
            })?;
            
            login_session.login(CKU_USER, user_pin.as_deref()).map_err(|err| {
                error!(
                    "[{}] Unable to login to PKCS#11 session for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );
                SignerError::PermanentlyUnusable
            })?;
            
            trace!(
                "[{}] Logged in to PKCS#11 session for library '{}' slot {}",
                signer_name,
                lib_name,
                slot_id,
            );
            
            Some(login_session)
        } else {
            None
        };

        // Switch from probing the server to using it.
        // -------------------------------------------

        let conn_settings = status.take_conn_settings();

        // Note: When Display'd via '{}' with format!() as is done below, the Rust `pkcs11` crate automatically trims
        // trailing whitespace from Cryptoki padded strings such as the token info label, model and manufacturerID.

        let server_identification = format!(
            "{} (Cryptoki v{}.{})",
            cryptoki_info.manufacturerID, cryptoki_info.libraryVersion.major, cryptoki_info.libraryVersion.minor
        );

        let token_identification = format!(
            "{} (model: {}, vendor: {})",
            token_info.label, token_info.model, token_info.manufacturerID
        );

        info!(
            "Using PKCS#11 token '{}' in slot {} of server '{}' via library '{}'",
            token_identification, slot_id, server_identification, lib_name
        );

        let supports_random_number_generation = false;
        let context = conn_settings.context.clone();
        let server_info = format!(
            "PKCS#11 Signer [token: {}, slot: {}, server: {}, library: {}]",
            token_identification, slot_id, server_identification, lib_name
        );
        let login_mode = conn_settings.login_mode;

        let state = UsableServerState::new(
            supports_random_number_generation,
            context,
            server_info,
            slot_id,
            login_mode,
            login_session,
        );

        *status = ProbingServerConnector::Usable(state);

        Ok(())
    }
}

//------------ Connection related functions ---------------------------------------------------------------------------

impl Pkcs11Signer {
    /// Get a connection to the server, if the server is usable.
    fn connect(&self) -> Result<Pkcs11Session, SignerError> {
        let conn = self.server()?.state().get_connection()?;
        Ok(conn)
    }

    /// Perform some operation using a PKCS#11 connection.
    ///
    /// Fails if the PKCS#11 server is not [Usable]. If the operation fails due to a transient connection error, retry
    /// with backoff upto a defined retry limit.
    fn with_conn<T, F>(&self, desc: &str, do_something_with_conn: F) -> Result<T, SignerError>
    where
        F: FnOnce(&Pkcs11Session) -> Result<T, pkcs11::errors::Error> + Copy,
    {
        let signer_name = &self.name;

        // Define the backoff policy to use
        let backoff_policy = ExponentialBackoff {
            initial_interval: RETRY_REQ_AFTER,
            multiplier: RETRY_REQ_AFTER_MULTIPLIER,
            max_elapsed_time: Some(RETRY_REQ_UNTIL_MAX),
            ..Default::default()
        };

        // Define a notify callback to customize messages written to the logger
        let notify = |err, next: Duration| {
            warn!(
                "[{}] {} failed, retrying in {} seconds: {}",
                signer_name,
                desc,
                next.as_secs(),
                err
            );
        };

        // Define an operation to (re)try
        let op = || {
            // First get a (possibly already existing) connection from the pool
            let conn = self.connect().map_err(retry_on_transient_signer_error)?;

            // Next, try to execute the callers operation using the connection. If it fails, examine the cause of
            // failure to determine if it should be a hard-fail (no more retries) or if we should try again.
            Ok((do_something_with_conn)(&conn).map_err(retry_on_transient_pkcs11_error)?)
        };

        // Don't even bother going round the retry loop if we haven't yet successfully connected to the PKCS#11 server
        // and verified its capabilities:
        let _ = self.server()?;

        // Try (and retry if needed) the requested operation.
        let res = backoff::retry_notify(backoff_policy, op, notify).or_else(|err| {
            error!("[{}] {} failed, retries exhausted: {}", signer_name, desc, err);
            Err(err)
        })?;

        Ok(res)
    }
}

//------------ High level helper functions for use by the public Signer interface implementation ----------------------

impl Pkcs11Signer {
    pub(super) fn remember_key_id(
        &self,
        key_id: &rpki::repository::crypto::KeyIdentifier,
        internal_key_id: String,
    ) -> Result<(), SignerError> {
        let readable_handle = self.handle.read().unwrap();
        let signer_handle = readable_handle.as_ref().ok_or(SignerError::Other(
            "PKCS#11: Failed to record signer key: Signer handle not set".to_string(),
        ))?;
        self.mapper
            .add_key(signer_handle, key_id, &internal_key_id)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to record signer key: {}", err)))?;

        Ok(())
    }

    pub(super) fn lookup_key_id(&self, key_id: &KeyIdentifier) -> Result<String, KeyError<SignerError>> {
        let readable_handle = self.handle.read().unwrap();
        let signer_handle = readable_handle.as_ref().ok_or(KeyError::KeyNotFound)?;

        let internal_key_id = self
            .mapper
            .get_key(signer_handle, key_id)
            .map_err(|_| KeyError::KeyNotFound)?;

        Ok(internal_key_id)
    }

    pub(super) fn get_random_bytes(&self, _num_bytes_wanted: usize) -> Result<Vec<u8>, SignerError> {
        if !self.supports_random() {
            return Err(SignerError::Pkcs11Error(
                "The PKCS#11 provider does not support random number generation".to_string(),
            ));
        }
        todo!()
    }

    pub(super) fn build_key(
        &self,
        algorithm: PublicKeyFormat,
    ) -> Result<(PublicKey, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, String), SignerError> {
        // https://tools.ietf.org/html/rfc6485#section-3: Asymmetric Key Pair Formats
        //   "The RSA key pairs used to compute the signatures MUST have a 2048-bit
        //    modulus and a public exponent (e) of 65,537."

        if !matches!(algorithm, PublicKeyFormat::Rsa) {
            return Err(SignerError::Pkcs11Error(format!(
                "Algorithm {:?} not supported while creating key",
                &algorithm
            )));
        }

        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut cka_id: [u8; 20] = [0; 20];
        openssl::rand::rand_bytes(&mut cka_id)
            .map_err(|_| SignerError::Pkcs11Error("Internal error while generating a random number".to_string()))?;

        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
        pub_template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(&cka_id));
        pub_template.push(CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(&2048));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(&[0x01, 0x00, 0x01]));
        pub_template.push(CK_ATTRIBUTE::new(CKA_LABEL).with_string("Krill"));

        let mut priv_template: Vec<CK_ATTRIBUTE> = Vec::new();
        priv_template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(&cka_id));
        priv_template.push(CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_LABEL).with_string("Krill"));

        let (pub_handle, priv_handle) = self.with_conn("generate key pair", |conn| {
            conn.generate_key_pair(&mech, &pub_template, &priv_template)
        })?;

        let public_key = self.get_public_key_from_handle(pub_handle)?;
        // let key_identifier = public_key.key_identifier();

        Ok((public_key, pub_handle, priv_handle, hex::encode(cka_id)))
    }

    fn get_rsa_public_key_bytes(&self, pub_handle: u64) -> Result<Bytes, SignerError> {
        let (modulus_len, pub_exponent_len) = self.with_conn("get key pair part lengths", |conn| {
            let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
            pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS));
            pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT));
            let (_, res_vec) = conn.get_attribute_value(pub_handle, &mut pub_template)?;
            Ok((res_vec[0].ulValueLen as usize, res_vec[1].ulValueLen as usize))
        })?;

        let (modulus, pub_exponent) = self.with_conn("get key pair parts", |conn| {
            let mut modulus = Vec::with_capacity(modulus_len);
            let mut pub_exponent = Vec::with_capacity(pub_exponent_len);
            modulus.resize(modulus_len, 0);
            pub_exponent.resize(pub_exponent_len, 0);
            let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
            pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS).with_bytes(modulus.as_mut_slice()));
            pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(pub_exponent.as_mut_slice()));
            conn.get_attribute_value(pub_handle, &mut pub_template)?;
            Ok((modulus, pub_exponent))
        })?;

        util::rsa_public_key_bytes_from_parts(&modulus, &pub_exponent)
    }

    // TODO: This is almost identical to the equivalent fn in KmipSigner. Factor out the common code.
    pub(super) fn get_public_key_from_handle(&self, pub_handle: u64) -> Result<PublicKey, SignerError> {
        let rsa_public_key_bytes = self.get_rsa_public_key_bytes(pub_handle)?;

        let subject_public_key = bcder::BitString::new(0, rsa_public_key_bytes);

        let subject_public_key_info =
            bcder::encode::sequence((PublicKeyFormat::Rsa.encode(), subject_public_key.encode()));

        let mut subject_public_key_info_source: Vec<u8> = Vec::new();
        subject_public_key_info
            .write_encoded(bcder::Mode::Der, &mut subject_public_key_info_source)
            .map_err(|err| {
                SignerError::Pkcs11Error(format!(
                    "Failed to create DER encoded SubjectPublicKeyInfo from constituent parts: {}",
                    err
                ))
            })?;

        let public_key = PublicKey::decode(subject_public_key_info_source.as_slice()).map_err(|err| {
            SignerError::Pkcs11Error(format!(
                "Failed to create public key from the DER encoded SubjectPublicKeyInfo: {}",
                err
            ))
        })?;

        Ok(public_key)
    }

    pub(super) fn sign_with_key(
        &self,
        private_key_handle: CK_OBJECT_HANDLE,
        algorithm: SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Signature, SignerError> {
        if algorithm.public_key_format() != PublicKeyFormat::Rsa {
            return Err(SignerError::KmipError(format!(
                "Algorithm '{:?}' not supported",
                algorithm.public_key_format()
            )));
        }

        let mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let signature_data = self.with_conn("sign", |conn| {
            conn.sign_init(&mechanism, private_key_handle)?;
            conn.sign(data)
        })?;

        let sig = Signature::new(SignatureAlgorithm::default(), Bytes::from(signature_data));

        Ok(sig)
    }

    pub(super) fn find_key(
        &self,
        cka_id_hex_str: &str,
        key_class: CK_OBJECT_CLASS,
    ) -> Result<CK_OBJECT_HANDLE, KeyError<SignerError>> {
        let human_key_class = match key_class {
            CKO_PUBLIC_KEY => "public key",
            CKO_PRIVATE_KEY => "private key",
            _ => "key",
        };

        let cka_id = hex::decode(cka_id_hex_str).map_err(|_| KeyError::Signer(SignerError::DecodeError))?;

        let results = self.with_conn("sign", |conn| {
            // Find at most two search results that match the given key class (public or private) and the given PKCS#11
            // CKA_ID bytes.
            let max_object_count = 2;
            let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
            template.push(CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&key_class));
            template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(cka_id.as_slice()));

            // A PKCS#11 session can have at most one active search operation at a time. A search must be initialized,
            // results fetched, and then finalized, only then can the session perform another search.
            conn.find_objects_init(&template)?;
            let results = conn.find_objects(max_object_count);
            let _ = conn.find_objects_final();

            results
        })?;

        match results.len() {
            0 => Err(KeyError::KeyNotFound),
            1 => Ok(results[0]),
            _ => Err(KeyError::Signer(SignerError::Pkcs11Error(format!(
                "More than one {} found with id {}",
                &human_key_class, cka_id_hex_str
            )))),
        }
    }
}

// TODO: Refactor duplicate code out of here and kmip/internal.rs:
fn is_time_to_check(time_between_checks: Duration, possible_lack_check_time: Option<Instant>) -> bool {
    match possible_lack_check_time {
        None => true,
        Some(instant) => Instant::now().saturating_duration_since(instant) > time_between_checks,
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Retry with backoff related helper impls/fns:
// --------------------------------------------------------------------------------------------------------------------

fn retry_on_transient_pkcs11_error(err: pkcs11::errors::Error) -> backoff::Error<SignerError> {
    if is_transient_error(&err) {
        backoff::Error::Transient(err.into())
    } else {
        backoff::Error::Permanent(err.into())
    }
}

fn retry_on_transient_signer_error(err: SignerError) -> backoff::Error<SignerError> {
    match err {
        SignerError::TemporarilyUnavailable => backoff::Error::Transient(err),
        _ => backoff::Error::Permanent(err),
    }
}

fn is_transient_error(err: &pkcs11::errors::Error) -> bool {
    match err {
        pkcs11::errors::Error::Io(_) => {
            // The Rust `pkcs11` crate encountered an I/O error. I assume this can only occur when trying and
            // failing to open the PKCS#11 library file that we asked it to use.
            false
        }
        pkcs11::errors::Error::Module(_) => {
            // The Rust `pkcs11` crate had a serious problem such as the loaded library not exporting a required
            // function or that it was asked to initialize an already initialized library.
            false
        }
        pkcs11::errors::Error::InvalidInput(_) => {
            // The Rust `pkcs11` crate was unable to use an input it was given, e.g. a PIN contained a nul byte
            // or was not set or unset as expected.
            false
        }
        pkcs11::errors::Error::Pkcs11(err) => {
            // Error codes were taken from the `types` module of the Rust `pkcs11` crate.
            // See section 11.1 of the PKCS#11 v2.20 specification for an explanation of each value.
            // Return true only for errors which might succeed very soon after they failed. Errors which are solvable
            // by an operator changing data or configuration in the HSM are not treated as transient errors as they
            // are unlikely to be solved in the immediate future and thus there is no value in retrying.
            //
            // Causes of certain errors that might be worth documenting or suggesting as guidance to the user in the
            // logs:
            //
            //   - CKR_FUNCTION_FAILED:   Can happen when the PKCS#11 library doesn't have access to its files, e.g.
            //                            when `softhsm2-util --init-token` was run as root but Krill is run as a
            //                            different user.
            //   - CKR_FUNCTION_FAILED:   Can happen when the PKCS#11 library cannot find its configuration files, e.g.
            //                            when the YubiHSM PKCS#11 library cannot find `yubihsm_pkcs11.conf` in the
            //                            current directory and the environment variable `YUBIHSM_PKCS11_CONF` is not
            //                            set and pointing to the correct location of the file or if the file is not
            //                            readable by the Krill user.
            //   - CKR_TOKEN_NOT_PRESENT: Can happen when the YubiHSM PKCS#11 configuration file `connector` setting
            //                            reers to a URL at which `yubihsm-connector -d` should be listening but the
            //                            YubiHSM PKCS#11 library fails to connect to (either because the URL is
            //                            incorrect or it is a HTTPS URL but there is a TLS failure such as invalid
            //                            certificate or unknown signing CA etc) or some other issue such as a firewall
            //                            or operating system restriction preventing access.
            match *err {
                // PKCS#11 v2.20
                CKR_OK => false, // unreachable!() ?
                CKR_CANCEL => false,
                CKR_HOST_MEMORY => true,
                CKR_SLOT_ID_INVALID => true, // maybe we tried accessing the slot just before it is created?
                CKR_GENERAL_ERROR => true,
                CKR_FUNCTION_FAILED => true, // the spec says the situation is not necessarily totally hopeless
                CKR_ARGUMENTS_BAD => false,  // resubmitting the same bad arguments will just fail again
                CKR_NO_EVENT => false,
                CKR_NEED_TO_CREATE_THREADS => false,
                CKR_CANT_LOCK => false,
                CKR_ATTRIBUTE_READ_ONLY => false, // for attributes that are always read only retrying will not succeed
                CKR_ATTRIBUTE_SENSITIVE => false,
                CKR_ATTRIBUTE_TYPE_INVALID => false,
                CKR_ATTRIBUTE_VALUE_INVALID => false,
                CKR_ACTION_PROHIBITED => false,
                CKR_DATA_INVALID => false,
                CKR_DATA_LEN_RANGE => false,
                CKR_DEVICE_ERROR => true, // some error but we don't know what so could be transient
                CKR_DEVICE_MEMORY => true, // maybe the token frees up some memory such that a retry succeeds?
                CKR_DEVICE_REMOVED => true, // not present at the time the function was executed but might be later
                CKR_ENCRYPTED_DATA_INVALID => false,
                CKR_ENCRYPTED_DATA_LEN_RANGE => false,
                CKR_FUNCTION_CANCELED => false,
                CKR_FUNCTION_NOT_PARALLEL => false,
                CKR_FUNCTION_NOT_SUPPORTED => false,
                CKR_KEY_HANDLE_INVALID => false,
                CKR_KEY_SIZE_RANGE => false,
                CKR_KEY_TYPE_INCONSISTENT => false,
                CKR_KEY_NOT_NEEDED => false,
                CKR_KEY_CHANGED => false,
                CKR_KEY_NEEDED => false,
                CKR_KEY_INDIGESTIBLE => false,
                CKR_KEY_FUNCTION_NOT_PERMITTED => false,
                CKR_KEY_NOT_WRAPPABLE => false,
                CKR_KEY_UNEXTRACTABLE => false,
                CKR_MECHANISM_INVALID => false,
                CKR_MECHANISM_PARAM_INVALID => false,
                CKR_OBJECT_HANDLE_INVALID => false,
                CKR_OPERATION_ACTIVE => true, // the active operation might finish thereby permitting a retry to succeed
                CKR_OPERATION_NOT_INITIALIZED => false,
                CKR_PIN_INCORRECT => false,
                CKR_PIN_INVALID => false,
                CKR_PIN_LEN_RANGE => false,
                CKR_PIN_EXPIRED => false,
                CKR_PIN_LOCKED => false,
                CKR_SESSION_CLOSED => true, // maybe on retry we open a new session and succeed?
                CKR_SESSION_COUNT => true, // if a session closes it might be possible on retry for a session open to succeed
                CKR_SESSION_HANDLE_INVALID => false,
                CKR_SESSION_PARALLEL_NOT_SUPPORTED => false,
                CKR_SESSION_READ_ONLY => false,
                CKR_SESSION_EXISTS => false,
                CKR_SESSION_READ_ONLY_EXISTS => true, // will succeed on retry if the conflicting SO session logs out
                CKR_SESSION_READ_WRITE_SO_EXISTS => true, // will succeed on retry if the conflicting SO session logs out
                CKR_SIGNATURE_INVALID => false,
                CKR_SIGNATURE_LEN_RANGE => false,
                CKR_TEMPLATE_INCOMPLETE => false,
                CKR_TEMPLATE_INCONSISTENT => false,
                CKR_TOKEN_NOT_PRESENT => true, // not present at the time the function was executed but might be later
                CKR_TOKEN_NOT_RECOGNIZED => false,
                CKR_TOKEN_WRITE_PROTECTED => true, // maybe the right protection is a transient condition?
                CKR_UNWRAPPING_KEY_HANDLE_INVALID => false,
                CKR_UNWRAPPING_KEY_SIZE_RANGE => false,
                CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => false,
                CKR_USER_ALREADY_LOGGED_IN => true, // maybe another client was is busy logging out so try again?
                CKR_USER_NOT_LOGGED_IN => false,
                CKR_USER_PIN_NOT_INITIALIZED => false,
                CKR_USER_TYPE_INVALID => false,
                CKR_USER_ANOTHER_ALREADY_LOGGED_IN => true,
                CKR_USER_TOO_MANY_TYPES => true, // maybe some sessions are terminated while retrying permitting us to succeed?
                CKR_WRAPPED_KEY_INVALID => false,
                CKR_WRAPPED_KEY_LEN_RANGE => false,
                CKR_WRAPPING_KEY_HANDLE_INVALID => false,
                CKR_WRAPPING_KEY_SIZE_RANGE => false,
                CKR_WRAPPING_KEY_TYPE_INCONSISTENT => false,
                CKR_RANDOM_SEED_NOT_SUPPORTED => false,
                CKR_RANDOM_NO_RNG => false,
                CKR_DOMAIN_PARAMS_INVALID => false,
                CKR_CURVE_NOT_SUPPORTED => false,
                CKR_BUFFER_TOO_SMALL => false,
                CKR_SAVED_STATE_INVALID => false,
                CKR_INFORMATION_SENSITIVE => false,
                CKR_STATE_UNSAVEABLE => true, // the spec doesn't seem to rule out this being a temporary condition
                CKR_CRYPTOKI_NOT_INITIALIZED => false,
                CKR_CRYPTOKI_ALREADY_INITIALIZED => false,
                CKR_MUTEX_BAD => false,        // should never happen so consider it fatal?
                CKR_MUTEX_NOT_LOCKED => false, // should never happen so consider it fatal?

                // PKCS#11 v2.40
                CKR_NEW_PIN_MODE => false,
                CKR_NEXT_OTP => false,
                CKR_EXCEEDED_MAX_ITERATIONS => false,
                CKR_FIPS_SELF_TEST_FAILED => false,
                CKR_LIBRARY_LOAD_FAILED => false,
                CKR_PIN_TOO_WEAK => false,
                CKR_PUBLIC_KEY_INVALID => false,
                CKR_FUNCTION_REJECTED => false,
                CKR_VENDOR_DEFINED => false,

                // Unknown
                _ => false,
            }
        }
        pkcs11::errors::Error::UnavailableInformation => false,
    }
}

impl From<pkcs11::errors::Error> for SignerError {
    fn from(err: pkcs11::errors::Error) -> Self {
        if is_transient_error(&err) {
            error!("PKCS#11 signer unavailable: {}", err);
            SignerError::TemporarilyUnavailable
        } else {
            SignerError::Pkcs11Error(err.to_string())
        }
    }
}
