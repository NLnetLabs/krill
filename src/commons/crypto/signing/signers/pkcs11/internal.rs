use std::{
    convert::TryInto,
    path::Path,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::Duration,
};

use backoff::ExponentialBackoff;

use bcder::encode::{PrimitiveContent, Values};
use bytes::Bytes;
use pkcs11::errors::Error as Pkcs11Error;
use pkcs11::types::*;
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm,
};

use crate::commons::{
    api::Handle,
    crypto::{
        dispatch::signerinfo::SignerMapper,
        signers::{
            pkcs11::{
                context::{Pkcs11Context, ThreadSafePkcs11Context},
                session::Pkcs11Session,
            },
            probe::{ProbeError, ProbeStatus, StatefulProbe},
            util,
        },
        SignerError,
    },
};

//------------ Types and constants ------------------------------------------------------------------------------------

/// The time to wait between an initial and subsequent attempt at sending a request to the PKCS#11 server.
const RETRY_REQ_AFTER: Duration = Duration::from_secs(2);

/// How much longer should we wait from one request attempt to the next compared to the previous wait?
const RETRY_REQ_AFTER_MULTIPLIER: f64 = 1.5;

/// The maximum amount of time to keep retrying a failed request.
const RETRY_REQ_UNTIL_MAX: Duration = Duration::from_secs(30);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoginMode {
    // The token can do cryptographic operations such as signing without requiring C_Login to be called first, and so a
    // user pin is also not required.
    LoginNotRequired,

    // The token requires that C_Login be called prior to performing any cryptographic operations such as signing. A
    // correct user pin may be needed for the login to succeed.
    LoginRequired,
}

#[derive(Clone, Debug)]
enum SlotIdOrLabel {
    Id(CK_SLOT_ID),

    Label(String),
}

// Placeholder struct
#[derive(Clone, Debug)]
struct ConnectionSettings {
    context: ThreadSafePkcs11Context,

    // For some PKCS#11 libraries it is easy, or only possible, to connect by slot ID (rather than slot label). With
    // others using labeled slots is easier (e.g. with SoftHSMv2 slot 0 has a seemingly random actual slot ID generated
    // when the slot is initialized) or is dynamic (apparently the OpenDNSSec project has encountered this behaviour).
    // When a slot label is supplied all available slots will be queried via `C_GetSlotList` and the slot id of the
    // first slot with a matching label will be used to connect to the HSM.
    slot: SlotIdOrLabel,

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
    server: Arc<StatefulProbe<ConnectionSettings, SignerError, UsableServerState>>,
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

        let server = Arc::new(StatefulProbe::new(Arc::new(conn_settings), Duration::from_secs(30)));

        let s = Pkcs11Signer {
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

    pub fn set_handle(&self, handle: crate::commons::api::Handle) {
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

    pub fn supports_random(&self) -> bool {
        if let Ok(status) = self.server.status(Self::probe_server) {
            if let Ok(state) = status.state() {
                return state.supports_random_number_generation;
            }
        }
        false
    }

    fn get_test_connection_settings() -> Result<ConnectionSettings, SignerError> {
        let context = Pkcs11Context::get_or_load(Path::new("/usr/lib/softhsm/libsofthsm2.so"));
        let slot = SlotIdOrLabel::Label("My token 1".to_string());
        let user_pin = Some("1234".to_string());
        let login_mode = LoginMode::LoginRequired;

        Ok(ConnectionSettings {
            context,
            slot,
            user_pin,
            login_mode,
        })
    }
}

//------------ Probe based server access ------------------------------------------------------------------------------

/// The details needed to interact with a usable PKCS#11 server.
#[derive(Debug)]
struct UsableServerState {
    context: ThreadSafePkcs11Context,

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
        context: ThreadSafePkcs11Context,
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

    pub fn get_connection(&self) -> Result<Pkcs11Session, Pkcs11Error> {
        Pkcs11Session::new(self.context.clone(), self.slot_id)
    }
}

impl Pkcs11Signer {
    /// Verify if the configured server is contactable and supports the required capabilities.
    fn probe_server(
        status: &ProbeStatus<ConnectionSettings, SignerError, UsableServerState>,
    ) -> Result<UsableServerState, ProbeError<SignerError>> {
        fn force_cache_flush(context: ThreadSafePkcs11Context) {
            // Finalize the PKCS#11 library so that we re-initialize it on next use, otherwise it just caches (at
            // least with SoftHSMv2 and YubiHSM) the token info and doesn't ever report the presence of the token
            // even when it becomes available.
            let _ = context.write().unwrap().finalize();
        }

        fn slot_label_eq(ctx: &RwLockReadGuard<Pkcs11Context>, slot_id: CK_SLOT_ID, slot_label: &str) -> bool {
            match ctx.get_token_info(slot_id) {
                Ok(info) => slot_label == info.label.to_string(),
                Err(err) => {
                    warn!("Failed to obtain token info for PKCS#11 slot id '{}': {}", slot_id, err);
                    false
                }
            }
        }

        fn find_slot_id_by_label(
            readable_ctx: &RwLockReadGuard<Pkcs11Context>,
            label: &str,
        ) -> Result<Option<u64>, Pkcs11Error> {
            let possible_slot_id = readable_ctx
                .get_slot_list(true)?
                .into_iter()
                .find(|&id| slot_label_eq(readable_ctx, id, label));
            Ok(possible_slot_id)
        }

        fn initialize_if_needed(conn_settings: &Arc<ConnectionSettings>) -> Result<(), SignerError> {
            conn_settings.context.write().unwrap().initialize_if_not_already()
        }

        fn interrogate_token(
            conn_settings: &Arc<ConnectionSettings>,
            signer_name: &str,
            lib_name: &String,
        ) -> Result<(CK_INFO, u64, CK_SLOT_INFO, CK_TOKEN_INFO, Option<String>), ProbeError<SignerError>> {
            let readable_ctx = conn_settings.context.read().unwrap();

            let cryptoki_info = readable_ctx.get_info().map_err(|err| {
                error!(
                    "[{}] Unable to read PKCS#11 info for library '{}': {}",
                    signer_name, lib_name, err
                );
                ProbeError::CompletedUnusable
            })?;
            trace!("[{}] C_GetInfo(): {:?}", signer_name, cryptoki_info);

            let slot_id = match &conn_settings.slot {
                SlotIdOrLabel::Id(id) => *id,
                SlotIdOrLabel::Label(label) => {
                    // No slot id provided, look it up by its label instead
                    match find_slot_id_by_label(&readable_ctx, &label) {
                        Ok(Some(id)) => id,
                        Ok(None) => {
                            let err_msg = format!(
                                "[{}] No PKCS#11 slot found for library '{}' with label '{}'",
                                signer_name, lib_name, label
                            );

                            error!("{}", err_msg);
                            return Err(ProbeError::CallbackFailed(SignerError::Pkcs11Error(err_msg)));
                        }
                        Err(err) => {
                            error!(
                                "[{}] Failed to enumerate PKCS#11 slots for library '{}': {}",
                                signer_name, lib_name, err
                            );
                            return Err(ProbeError::CompletedUnusable);
                        }
                    }
                }
            };

            let slot_info = readable_ctx.get_slot_info(slot_id).map_err(|err| {
                let err_msg = format!(
                    "[{}] Unable to read PKCS#11 slot info for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );

                error!("{}", err_msg);
                ProbeError::CallbackFailed(SignerError::Pkcs11Error(err_msg))
            })?;
            trace!("[{}] C_GetSlotInfo(): {:?}", signer_name, slot_info);

            let token_info = readable_ctx.get_token_info(slot_id).map_err(|err| {
                let err_msg = format!(
                    "[{}] Unable to read PKCS#11 token info for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );

                error!("{}", err_msg);
                ProbeError::CallbackFailed(SignerError::Pkcs11Error(err_msg))
            })?;
            trace!("[{}] C_GetTokenInfo(): {:?}", signer_name, token_info);

            let user_pin = conn_settings.user_pin.clone();
            Ok((cryptoki_info, slot_id, slot_info, token_info, user_pin))
        }

        fn check_rand_support(session: &Pkcs11Session) -> Result<bool, ProbeError<SignerError>> {
            // The PKCS#11 C_SeedRandom() and C_GenerateRandom() functions are allowed to return CKR_RANDOM_NO_RNG to
            // indicate "that the specified token doesn’t have a random number generator". The C_SeedRandom() function
            // can also return CKR_RANDOM_SEED_NOT_SUPPORTED. Thus it is not a given that the provider is able to
            // generate random numbers just because it exports the related functions. In theory the provider can also
            // fail to implement the random functions entirely but the Rust PKCS11 crate `Ctx::new()` function requires
            // these functions to be supported or else it will fail and we would never get to this point.
            Ok(session.generate_random(32).is_ok())
        }

        fn login(
            session: Pkcs11Session,
            user_pin: Option<String>,
            signer_name: &str,
            lib_name: &String,
            slot_id: u64,
        ) -> Result<Option<Pkcs11Session>, ProbeError<SignerError>> {
            session.login(CKU_USER, user_pin.as_deref()).map_err(|err| {
                error!(
                    "[{}] Unable to login to PKCS#11 session for library '{}' slot {}: {}",
                    signer_name, lib_name, slot_id, err
                );
                ProbeError::CompletedUnusable
            })?;
            trace!(
                "[{}] Logged in to PKCS#11 session for library '{}' slot {}",
                signer_name,
                lib_name,
                slot_id,
            );
            Ok(Some(session))
        }

        let signer_name = "TODO";
        let conn_settings = status.config()?;
        let lib_name = conn_settings.context.read().unwrap().get_lib_file_name();

        debug!("[{}] Probing server using library '{}'", signer_name, lib_name);

        initialize_if_needed(&conn_settings).map_err(|err| {
            error!(
                "[{}] Unable to initialize PKCS#11 info for library '{}': {}",
                signer_name, lib_name, err
            );
            ProbeError::CompletedUnusable
        })?;

        let (cryptoki_info, slot_id, _slot_info, token_info, user_pin) =
            interrogate_token(&conn_settings, signer_name, &lib_name).map_err(|err| {
                if matches!(err, ProbeError::CallbackFailed(SignerError::Pkcs11Error(_))) {
                    // While the token is not available now, it might be later.
                    force_cache_flush(conn_settings.context.clone());
                }
                err
            })?;

        let session = Pkcs11Session::new(conn_settings.context.clone(), slot_id).map_err(|err| {
            error!(
                "[{}] Unable to open PKCS#11 session for library '{}' slot {}: {}",
                signer_name, lib_name, slot_id, err
            );
            ProbeError::CompletedUnusable
        })?;

        // Note: We don't need to check for supported functions because the `pkcs11` Rust crate `fn new()` already
        // requires that all of the functions that we need are supported. In fact it checks for so many functions I
        // wonder if it might not fail on some customer deployments, but perhaps it checks only for functions required
        // by the PKCS#11 specification...?

        // TODO: check for RSA key pair support?

        let supports_random_number_generation = check_rand_support(&session)?;

        // Login if needed
        let login_session = if conn_settings.login_mode == LoginMode::LoginRequired {
            login(session, user_pin, signer_name, &lib_name, slot_id)?
        } else {
            None
        };

        // Switch from probing the server to using it.
        // -------------------------------------------

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

        Ok(state)
    }
}

//------------ Connection related functions ---------------------------------------------------------------------------

impl Pkcs11Signer {
    /// Get a connection to the server, if the server is usable.
    fn connect(&self) -> Result<Pkcs11Session, SignerError> {
        let conn = self.server.status(Self::probe_server)?.state()?.get_connection()?;
        Ok(conn)
    }

    /// Perform some operation using a PKCS#11 connection.
    ///
    /// Fails if the PKCS#11 server is not [Usable]. If the operation fails due to a transient connection error, retry
    /// with backoff upto a defined retry limit.
    fn with_conn<T, F>(&self, desc: &str, do_something_with_conn: F) -> Result<T, SignerError>
    where
        F: FnOnce(&Pkcs11Session) -> Result<T, Pkcs11Error> + Copy,
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
        let _ = self.server.status(Self::probe_server)?;

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

    pub(super) fn get_random_bytes(&self, num_bytes_wanted: usize) -> Result<Vec<u8>, SignerError> {
        if !self.supports_random() {
            return Err(SignerError::Pkcs11Error(
                "The PKCS#11 provider does not support random number generation".to_string(),
            ));
        }

        let num_bytes_wanted: CK_ULONG = num_bytes_wanted.try_into().map_err(|err| {
            SignerError::Pkcs11Error(format!(
                "Internal error: number of random bytes wanted is incompatible with PKCS#11: {}",
                err
            ))
        })?;

        self.with_conn("generate random", |conn| conn.generate_random(num_bytes_wanted))
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
    pub(super) fn get_public_key_from_handle(&self, pub_handle: CK_OBJECT_HANDLE) -> Result<PublicKey, SignerError> {
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

        // Note: The AWS CloudHSM Known Issues for the PKCS#11 Library states:
        // https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-pkcs11-sdk.html#ki-pkcs11-7
        //
        //   Issue: You could not hash more than 16KB of data
        //   For larger buffers, only the first 16KB will be hashed and returned. The excess data would have been
        //   silently ignored.
        //   Resolution status: Data less than 16KB in size continues to be sent to the HSM for hashing. We have added
        //   capability to hash locally, in software, data between 16KB and 64KB in size. The client and the SDKs will
        //   explicitly fail if the data buffer is larger than 64KB. You must update your client and SDK(s) to version
        //   1.1.1 or higher to benefit from the fix.
        //
        // TODO: if data is larger than 16KB we should hash locally and only use the HSM for signing, not for hashing.
        // Should we enable this behaviour based on detection of an AWS CloudHSM or a config flag or ??? As an example,
        // Oracle enables an AWS CloudHSM specific workaround by detecting a CLOUDHSM_IGNORE_CKA_MODIFIABLE_FALSE
        // environment variable.

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

    pub(super) fn destroy_key_by_handle(&self, key_handle: CK_OBJECT_HANDLE) -> Result<(), SignerError> {
        trace!("PKCS#11: Destroying key with PKCS#11 handle {}", key_handle);
        self.with_conn("destroy", |conn| conn.destroy_object(key_handle))
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Retry with backoff related helper impls/fns:
// --------------------------------------------------------------------------------------------------------------------

fn retry_on_transient_pkcs11_error(err: Pkcs11Error) -> backoff::Error<SignerError> {
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

fn is_transient_error(err: &Pkcs11Error) -> bool {
    match err {
        Pkcs11Error::Io(_) => {
            // The Rust `pkcs11` crate encountered an I/O error. I assume this can only occur when trying and
            // failing to open the PKCS#11 library file that we asked it to use.
            false
        }
        Pkcs11Error::Module(_) => {
            // The Rust `pkcs11` crate had a serious problem such as the loaded library not exporting a required
            // function or that it was asked to initialize an already initialized library.
            false
        }
        Pkcs11Error::InvalidInput(_) => {
            // The Rust `pkcs11` crate was unable to use an input it was given, e.g. a PIN contained a nul byte
            // or was not set or unset as expected.
            false
        }
        Pkcs11Error::Pkcs11(err) => {
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
        Pkcs11Error::UnavailableInformation => false,
    }
}

impl From<Pkcs11Error> for SignerError {
    fn from(err: Pkcs11Error) -> Self {
        if is_transient_error(&err) {
            error!("PKCS#11 signer unavailable: {}", err);
            SignerError::TemporarilyUnavailable
        } else {
            SignerError::Pkcs11Error(err.to_string())
        }
    }
}

impl From<ProbeError<SignerError>> for SignerError {
    fn from(err: ProbeError<SignerError>) -> Self {
        match err {
            ProbeError::WrongState => {
                SignerError::Other("Internal error: probe is not in the expected state".to_string())
            }
            ProbeError::AwaitingNextProbe => SignerError::TemporarilyUnavailable,
            ProbeError::CompletedUnusable => SignerError::PermanentlyUnusable,
            ProbeError::CallbackFailed(err) => err,
        }
    }
}

impl From<SignerError> for ProbeError<SignerError> {
    fn from(err: SignerError) -> Self {
        ProbeError::CallbackFailed(err)
    }
}
