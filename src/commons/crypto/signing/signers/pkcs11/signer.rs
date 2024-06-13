use std::{
    convert::{TryFrom, TryInto},
    marker::PhantomData,
    path::Path,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::Duration,
};

use backoff::ExponentialBackoff;

use bytes::Bytes;
use cryptoki::{
    context::Info,
    error::{Error as Pkcs11Error, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::UserType,
    slot::{Slot, SlotInfo, TokenInfo},
};

use rpki::{
    crypto::signer::KeyError,
    crypto::{
        KeyIdentifier, PublicKey, PublicKeyFormat, RpkiSignature, RpkiSignatureAlgorithm, Signature,
        SignatureAlgorithm, SigningError,
    },
};

use crate::commons::crypto::{
    dispatch::signerinfo::SignerMapper,
    signers::{
        pkcs11::{
            context::{Pkcs11Context, ThreadSafePkcs11Context},
            session::Pkcs11Session,
        },
        probe::{ProbeError, ProbeStatus, StatefulProbe},
    },
    SignerError, SignerHandle,
};

//------------ Types and constants ------------------------------------------------------------------------------------

use serde::{de::Visitor, Deserialize};

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Pkcs11SignerConfig {
    pub lib_path: String,

    pub user_pin: Option<String>,

    #[serde(deserialize_with = "slot_id_or_label")]
    pub slot: SlotIdOrLabel,

    #[serde(default = "Pkcs11SignerConfig::default_login")]
    pub login: bool,

    #[serde(default = "Pkcs11SignerConfig::default_retry_seconds")]
    pub retry_seconds: u64,

    #[serde(default = "Pkcs11SignerConfig::default_backoff_multiplier")]
    pub backoff_multiplier: f64,

    #[serde(default = "Pkcs11SignerConfig::default_max_retry_seconds")]
    pub max_retry_seconds: u64,

    #[serde(default)]
    pub public_key_attributes: Pkcs11ConfigurablePublicKeyAttributes,

    #[serde(default)]
    pub private_key_attributes: Pkcs11ConfigurablePrivateKeyAttributes,
}

impl Eq for Pkcs11SignerConfig {}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Pkcs11ConfigurablePublicKeyAttributes {
    /// PKCS#11 v2.40 4.4: "CK_TRUE if object can be modified. Default is
    /// CK_TRUE."
    #[serde(alias = "CKA_MODIFIABLE")]
    cka_modifiable: Option<bool>,

    /// PKCS#11 v2.40 4.4: "CK_TRUE if object is a private object; CK_FALSE
    /// if object is a public object. Default value is token-specific, and may
    /// depend on the values of other attributes of the object."
    #[serde(alias = "CKA_PRIVATE")]
    cka_private: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Pkcs11ConfigurablePrivateKeyAttributes {
    /// PKCS#11 v2.40 4.9: "CK_TRUE if key is extractable and can be wrapped."
    #[serde(alias = "CKA_EXTRACTABLE")]
    cka_extractable: Option<bool>,

    /// PKCS#11 v2.40 4.4: "CK_TRUE if object can be modified. Default is
    /// CK_TRUE."
    #[serde(alias = "CKA_MODIFIABLE")]
    cka_modifiable: Option<bool>,

    /// PKCS#11 v2.40 4.4: "CK_TRUE if object is a private object; CK_FALSE
    /// if object is a public object. Default value is token-specific, and may
    /// depend on the values of other attributes of the object."
    #[serde(alias = "CKA_PRIVATE")]
    cka_private: Option<bool>,

    /// PKCS#11 v2.40 4.9: "CK_TRUE if key is sensitive."
    #[serde(alias = "CKA_SENSITIVE")]
    cka_sensitive: Option<bool>,
}

impl Pkcs11SignerConfig {
    pub fn default_login() -> bool {
        true
    }

    pub fn default_retry_seconds() -> u64 {
        2
    }

    pub fn default_backoff_multiplier() -> f64 {
        1.5
    }

    pub fn default_max_retry_seconds() -> u64 {
        30
    }
}

impl Default for Pkcs11ConfigurablePublicKeyAttributes {
    fn default() -> Self {
        // These values are backward compatible with the hard-coded values
        // used by Krill before they were made configurable for #1018.
        // See: https://github.com/NLnetLabs/krill/issues/1018
        Self {
            cka_modifiable: None,
            cka_private: Some(true),
        }
    }
}

impl Pkcs11ConfigurablePublicKeyAttributes {
    pub fn to_vec(&self) -> Vec<Attribute> {
        let mut attrs = vec![];
        if let Some(attr_value) = self.cka_modifiable {
            attrs.push(Attribute::Modifiable(attr_value));
        }
        if let Some(attr_value) = self.cka_private {
            attrs.push(Attribute::Private(attr_value));
        }
        attrs
    }
}

impl Default for Pkcs11ConfigurablePrivateKeyAttributes {
    fn default() -> Self {
        // These values are backward compatible with the hard-coded values
        // used by Krill before they were made configurable for #1018.
        //
        // The original values chosen were partly informed by a SafeNet article:
        //
        //   "Follow best practices when setting sensitive key attributes: If you have secret or private keys
        //    that are particularly sensitive and you want to prevent them from being wrapped off, they can be
        //    generated with their template attributes: CKA_SENSITIVE and CKA_PRIVATE set to True and
        //    CKA_EXTRACTABLE and CKA_MODIFIABLE both set to False. This way, the keys are only
        //    accessible by a user who is logged in, and key values cannot be read by anyone. Also, the keys
        //    cannot be wrapped off and the attribute values cannot be changed at some later time to invalidate
        //    the original settings."
        //
        // See:
        //   - https://github.com/NLnetLabs/krill/issues/1018
        //   - http://secgroup.dais.unive.it/wp-content/uploads/2010/10/Reponse-by-SafeNet.pdf
        Self {
            cka_extractable: Some(false),
            cka_modifiable: None,
            cka_private: Some(true),
            cka_sensitive: Some(true),
        }
    }
}

impl Pkcs11ConfigurablePrivateKeyAttributes {
    pub fn to_vec(&self) -> Vec<Attribute> {
        let mut attrs = vec![];
        if let Some(attr_value) = self.cka_extractable {
            attrs.push(Attribute::Extractable(attr_value));
        }
        if let Some(attr_value) = self.cka_modifiable {
            attrs.push(Attribute::Modifiable(attr_value));
        }
        if let Some(attr_value) = self.cka_private {
            attrs.push(Attribute::Private(attr_value));
        }
        if let Some(attr_value) = self.cka_sensitive {
            attrs.push(Attribute::Sensitive(attr_value));
        }
        attrs
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoginMode {
    // The token can do cryptographic operations such as signing without requiring C_Login to be called first, and so a
    // user pin is also not required.
    LoginNotRequired,

    // The token requires that C_Login be called prior to performing any cryptographic operations such as signing. A
    // correct user pin may be needed for the login to succeed.
    LoginRequired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotIdOrLabel {
    Id(u64),

    Label(String),
}

// Placeholder struct
#[derive(Clone, Debug)]
struct ConnectionSettings {
    lib_path: String,

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

    retry_interval: Duration,

    backoff_multiplier: f64,

    retry_timeout: Duration,
}

impl TryFrom<&Pkcs11SignerConfig> for ConnectionSettings {
    type Error = SignerError;

    fn try_from(conf: &Pkcs11SignerConfig) -> Result<Self, Self::Error> {
        let lib_path = conf.lib_path.clone();
        let slot = conf.slot.clone();
        let user_pin = conf.user_pin.clone();
        let login_mode = match conf.login {
            true => LoginMode::LoginRequired,
            false => LoginMode::LoginNotRequired,
        };
        let retry_interval = Duration::from_secs(conf.retry_seconds);
        let backoff_multiplier = conf.backoff_multiplier;
        let retry_timeout = Duration::from_secs(conf.max_retry_seconds);

        Ok(ConnectionSettings {
            lib_path,
            slot,
            user_pin,
            login_mode,
            retry_interval,
            backoff_multiplier,
            retry_timeout,
        })
    }
}

#[derive(Debug)]
pub struct Pkcs11Signer {
    name: String,

    handle: RwLock<Option<SignerHandle>>,

    mapper: Arc<SignerMapper>,

    /// A probe dependent interface to the PKCS#11 server.
    server: Arc<StatefulProbe<ConnectionSettings, SignerError, UsableServerState>>,

    extra_public_key_attributes: Vec<Attribute>,

    extra_private_key_attributes: Vec<Attribute>,
}

impl Pkcs11Signer {
    /// Creates a new instance of Pkcs11Signer.
    ///
    /// Warning: invoking this function twice within the same process when testing with SoftHSM can lead to error
    /// CKR_USER_ALREADY_LOGGED_IN. To avoid this tests should be run with `cargo test ... -- --test-threads=1`.
    pub fn build(
        name: &str,
        conf: &Pkcs11SignerConfig,
        probe_interval: Duration,
        mapper: Arc<SignerMapper>,
    ) -> Result<Self, SignerError> {
        // Signer initialization should not block Krill startup. As such we verify that we are able to load the PKCS#11
        // library don't we initialize the PKCS#11 interface yet because we don't know what it's code will do. If it
        // were to block while trying to connect to a remote server it would block Krill from starting up completely.
        // If the remote server is down and the library has logic to delay and retry, or lacks appropriate timeouts of
        // connection attempts, we could get stuck for a while. Instead we defer initialization of the library until
        // first use. The downside of this approach is that we won't detect any issues until that point. Another reason
        // not to initialize the PKCS#11 library here is that if there are multiple instances of the Pkcs11Signer only
        // the first of them should call the PKCS#11 C_Initialize() function as the PKCS#11 v2.20 specification states
        // that "Note that exactly one call to C_Initialize should be made for each application (as opposed to one call
        // for every thread, for example)". At least, for the same PKCS#11 library that is. If two instances of
        // Pkcs11Signer each use a different PKCS#11 library, e.g. one uses the SoftHSMv2 library and the other uses the
        // AWS CloudHSM library, presumably they both need initializing within the same instance of the Krill
        // "application".

        let server = Arc::new(StatefulProbe::new(
            name.to_string(),
            Arc::new(conf.try_into()?),
            probe_interval,
        ));

        let extra_public_key_attributes = conf.public_key_attributes.to_vec();
        let extra_private_key_attributes = conf.private_key_attributes.to_vec();

        let s = Pkcs11Signer {
            name: name.to_string(),
            handle: RwLock::new(None),
            mapper,
            server,
            extra_public_key_attributes,
            extra_private_key_attributes,
        };

        Ok(s)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_handle(&self, handle: SignerHandle) {
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
        match self.build_key_internal(PublicKeyFormat::Rsa) {
            Ok((public_key, _, _, internal_key_id)) => Ok((public_key, internal_key_id)),

            Err(err @ InternalConnError::Pkcs11Error(Pkcs11Error::Pkcs11(RvError::TemplateInconsistent))) => {
                // https://github.com/NLnetLabs/krill/issues/1019
                let err_msg = format!(
                    "{} [Note: This error can occur if the signer does not support authenticated \
                    access to public keys. Setting `CKA_PRIVATE` in krill.conf to \"false\"` may help]",
                    err
                );
                Err(SignerError::Pkcs11Error(err_msg))
            }

            Err(err) => Err(err.into()),
        }
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &str,
        challenge: &D,
    ) -> Result<RpkiSignature, SignerError> {
        let priv_handle = self
            .find_key(key_id, ObjectClass::PRIVATE_KEY)
            .map_err(|err| match err {
                KeyError::KeyNotFound => SignerError::KeyNotFound,
                KeyError::Signer(err) => err,
            })?;
        self.sign_with_key(priv_handle, RpkiSignatureAlgorithm::default(), challenge.as_ref())
    }
}

//------------ Probe based server access ------------------------------------------------------------------------------

/// The details needed to interact with a usable PKCS#11 server.
#[derive(Debug)]
struct UsableServerState {
    context: ThreadSafePkcs11Context,

    conn_info: String,

    slot_id: Slot,

    /// When login_mode is NOT LoginMode::LoginRequired this will be None.
    ///
    /// Section 11.6 "Session management functions" of the PKCS#11 v2.20 specification says:
    ///   "Call C_Login to log the user into the token. Since all sessions an application has with a token have a
    ///    shared login state, C_Login only needs to be called for one of the sessions."
    ///
    /// Therefore we hold a reference to the login session so that all future sessions are considered logged in.
    /// The Drop impl for Pkcs11Session will log the session out if logged in.
    _login_session: Option<Pkcs11Session>,

    retry_interval: Duration,

    backoff_multiplier: f64,

    retry_timeout: Duration,
}

impl UsableServerState {
    pub fn new(
        context: ThreadSafePkcs11Context,
        conn_info: String,
        slot_id: Slot,
        login_session: Option<Pkcs11Session>,
        retry_interval: Duration,
        backoff_multiplier: f64,
        retry_timeout: Duration,
    ) -> UsableServerState {
        UsableServerState {
            context,
            conn_info,
            slot_id,
            _login_session: login_session,
            retry_interval,
            backoff_multiplier,
            retry_timeout,
        }
    }

    pub fn get_connection(&self) -> Result<Pkcs11Session, Pkcs11Error> {
        Pkcs11Session::new(self.context.clone(), self.slot_id)
    }
}

impl Pkcs11Signer {
    /// Verify if the configured server is contactable and supports the required capabilities.
    fn probe_server(
        name: String,
        status: &ProbeStatus<ConnectionSettings, SignerError, UsableServerState>,
    ) -> Result<UsableServerState, ProbeError<SignerError>> {
        fn slot_label_eq(ctx: &RwLockReadGuard<Pkcs11Context>, slot: Slot, slot_label: &str) -> bool {
            match ctx.get_token_info(slot) {
                Ok(info) => String::from_utf8_lossy(&info.label).trim_end() == slot_label,
                Err(err) => {
                    warn!(
                        "Failed to obtain token info for PKCS#11 slot id '{}': {}",
                        slot.id(),
                        err
                    );
                    false
                }
            }
        }

        fn find_slot_by_label(
            readable_ctx: &RwLockReadGuard<Pkcs11Context>,
            label: &str,
        ) -> Result<Option<Slot>, Pkcs11Error> {
            let possible_slot_id = readable_ctx
                .get_slot_list(true)?
                .into_iter()
                .find(|&id| slot_label_eq(readable_ctx, id, label));
            Ok(possible_slot_id)
        }

        fn initialize_if_needed(
            conn_settings: &Arc<ConnectionSettings>,
        ) -> Result<ThreadSafePkcs11Context, SignerError> {
            let lib_path = Path::new(&conn_settings.lib_path);
            let ctx = Pkcs11Context::get_or_load(lib_path)?;
            ctx.write().unwrap().initialize_if_not_already()?;
            Ok(ctx)
        }

        #[allow(clippy::type_complexity)]
        fn interrogate_token(
            conn_settings: &Arc<ConnectionSettings>,
            ctx: ThreadSafePkcs11Context,
            name: &str,
            lib_name: &String,
        ) -> Result<(Info, Slot, SlotInfo, TokenInfo, Option<String>), ProbeError<SignerError>> {
            let readable_ctx = ctx.read().unwrap();

            let cryptoki_info = readable_ctx.get_info().map_err(|err| {
                error!(
                    "[{}] Unable to read PKCS#11 info for library '{}': {}",
                    name, lib_name, err
                );
                ProbeError::CompletedUnusable
            })?;
            trace!("[{}] C_GetInfo(): {:?}", name, cryptoki_info);

            let slot = match &conn_settings.slot {
                SlotIdOrLabel::Id(id) => {
                    match readable_ctx
                        .get_slot_list(false)
                        .map_err(|err| {
                            error!(
                                "[{}] Unable to get PKCS#11 slot list for library '{}': {}",
                                name, lib_name, err
                            );
                            ProbeError::CompletedUnusable
                        })?
                        .into_iter()
                        .find(|&slot| slot.id() == *id)
                    {
                        Some(slot) => slot,
                        None => {
                            let err_msg = format!(
                                "[{}] No PKCS#11 slot found for library '{}' with id {}",
                                name, lib_name, id
                            );

                            error!("{}", err_msg);
                            return Err(ProbeError::CallbackFailed(SignerError::TemporarilyUnavailable));
                        }
                    }
                }
                SlotIdOrLabel::Label(label) => {
                    // No slot id provided, look it up by its label instead
                    match find_slot_by_label(&readable_ctx, label) {
                        Ok(Some(slot)) => slot,
                        Ok(None) => {
                            let err_msg = format!(
                                "[{}] No PKCS#11 slot found for library '{}' with label '{}'",
                                name, lib_name, label
                            );

                            error!("{}", err_msg);
                            return Err(ProbeError::CallbackFailed(SignerError::TemporarilyUnavailable));
                        }
                        Err(err) => {
                            error!(
                                "[{}] Failed to enumerate PKCS#11 slots for library '{}': {}",
                                name, lib_name, err
                            );
                            return Err(ProbeError::CompletedUnusable);
                        }
                    }
                }
            };

            let slot_info = readable_ctx.get_slot_info(slot).map_err(|err| {
                let err_msg = format!(
                    "[{}] Unable to read PKCS#11 slot info for library '{}' slot {}: {}",
                    name, lib_name, slot, err
                );

                error!("{}", err_msg);

                if is_transient_error(&err) {
                    ProbeError::CallbackFailed(SignerError::TemporarilyUnavailable)
                } else {
                    ProbeError::CallbackFailed(SignerError::Pkcs11Error(err_msg))
                }
            })?;
            trace!("[{}] C_GetSlotInfo(): {:?}", name, slot_info);

            let token_info = readable_ctx.get_token_info(slot).map_err(|err| {
                let err_msg = format!(
                    "[{}] Unable to read PKCS#11 token info for library '{}' slot {}: {}",
                    name, lib_name, slot, err
                );

                error!("{}", err_msg);

                if is_transient_error(&err) {
                    ProbeError::CallbackFailed(SignerError::TemporarilyUnavailable)
                } else {
                    ProbeError::CallbackFailed(SignerError::Pkcs11Error(err_msg))
                }
            })?;
            trace!("[{}] C_GetTokenInfo(): {:?}", name, token_info);

            let user_pin = conn_settings.user_pin.clone();
            Ok((cryptoki_info, slot, slot_info, token_info, user_pin))
        }

        fn login(
            session: Pkcs11Session,
            login_mode: LoginMode,
            user_pin: Option<String>,
            name: &str,
            lib_name: &String,
            slot: Slot,
        ) -> Result<Option<Pkcs11Session>, ProbeError<SignerError>> {
            match login_mode {
                LoginMode::LoginNotRequired => {
                    // Nothing to do
                    Ok(None)
                }
                LoginMode::LoginRequired => {
                    session.login(UserType::User, user_pin.as_deref()).map_err(|err| {
                        error!(
                            "[{}] Unable to login to PKCS#11 session for library '{}' slot {}: {}",
                            name, lib_name, slot, err
                        );
                        ProbeError::CallbackFailed(SignerError::TemporarilyUnavailable)
                    })?;

                    trace!(
                        "[{}] Logged in to PKCS#11 session for library '{}' slot {}",
                        name,
                        lib_name,
                        slot,
                    );

                    Ok(Some(session))
                }
            }
        }

        let conn_settings = status.config()?;
        let lib_name = &conn_settings.lib_path;

        debug!("[{}] Probing server using library '{}'", name, lib_name);

        let context = initialize_if_needed(&conn_settings).map_err(|err| {
            error!(
                "[{}] Unable to initialize PKCS#11 info for library '{}': {}",
                name, lib_name, err
            );
            ProbeError::CompletedUnusable
        })?;

        match interrogate_token(&conn_settings, context.clone(), &name, lib_name) {
            Ok((cryptoki_info, slot, _slot_info, token_info, user_pin)) => {
                let session = Pkcs11Session::new(context.clone(), slot).map_err(|err| {
                    error!(
                        "[{}] Unable to open PKCS#11 session for library '{}' slot {}: {}",
                        name, lib_name, slot, err
                    );
                    ProbeError::CompletedUnusable
                })?;

                // TODO: unlike the `pkcs11` crate, the `cryptoki` crate doesn't require lots of PKCS#11 functions to be
                // implemented by the loaded library. Do we need to verify therefore for ourselves that the required
                // functions exist/work? See: https://github.com/parallaxsecond/rust-cryptoki/issues/78

                // TODO: check for RSA key pair support?

                // Login if needed
                let login_session = login(session, conn_settings.login_mode, user_pin, &name, lib_name, slot)?;

                // Switch from probing the server to using it.
                // -------------------------------------------

                // Note: When Display'd via '{}' with format!() as is done below, the Rust `cryptoki` crate automatically trims
                // trailing whitespace from Cryptoki padded strings such as the token info label, model and manufacturerID.

                let server_identification = format!(
                    "{} (Cryptoki v{})",
                    cryptoki_info.manufacturer_id(),
                    cryptoki_info.library_version()
                );

                let token_identification = format!(
                    "{} (model: {}, vendor: {})",
                    token_info.label(),
                    token_info.model(),
                    token_info.manufacturer_id()
                );

                info!(
                    "Using PKCS#11 token '{}' in slot {} of server '{}' via library '{}'",
                    token_identification, slot, server_identification, lib_name
                );

                let server_info = format!(
                    "PKCS#11 Signer [token: {}, slot: {}, server: {}, library: {}]",
                    token_identification, slot, server_identification, lib_name
                );

                let state = UsableServerState::new(
                    context,
                    server_info,
                    slot,
                    login_session,
                    conn_settings.retry_interval,
                    conn_settings.backoff_multiplier,
                    conn_settings.retry_timeout,
                );

                Ok(state)
            }
            Err(err) => {
                if matches!(err, ProbeError::CallbackFailed(SignerError::TemporarilyUnavailable)) {
                    // This error can occur if the PKCS#11 library has cached
                    // the available token state on startup and doesn't see
                    // the token even though it is now available. For example
                    // we've seen this happen with SoftHSMv2 (when the slot is
                    // not yet initialized) and YubiHSM 2 (when the connector
                    // daemon is not running). Re-initialising the library
                    // helped in these specific cases and might therefore help
                    // with whichever token is being used now. Uninitialize
                    // the library so that it will be re-initialized when
                    // probed again.
                    context.write().unwrap().uninitialize_if_not_already();
                }
                Err(err)
            }
        }
    }
}

//------------ Connection related functions ---------------------------------------------------------------------------

impl Pkcs11Signer {
    /// Get a connection to the server, if the server is usable.
    fn connect(&self) -> Result<Pkcs11Session, InternalConnError> {
        let conn = self.server.status(Self::probe_server)?.state()?.get_connection()?;
        Ok(conn)
    }

    /// Perform some operation using a PKCS#11 connection.
    ///
    /// Fails if the PKCS#11 server is not [Usable]. If the operation fails due to a transient connection error, retry
    /// with backoff upto a defined retry limit.
    fn with_conn<T, F>(&self, desc: &str, mut do_something_with_conn: F) -> Result<T, InternalConnError>
    where
        F: FnMut(&Pkcs11Session) -> Result<T, Pkcs11Error>,
    {
        let signer_name = &self.name;

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
            let conn = self.connect().map_err(retry_on_transient_error)?;

            // Next, try to execute the callers operation using the connection. If it fails, examine the cause of
            // failure to determine if it should be a hard-fail (no more retries) or if we should try again.
            (do_something_with_conn)(&conn).map_err(retry_on_transient_pkcs11_error)
        };

        // Don't even bother going round the retry loop if we haven't yet successfully connected to the PKCS#11 server
        // and verified its capabilities:
        let status = self.server.status(Self::probe_server)?;
        let state = status.state()?;

        // Define the backoff policy to use
        let backoff_policy = ExponentialBackoff {
            initial_interval: state.retry_interval,
            multiplier: state.backoff_multiplier,
            max_elapsed_time: Some(state.retry_timeout),
            ..Default::default()
        };

        // Try (and retry if needed) the requested operation.
        backoff::retry_notify(backoff_policy, op, notify).map_err(|e| {
            error!("[{}] {} failed, retries exhausted: {}", signer_name, desc, e);
            e.into()
        })
    }
}

//------------ High level helper functions for use by the public Signer interface implementation ----------------------

impl Pkcs11Signer {
    pub(super) fn remember_key_id(
        &self,
        key_id: &rpki::crypto::KeyIdentifier,
        internal_key_id: String,
    ) -> Result<(), SignerError> {
        let readable_handle = self.handle.read().unwrap();
        let signer_handle = readable_handle.as_ref().ok_or_else(|| {
            SignerError::Other("PKCS#11: Failed to record signer key: Signer handle not set".to_string())
        })?;
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

    pub(super) fn build_key(
        &self,
        algorithm: PublicKeyFormat,
    ) -> Result<(PublicKey, ObjectHandle, ObjectHandle, String), SignerError> {
        Ok(self.build_key_internal(algorithm)?)
    }

    fn build_key_internal(
        &self,
        algorithm: PublicKeyFormat,
    ) -> Result<(PublicKey, ObjectHandle, ObjectHandle, String), InternalConnError> {
        // https://tools.ietf.org/html/rfc6485#section-3: Asymmetric Key Pair Formats
        //   "The RSA key pairs used to compute the signatures MUST have a 2048-bit
        //    modulus and a public exponent (e) of 65,537."

        if !matches!(algorithm, PublicKeyFormat::Rsa) {
            return Err(SignerError::Pkcs11Error(format!(
                "Algorithm {:?} not supported while creating key",
                &algorithm
            )))?;
        }

        let mech = Mechanism::RsaPkcsKeyPairGen;

        let mut cka_id: [u8; 20] = [0; 20];
        openssl::rand::rand_bytes(&mut cka_id)
            .map_err(|_| SignerError::Pkcs11Error("Internal error while generating a random number".to_string()))?;

        let pub_template = self.mk_public_key_template(&cka_id, &self.extra_public_key_attributes);
        let priv_template = self.mk_private_key_template(&cka_id, &self.extra_private_key_attributes);

        let (pub_handle, priv_handle) = self.with_conn("generate key pair", |conn| {
            // The Krill functional test once failed under GitHub Actions with error:
            //   libsofthsm2.so::C_GenerateKeyPair() failed: PKCS#11: CKR_TEMPLATE_INCONSISTENT (0xd1)
            // and with the underlying SoftHSM log containing this at the same timestamp:
            //   ObjectFile.cpp(124): The attribute does not exist: 0x00000002
            // and where the `pkcs11` Rust crate `types.rs` file defines that attribute as:
            //   pub const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x00000002;
            // How can the CKA_PRIVATE attribute not exist?
            // Is this a real issue or just a transient problem with SoftHSMv2?
            conn.generate_key_pair(&mech, &pub_template, &priv_template)
        })?;

        let public_key = self.get_public_key_from_handle(pub_handle)?;

        Ok((public_key, pub_handle, priv_handle, hex::encode(cka_id)))
    }

    fn mk_private_key_template(&self, cka_id: &[u8], extra_attrs: &[Attribute]) -> Vec<Attribute> {
        let mut priv_template = vec![
            Attribute::Id(cka_id.to_vec()),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
            Attribute::Token(true),
            Attribute::Label("Krill".to_string().into_bytes()),
        ];
        priv_template.extend_from_slice(extra_attrs);
        priv_template
    }

    fn mk_public_key_template(&self, cka_id: &[u8], extra_attrs: &[Attribute]) -> Vec<Attribute> {
        let mut pub_template = vec![
            Attribute::Id(cka_id.to_vec()),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Token(true),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
            Attribute::Label("Krill".to_string().into_bytes()),
        ];
        pub_template.extend_from_slice(extra_attrs);
        pub_template
    }

    pub(super) fn get_public_key_from_handle(&self, pub_handle: ObjectHandle) -> Result<PublicKey, SignerError> {
        let res = self.with_conn("get key pair parts", |conn| {
            conn.get_attributes(pub_handle, &[AttributeType::Modulus, AttributeType::PublicExponent])
        })?;

        if res.len() == 2 {
            if let (Attribute::Modulus(m), Attribute::PublicExponent(e)) = (&res[0], &res[1]) {
                PublicKey::rsa_from_components(m, e).map_err(|e| {
                    SignerError::Pkcs11Error(format!(
                        "Failed to construct RSA Public for key '{:?}'. Error: {}",
                        pub_handle, e
                    ))
                })
            } else {
                Err(SignerError::Pkcs11Error(format!(
                    "Unable to obtain modulus and public exponent for key {:?}. Got two different attribute types: {} and {}",
                    pub_handle,
                    res[0].attribute_type(),
                    res[1].attribute_type(),
                )))
            }
        } else {
            Err(SignerError::Pkcs11Error(format!(
                "Unable to obtain modulus and public exponent attributes for key {:?}",
                pub_handle
            )))
        }
    }

    pub(super) fn sign_with_key<Alg: SignatureAlgorithm>(
        &self,
        private_key_handle: ObjectHandle,
        algorithm: Alg,
        data: &[u8],
    ) -> Result<Signature<Alg>, SignerError> {
        if algorithm.public_key_format() != PublicKeyFormat::Rsa {
            return Err(SignerError::KmipError(format!(
                "Algorithm '{:?}' not supported",
                algorithm.public_key_format()
            )));
        }

        let mechanism = Mechanism::Sha256RsaPkcs;

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

        let signature_data = self.with_conn("sign", |conn| conn.sign(&mechanism, private_key_handle, data))?;

        let sig = Signature::new(algorithm, Bytes::from(signature_data));

        Ok(sig)
    }

    pub(super) fn find_key(
        &self,
        cka_id_hex_str: &str,
        key_class: ObjectClass,
    ) -> Result<ObjectHandle, KeyError<SignerError>> {
        let human_key_class = match key_class {
            ObjectClass::PUBLIC_KEY => "public key",
            ObjectClass::PRIVATE_KEY => "private key",
            _ => "key",
        };

        let cka_id = hex::decode(cka_id_hex_str).map_err(|_| KeyError::Signer(SignerError::DecodeError))?;

        let results = self
            .with_conn("find key", |conn| {
                // Find at most one result that matches the given key class (public or private) and the given PKCS#11
                // CKA_ID bytes.

                // A PKCS#11 session can have at most one active search operation at a time. A search must be initialized,
                // results fetched, and then finalized, only then can the session perform another search.
                conn.find_objects(&[Attribute::Class(key_class), Attribute::Id(cka_id.clone())])
            })
            .map_err(SignerError::from)?;

        match results.len() {
            0 => Err(KeyError::KeyNotFound),
            1 => Ok(results[0]),
            _ => Err(KeyError::Signer(SignerError::Pkcs11Error(format!(
                "More than one {} found with id {}",
                &human_key_class, cka_id_hex_str
            )))),
        }
    }

    pub(super) fn destroy_key_by_handle(&self, key_handle: ObjectHandle) -> Result<(), SignerError> {
        trace!("[{}] Destroying key with PKCS#11 handle {}", self.name, key_handle);
        Ok(self.with_conn("destroy", |conn| conn.destroy_object(key_handle))?)
    }
}

//------------ Functions required to exist by the `SignerProvider` ----------------------------------------------------

// Implement the functions defined by the `Signer` trait because `SignerProvider` expects to invoke them, but as the
// dispatching is not trait based we don't actually have to implement the `Signer` trait.

impl Pkcs11Signer {
    pub fn create_key(&self, algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        let (key, _, _, internal_key_id) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.remember_key_id(&key_id, internal_key_id)?;
        Ok(key_id)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<SignerError>> {
        let internal_key_id = self.lookup_key_id(key_id)?;
        let pub_handle = self.find_key(&internal_key_id, ObjectClass::PUBLIC_KEY)?;
        self.get_public_key_from_handle(pub_handle).map_err(KeyError::Signer)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        debug!("[{}] Destroying key pair with ID {}", self.name, key_id);
        let internal_key_id = self.lookup_key_id(key_id)?;
        let mut res: Result<(), KeyError<SignerError>> = Ok(());

        // try deleting the public key
        if let Ok(pub_handle) = self.find_key(&internal_key_id, ObjectClass::PUBLIC_KEY) {
            res = self.destroy_key_by_handle(pub_handle).map_err(|err| match err {
                SignerError::KeyNotFound => KeyError::KeyNotFound,
                _ => KeyError::Signer(err),
            });

            if let Err(err) = &res {
                warn!(
                    "[{}] Failed to destroy public key with ID {}: {}",
                    self.name, key_id, err
                );
            }
        }

        // try deleting the private key
        if let Ok(priv_handle) = self.find_key(&internal_key_id, ObjectClass::PRIVATE_KEY) {
            let res2 = self.destroy_key_by_handle(priv_handle).map_err(|err| match err {
                SignerError::KeyNotFound => KeyError::KeyNotFound,
                _ => KeyError::Signer(err),
            });

            if let Err(err) = &res2 {
                warn!(
                    "[{}] Failed to destroy private key with ID {}: {}",
                    self.name, key_id, err
                );
            }

            res = res.and(res2);
        }

        // remove the key from the signer mapper as well
        if let Some(signer_handle) = self.handle.read().unwrap().as_ref() {
            let res3 = self
                .mapper
                .remove_key(signer_handle, key_id)
                .map_err(|err| KeyError::Signer(SignerError::Other(err.to_string())));

            if let Err(err) = &res3 {
                warn!(
                    "[{}] Failed to remove mapping for key with ID {}: {}",
                    self.name, key_id, err
                );
            }

            res = res.and(res3);
        }

        res
    }

    pub fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SigningError<SignerError>> {
        let internal_key_id = self.lookup_key_id(key_id)?;
        let priv_handle = self
            .find_key(&internal_key_id, ObjectClass::PRIVATE_KEY)
            .map_err(|err| match err {
                KeyError::KeyNotFound => SigningError::KeyNotFound,
                KeyError::Signer(err) => SigningError::Signer(err),
            })?;

        self.sign_with_key(priv_handle, algorithm, data.as_ref())
            .map_err(SigningError::Signer)
    }

    pub fn sign_one_off<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: Alg,
        data: &D,
    ) -> Result<(Signature<Alg>, PublicKey), SignerError> {
        let (key, pub_handle, priv_handle, _) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature_res = self
            .sign_with_key(priv_handle, algorithm, data.as_ref())
            .map_err(|err| SignerError::Pkcs11Error(format!("One-off signing of data failed: {}", err)));

        let _ = self.destroy_key_by_handle(pub_handle);
        let _ = self.destroy_key_by_handle(priv_handle);

        let signature = signature_res?;

        Ok((signature, key))
    }
}

// --------------------------------------------------------------------------------------------------------------------
// Retry with backoff related helper impls/fns:
// --------------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
enum InternalConnError {
    Pkcs11Error(Pkcs11Error),
    SignerError(SignerError),
}

impl std::fmt::Display for InternalConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalConnError::Pkcs11Error(v) => v.fmt(f),
            InternalConnError::SignerError(v) => v.fmt(f),
        }
    }
}

impl From<Pkcs11Error> for InternalConnError {
    fn from(v: Pkcs11Error) -> Self {
        InternalConnError::Pkcs11Error(v)
    }
}

impl From<SignerError> for InternalConnError {
    fn from(v: SignerError) -> Self {
        InternalConnError::SignerError(v)
    }
}

impl From<InternalConnError> for SignerError {
    fn from(v: InternalConnError) -> Self {
        match v {
            InternalConnError::Pkcs11Error(v) => SignerError::Pkcs11Error(v.to_string()),
            InternalConnError::SignerError(v) => v,
        }
    }
}

impl From<backoff::Error<InternalConnError>> for InternalConnError {
    fn from(v: backoff::Error<InternalConnError>) -> Self {
        match v {
            backoff::Error::Permanent(err) => err,
            backoff::Error::Transient { err, .. } => err,
        }
    }
}

fn retry_on_transient_pkcs11_error(err: Pkcs11Error) -> backoff::Error<InternalConnError> {
    if is_transient_error(&err) {
        backoff::Error::transient(err.into())
    } else {
        backoff::Error::Permanent(err.into())
    }
}

fn retry_on_transient_signer_error(err: SignerError) -> backoff::Error<InternalConnError> {
    match err {
        SignerError::TemporarilyUnavailable => backoff::Error::transient(err.into()),
        _ => backoff::Error::Permanent(err.into()),
    }
}

fn retry_on_transient_error(err: InternalConnError) -> backoff::Error<InternalConnError> {
    match err {
        InternalConnError::Pkcs11Error(err) => retry_on_transient_pkcs11_error(err),
        InternalConnError::SignerError(err) => retry_on_transient_signer_error(err),
    }
}

fn is_transient_error(err: &Pkcs11Error) -> bool {
    match err {
        Pkcs11Error::NotSupported
        | Pkcs11Error::NullFunctionPointer
        | Pkcs11Error::LibraryLoading(_)
        | Pkcs11Error::TryFromInt(_)
        | Pkcs11Error::TryFromSlice(_)
        | Pkcs11Error::NulError(_)
        | Pkcs11Error::InvalidValue
        | Pkcs11Error::PinNotSet => {
            // The Rust `pkcs11` crate had a serious problem such as the loaded library not exporting a required
            // function or that it was asked to initialize an already initialized library.
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
            match err {
                cryptoki::error::RvError::ActionProhibited => false,
                cryptoki::error::RvError::ArgumentsBad => false, // resubmitting the same bad arguments will just fail again
                cryptoki::error::RvError::AttributeReadOnly => false, // for attributes that are always read only retrying will not succeed
                cryptoki::error::RvError::AttributeSensitive => false,
                cryptoki::error::RvError::AttributeTypeInvalid => false,
                cryptoki::error::RvError::AttributeValueInvalid => false,
                cryptoki::error::RvError::BufferTooSmall => false,
                cryptoki::error::RvError::Cancel => false,
                cryptoki::error::RvError::CantLock => false,
                cryptoki::error::RvError::CryptokiAlreadyInitialized => false,
                cryptoki::error::RvError::CryptokiNotInitialized => false,
                cryptoki::error::RvError::CurveNotSupported => false,
                cryptoki::error::RvError::DataInvalid => false,
                cryptoki::error::RvError::DataLenRange => false,
                cryptoki::error::RvError::DeviceError => true, // some error but we don't know what so could be transient
                cryptoki::error::RvError::DeviceMemory => true, // maybe the token frees up some memory such that a retry succeeds?
                cryptoki::error::RvError::DeviceRemoved => true, // not present at the time the function was executed but might be later
                cryptoki::error::RvError::DomainParamsInvalid => false,
                cryptoki::error::RvError::EncryptedDataInvalid => false,
                cryptoki::error::RvError::EncryptedDataLenRange => false,
                cryptoki::error::RvError::ExceededMaxIterations => false,
                cryptoki::error::RvError::FipsSelfTestFailed => false,
                cryptoki::error::RvError::FunctionCanceled => false,
                cryptoki::error::RvError::FunctionFailed => true, // the spec says the situation is not necessarily totally hopeless
                cryptoki::error::RvError::FunctionNotParallel => false,
                cryptoki::error::RvError::FunctionNotSupported => false,
                cryptoki::error::RvError::FunctionRejected => false,
                cryptoki::error::RvError::GeneralError => false,
                cryptoki::error::RvError::HostMemory => true,
                cryptoki::error::RvError::InformationSensitive => false,
                cryptoki::error::RvError::KeyChanged => false,
                cryptoki::error::RvError::KeyFunctionNotPermitted => false,
                cryptoki::error::RvError::KeyHandleInvalid => false,
                cryptoki::error::RvError::KeyIndigestible => false,
                cryptoki::error::RvError::KeyNeeded => false,
                cryptoki::error::RvError::KeyNotNeeded => false,
                cryptoki::error::RvError::KeyNotWrappable => false,
                cryptoki::error::RvError::KeySizeRange => false,
                cryptoki::error::RvError::KeyTypeInconsistent => false,
                cryptoki::error::RvError::KeyUnextractable => false,
                cryptoki::error::RvError::LibraryLoadFailed => false,
                cryptoki::error::RvError::MechanismInvalid => false,
                cryptoki::error::RvError::MechanismParamInvalid => false,
                cryptoki::error::RvError::MutexBad => false, // should never happen so consider it fatal?
                cryptoki::error::RvError::MutexNotLocked => false, // should never happen so consider it fatal?
                cryptoki::error::RvError::NeedToCreateThreads => false,
                cryptoki::error::RvError::NewPinMode => false,
                cryptoki::error::RvError::NextOtp => false,
                cryptoki::error::RvError::NoEvent => false,
                cryptoki::error::RvError::ObjectHandleInvalid => false,
                cryptoki::error::RvError::OperationActive => true, // the active operation might finish thereby permitting a retry to succeed
                cryptoki::error::RvError::OperationNotInitialized => false,
                cryptoki::error::RvError::PinExpired => false,
                cryptoki::error::RvError::PinIncorrect => true, // maybe the operator misconfigured the token and will fix it
                cryptoki::error::RvError::PinInvalid => false,
                cryptoki::error::RvError::PinLenRange => false,
                cryptoki::error::RvError::PinLocked => false,
                cryptoki::error::RvError::PinTooWeak => false,
                cryptoki::error::RvError::PublicKeyInvalid => false,
                cryptoki::error::RvError::RandomNoRng => false,
                cryptoki::error::RvError::RandomSeedNotSupported => false,
                cryptoki::error::RvError::SavedStateInvalid => false,
                cryptoki::error::RvError::SessionClosed => true, // maybe on retry we open a new session and succeed?
                cryptoki::error::RvError::SessionCount => true, // if a session closes it might be possible on retry for a session open to succeed
                cryptoki::error::RvError::SessionExists => false,
                cryptoki::error::RvError::SessionHandleInvalid => false,
                cryptoki::error::RvError::SessionParallelNotSupported => false,
                cryptoki::error::RvError::SessionReadOnly => false,
                cryptoki::error::RvError::SessionReadOnlyExists => true, // will succeed on retry if the conflicting SO session logs out
                cryptoki::error::RvError::SessionReadWriteSoExists => true, // will succeed on retry if the conflicting SO session logs out
                cryptoki::error::RvError::SignatureInvalid => false,
                cryptoki::error::RvError::SignatureLenRange => false,
                cryptoki::error::RvError::SlotIdInvalid => true, // maybe we tried accessing the slot just before it is created?
                cryptoki::error::RvError::StateUnsaveable => true, // the spec doesn't seem to rule out this being a temporary condition
                cryptoki::error::RvError::TemplateIncomplete => false,
                cryptoki::error::RvError::TemplateInconsistent => false,
                cryptoki::error::RvError::TokenNotPresent => true, // not present at the time the function was executed but might be later
                cryptoki::error::RvError::TokenNotRecognized => false,
                cryptoki::error::RvError::TokenWriteProtected => true, // maybe the write protection is a transient condition?
                cryptoki::error::RvError::UnwrappingKeyHandleInvalid => false,
                cryptoki::error::RvError::UnwrappingKeySizeRange => false,
                cryptoki::error::RvError::UnwrappingKeyTypeInconsistent => false,
                cryptoki::error::RvError::UserAlreadyLoggedIn => true, // maybe another client was is busy logging out so try again?
                cryptoki::error::RvError::UserAnotherAlreadyLoggedIn => true,
                cryptoki::error::RvError::UserNotLoggedIn => false,
                cryptoki::error::RvError::UserPinNotInitialized => true, // maybe the operator will initialize the PIN
                cryptoki::error::RvError::UserTooManyTypes => true, // maybe some sessions are terminated while retrying permitting us to succeed?
                cryptoki::error::RvError::UserTypeInvalid => true,  // maybe the operator will fix the users type
                cryptoki::error::RvError::VendorDefined => true, // we have no way of knowing what this kind of failure is, maybe it is transient
                cryptoki::error::RvError::WrappedKeyInvalid => false,
                cryptoki::error::RvError::WrappedKeyLenRange => false,
                cryptoki::error::RvError::WrappingKeyHandleInvalid => false,
                cryptoki::error::RvError::WrappingKeySizeRange => false,
                cryptoki::error::RvError::WrappingKeyTypeInconsistent => false,
            }
        }
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

impl From<ProbeError<SignerError>> for InternalConnError {
    fn from(err: ProbeError<SignerError>) -> Self {
        err.into()
    }
}

impl From<SignerError> for ProbeError<SignerError> {
    fn from(err: SignerError) -> Self {
        ProbeError::CallbackFailed(err)
    }
}

macro_rules! integer_to_slot_id {
    ($deserialize:ident, $type:ident) => {
        fn $deserialize<E>(self, v: $type) -> Result<SlotIdOrLabel, E>
        where
            E: serde::de::Error,
        {
            Ok(SlotIdOrLabel::Id(u64::try_from(v).map_err(|_| {
                serde::de::Error::custom("not a valid PKCS#11 slot ID")
            })?))
        }
    };
}

// Based on https://serde.rs/string-or-struct.html
fn slot_id_or_label<'de, D>(deserializer: D) -> Result<SlotIdOrLabel, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UintOrString(PhantomData<fn() -> SlotIdOrLabel>);

    impl<'de> Visitor<'de> for UintOrString {
        type Value = SlotIdOrLabel;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("PKCS#11 unsigned integer slot ID or string label")
        }

        fn visit_str<E>(self, value: &str) -> Result<SlotIdOrLabel, E>
        where
            E: serde::de::Error,
        {
            Ok(SlotIdOrLabel::Label(value.to_string()))
        }

        integer_to_slot_id!(visit_u8, u8);
        integer_to_slot_id!(visit_u16, u16);
        integer_to_slot_id!(visit_u32, u32);
        integer_to_slot_id!(visit_u64, u64);
        integer_to_slot_id!(visit_i8, i8);
        integer_to_slot_id!(visit_i16, i16);
        integer_to_slot_id!(visit_i32, i32);
        integer_to_slot_id!(visit_i64, i64);
    }

    deserializer.deserialize_any(UintOrString(PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configure_using_slot_id() {
        let config_str = r#"
            lib_path = "dummy path"
            slot = 1234
        "#;
        let config: Pkcs11SignerConfig = toml::from_str(config_str).unwrap();
        assert!(matches!(config.slot, SlotIdOrLabel::Id(1234)));
    }

    #[test]
    fn configure_using_slot_label() {
        let config_str = r#"
            lib_path = "dummy path"
            slot = "well well well"
        "#;
        let config: Pkcs11SignerConfig = toml::from_str(config_str).unwrap();
        let expected_label = "well well well".to_string();
        assert!(matches!(config.slot, SlotIdOrLabel::Label(label) if label == expected_label));
    }

    #[test]
    fn disallow_configure_using_negative_slot_id() {
        let config_str = r#"
            lib_path = "dummy path"
            slot = -1234
        "#;
        let err = toml::from_str::<Pkcs11SignerConfig>(config_str).unwrap_err();
        assert!(err.contains("not a valid PKCS#11 slot ID"))
    }

    #[test]
    fn default_key_attributes_are_backward_compatible() {
        let config_str = r#"
            lib_path = "dummy path"
            slot = 1234
        "#;
        let config = toml::from_str::<Pkcs11SignerConfig>(config_str).unwrap();

        let attrs = config.public_key_attributes.to_vec();
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Modifiable(_))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Private(true))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Private(false))));

        let attrs = config.private_key_attributes.to_vec();
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Extractable(false))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Extractable(true))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Modifiable(_))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Private(true))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Private(false))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Sensitive(true))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Sensitive(false))));
    }

    #[test]
    fn default_key_attributes_can_be_overriden() {
        let config_str = r#"
            lib_path = "dummy path"
            slot = 1234

            [public_key_attributes]
            CKA_MODIFIABLE = true
            CKA_PRIVATE = false

            [private_key_attributes]
            CKA_EXTRACTABLE = true
            CKA_MODIFIABLE = false
            CKA_SENSITIVE = false
            CKA_PRIVATE = false 
        "#;
        let config = toml::from_str::<Pkcs11SignerConfig>(config_str).unwrap();

        let attrs = config.public_key_attributes.to_vec();
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Modifiable(true))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Private(false))));

        let attrs = config.private_key_attributes.to_vec();
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Extractable(true))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Modifiable(false))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Private(false))));
        assert!(attrs.iter().any(|attr| matches!(attr, Attribute::Sensitive(false))));
    }

    #[test]
    fn overriding_key_attributes_sets_others_to_pkcs11_default_if_not_specified() {
        let config_str = r#"
            lib_path = "dummy path"
            slot = 1234
            public_key_attributes = {}
            private_key_attributes = {}
        "#;
        let config = toml::from_str::<Pkcs11SignerConfig>(config_str).unwrap();

        let attrs = config.public_key_attributes.to_vec();
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Modifiable(_))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Private(_))));

        let attrs = config.private_key_attributes.to_vec();
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Extractable(_))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Private(_))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Sensitive(_))));
        assert!(!attrs.iter().any(|attr| matches!(attr, Attribute::Modifiable(_))));
    }
}
