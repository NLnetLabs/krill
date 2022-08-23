use std::sync::Arc;
use std::{collections::HashMap, sync::RwLock};

use rpki::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::{
    crypto::{
        dispatch::{signerinfo::SignerMapper, signerprovider::SignerProvider},
        signers::error::SignerError,
        SignerHandle,
    },
    error::Error,
    KrillResult,
};

#[cfg(feature = "hsm")]
use crate::commons::crypto::dispatch::error::ErrorString;

/// Manages multiple Signers and routes requests to the appropriate Signer.
///
/// SignerRouter:
///   - Creates the appropriate [Signer] implementations according to configuration.
///   - Handles registration of [Signer] instances with the [SignerMapper].
///   - Dispatches requests to the correct [Signer] instance, either because the request specified a [KeyIdentifier]
///     which is owned by a particular [Signer] instance, or because the kind of request dictates the kind of [Signer]
///     that should handle it (e.g. one-off signing may be handled by a different [Signer] than handles new key
///     creation).
///
/// Note: If the `hsm` feature is not enabled all requests are routed to an instance of the [OpenSslSigner] for
/// backward compatibility with the behaviour of Krill before the introduction of the feature and the [SignerMapper] is
/// not created.
///
/// To avoid the complexities of dynamic dispatch in Rust we use enum based dispatch instead, as we know at compile time
/// which implementations of the [Signer] trait exist. The code noise caused by doing enum based dispatch is wrapped up
/// in the [SignerProvider] struct so we can focus on the business logic here instead.
///
/// [SignerProvider] instances are wrapped in [Arc] so that we can "assign" the same signer to multiple different
/// "roles" (default signer, one-off signer, etc).
///
/// Additional complexity is introduced by the need to wrap the [Signer]s in a lock due to the use of `&mut` by the
/// [Signer] trait on the `create_key()` and `destroy_key()` functions. The latest, not yet released, version of the
/// `rpki-rs` crate which defines the [Signer] trait removes the `&mut` from the trait and so we will be able to remove
/// these locks and instead use interior mutability inside the [Signer] implementations as appropriate/necessary rather
/// than lock the entire [Signer]. Even if that is released we will not make those changes in the current code however
/// as that will introduce too many changes in one PR. See https://github.com/NLnetLabs/rpki-rs/issues/161 and
/// https://github.com/NLnetLabs/rpki-rs/pull/162 for more information.
///
/// Further, a signer may not be available at the time we wish to use it, perhaps it is down or being slow or a network
/// or configuration issue prevents us connecting to it at that time. Signers are therefore maintained in two distinct
/// sets: pending and active. Signers start in the pending set and are promoted to the active set once we are able to
/// verify that we can connect to and use them and determine which [SignerMapper] [Handle] they should be assigned.
#[derive(Debug)]
pub struct SignerRouter {
    /// The signer to use for creating new keys.
    ///
    /// Exceptions:
    ///   - One-off signing keys are NOT created by the default signer. See `one_off_signer` below.
    ///   - Random numbers are always generated using OpenSSL.
    default_signer: Arc<SignerProvider>,

    /// The signer to create, sign with and destroy a one-off key.
    ///
    /// As the security of a HSM isn't needed for one-off keys, and HSMs are slow, by default this should be an instance
    /// of [OpenSslSigner]. However, if users think the perceived extra security is warranted let them use a different
    /// signer for one-off keys if that's what they want.
    one_off_signer: Arc<SignerProvider>,

    /// A mechanism for identifying the signer [Handle] that owns the key with a particular [KeyIdentifier].
    ///
    /// Used to route requests to the signer that possesses the key. If a key was created using a signer that is no
    /// longer present in the config file then the [SignerMapper] may return a [Handle] which is not present in the
    /// `active_signers` set (see below) and thus for which we thus have no way of using the key.
    ///
    /// Conversely, if a key was deleted from the signer/HSM by an external entity without our knowledge then the
    /// [SignerMapper] may return a [Handle] for a signer which no longer possesses the key.
    ///
    /// A reference to the [SignerMapper] is also given to each [Signer] so that it can register the mapping of newly
    /// created keys by their [KeyIdentifier] to their [Signer] implementation specific internal key identifier, and
    /// in reverse to lookup the internal key identifier from A given [KeyIdentifier].
    signer_mapper: Option<Arc<SignerMapper>>,

    /// A lookup table for resolving a signer [Handle] to its associated [SignerProvider] instance.
    ///
    /// Used for any operation which must be routed to the signer that owns the key, e.g. key deletion and signing
    /// (except one-off signing). First the []
    ///
    /// If a signer was used in the past to create a key but that signer is no longer present in the Krill config file
    /// it will not be present in this map and will thus not be usable. While we could keep a record of connection
    /// details for used signers even once they are removed from the config file we don't do that, the operator must
    /// ensure correct connection details are present in the config file. There are multiple reasons for this:
    /// connection details likely include secrets such as client certificates, keys, usernames and passwords; an
    /// operator may no longer wish to or have the right to use a particular signer/HSM; once we support multi-node
    /// deployment connection details to the signer/HSM may vary from one node to another so there is no single correct
    /// set of connection details to store in the history, e.g. if the HSM is clustered and each Krill node uses its
    /// nearest/same subnet HSM instance which has a different IP address from the HSM instance used by another Krill
    /// node in another subnet).
    ///
    /// This lookup table includes at least the default and one off signers and may also include other signers defined
    /// in the config file which were used to create keys in the past which are still in use.
    ///
    /// [SignerProvider] instances are moved to this set from the `pending_signers` set once we are able to confirm that
    /// we can connect to them and can identify the correct signer [Handle] used by the [SignerMapper] to associate with
    /// keys created by that signer.
    active_signers: RwLock<HashMap<SignerHandle, Arc<SignerProvider>>>,

    /// The set of [SignerProvider] instances that are configured but not yet confirmed to be usable. All signers start
    /// off in this set and are moved to the `active_signers` set as soon as we are able to confirm them. See
    /// `active_signers` above.
    #[cfg(feature = "hsm")]
    pending_signers: RwLock<Vec<Arc<SignerProvider>>>,
}

impl SignerRouter {
    pub fn build(signer_mapper: Option<Arc<SignerMapper>>, mut signers: Vec<SignerProvider>) -> KrillResult<Self> {
        // Keep a mapping of signer mapper handle to signer provider. Fill it in as and when signers become ready at
        // which point their signer mapper handle will be known.
        let active_signers = RwLock::new(HashMap::new());

        // One and only one signer should be the default. The default signer is used for operations that don't concern
        // an existing key, i.e. key creation and one-off signing.
        // Create the signers
        let mut default_signer: Option<Arc<SignerProvider>> = None;
        let mut one_off_signer: Option<Arc<SignerProvider>> = None;
        let mut all_signers = Vec::new();

        for signer in signers.drain(..) {
            let signer = Arc::new(signer);
            if signer.is_default_signer() {
                Self::set_once(&mut default_signer, signer.clone())
                    .map_err(|_| Error::ConfigError("There must only be one default signer".to_string()))?;
            } else if signer.is_one_off_signer() {
                Self::set_once(&mut one_off_signer, signer.clone())
                    .map_err(|_| Error::ConfigError("There must only be one one-off signer".to_string()))?;
            }
            all_signers.push(signer.clone());
        }

        let default_signer = default_signer.unwrap();

        #[cfg(feature = "hsm")]
        let pending_signers = RwLock::new(all_signers);

        Ok(SignerRouter {
            default_signer: default_signer.clone(),
            one_off_signer: one_off_signer.unwrap_or_else(|| default_signer.clone()),
            active_signers,
            #[cfg(feature = "hsm")]
            pending_signers,
            signer_mapper,
        })
    }

    pub fn get_mapper(&self) -> Option<Arc<SignerMapper>> {
        self.signer_mapper.clone()
    }

    pub fn get_active_signers(&self) -> HashMap<SignerHandle, Arc<SignerProvider>> {
        self.active_signers.read().unwrap().clone()
    }

    /// Locate the [SignerProvider] that owns a given [KeyIdentifier], if the signer is active.
    ///
    /// If the signer that owns the key has not yet been promoted from the pending set to the active set or if no
    /// the key was not created by us or was not registered with the [SignerMapper] then this lookup will fail with
    /// [SignerError::KeyNotFound].
    fn get_signer_for_key(&self, key_id: &KeyIdentifier) -> Result<Arc<SignerProvider>, SignerError> {
        match &self.signer_mapper {
            None => Ok(self.default_signer.clone()),
            Some(mapper) => {
                // Get the signer handle for the key
                let signer_handle = mapper
                    .get_signer_for_key(key_id)
                    .map_err(|_| SignerError::KeyNotFound)?;

                // Get the SignerProvider for the handle, if the signer is active
                let signer = self.active_signers.read().unwrap().get(&signer_handle).cloned();

                signer.ok_or(SignerError::KeyNotFound)
            }
        }
    }

    fn set_once(to_be_set: &mut Option<Arc<SignerProvider>>, new_value: Arc<SignerProvider>) -> Result<(), ()> {
        let old_value = to_be_set.replace(new_value);
        if old_value.is_some() {
            Err(())
        } else {
            Ok(())
        }
    }
}

/// When the "hsm" feature is enabled we can no longer assume that signers are immediately and always available as was
/// the case without the "hsm" feature when only the OpenSslSigner was supported. We therefore keep created signers on
/// standby in a "pending" set until we can verify that they are reachable and usable and can determine which
/// [SignerMapper] [Handle] to assign to them.
///
/// The Krill configuration file defines named signers with a type (openssl, kmip or pkcs#11) and type specific
/// settings (key dir path, hostname, port number, TLS certificate paths, username, password, slot id, etc) and assigns
/// signers one or more roles (default signer or one-off signer) either explicitly or by default.
///
/// Keys created using signers in a previous Krill process MUST have been registered by the signer with the
/// [SignerMapper] to indicate that the signer owns/possesses the key, and how to map from the [KeyIdentifier] to any
/// internal signer specific key id. When a new Krill process starts it will need to know for any given [KeyIdentifier]
/// which signer that was created should be used to work with the key. Rather than rely on operator supplied signer
/// names being stable or requiring operators to also maintain a stable signer id in the config, we instead "bind" the
/// signer backend to the signer handle that owns the set of keys stored in the [SignerMapper].
///
/// Binding is done by asking the signer on first use to create a new key pair for which we save the public key and the
/// signer specific internal private key identifier and combine them into a unique [Handle] for use by the signer with
/// the [SignerMapper]. We also store some metadata about the signer backend with the [Handle] in the [SignerMapper]
/// which allows us to see if the configuration and/or backend properties change over time.
///
/// On subsequent bindings we determine which signer maps to which [SignerMapper] [Handle] by extracting the private key
/// signer specific internal id from the [Handle] and asking each signer to sign a challenge using that key. We then
/// verify the signature using the saved public key. If the signer doesn't know the internal private key id or produces
/// an incorrect signature we know that the signer doesn't possess the binding key and thus likely isn't the signer we
/// should go to for the keys mapped to the [SignerMapper] [Handle] corresponding to the binding key.
///
/// By binding this way we both verify that the signer is usable (at least for key pair creation and signing) and that
/// we are using a signer that should have the keys we expect it to possess.
///
#[cfg(feature = "hsm")]
enum IdentifyResult {
    Unavailable,
    Corrupt,
    Identified(SignerHandle),
    Unusable,
    Unidentified,
}

#[cfg(feature = "hsm")]
enum RegisterResult {
    NotReady,
    ReadyVerified(SignerHandle),
    ReadyUnusable,
}

#[cfg(not(feature = "hsm"))]
impl SignerRouter {
    fn bind_ready_signers(&self) {}
}

#[cfg(feature = "hsm")]
impl SignerRouter {
    /// Check for and bind any ready signers.
    ///
    /// This function should return as quickly as possible. Newly bound signers will be moved from the pending set to
    /// the active set and be available immediately for use by the caller.
    ///
    /// This function should be invoked prior to attempting a signing operation so that the required signer is ready to
    /// handle the request. On error we log but do not return an error to the caller because the signer required by the
    /// caller may have been previously bound and this binding error may relate to a different signer. There's also
    /// nothing the caller can do if a binding failure occurs so receiving an error wouldn't be useful.
    ///
    /// If all signers have either already been bound or deemed to be permanently broken then this function will return
    /// immediately. In cases of temporary connectivity issues the signer handling code may deem it worth trying again
    /// but in such cases should implement retry and backoff such that not every attempt to use the signer is blocked
    /// trying to connect to the backend. Instead most attempts to use a temporarily unavailable signer should fail
    /// very quickly because the signer handling code is "sleeping" between binding attempts.
    fn bind_ready_signers(&self) {
        if let Err(err) = self.do_ready_signer_binding() {
            error!("Internal error: Unable to bind ready signers: {}", err);
        }
    }

    /// Attempt to bind pending signers.
    fn do_ready_signer_binding(&self) -> Result<(), String> {
        let num_pending_signers = self.pending_signers.read().unwrap().len();
        if num_pending_signers > 0 {
            trace!("Attempting to bind {} pending signers", num_pending_signers);

            // Fetch the handle of every signer previously created in the [SignerMapper] to see if any of the pending
            // signers is actually one of these or is a new signer that we haven't seen before.
            let candidate_handles = self.get_candidate_signer_handles()?;
            trace!("{} signers were previously registered", candidate_handles.len());

            // Block until we can get a write lock on the set of pending_signers as we will hopefully remove one or
            // more items from the set. Standard practice in Krill is to panic if a lock cannot be obtained.
            let mut pending_signers = self.pending_signers.write().unwrap();

            let mut abort_flag = false;

            // For each pending signer see if we can verify it and if so move it from the pending set to the active set.
            pending_signers.retain(|signer_provider| -> bool {
                if abort_flag {
                    return true;
                }

                let signer_name = signer_provider.get_name().to_string();

                // See if this is a known signer that whose signature matches the public key stored in the
                // [SignerMapper] for the signer.
                self.identify_signer(signer_provider, &candidate_handles)
                    .and_then(|verify_result| match verify_result {
                        IdentifyResult::Unavailable => {
                            // Signer isn't ready yet, leave it in the pending set and try again next time.
                            trace!("Signer '{}' is unavailable", signer_name);
                            Ok(true)
                        }
                        IdentifyResult::Identified(signer_handle) => {
                            // Signer is ready and verified, add it to the active set.
                            self.active_signers
                                .write()
                                .unwrap()
                                .insert(signer_handle, signer_provider.clone());
                            info!("Signer '{}' is ready for use", signer_name);
                            // And remove it from the pending set
                            Ok(false)
                        }
                        IdentifyResult::Unidentified => {
                            // Signer is ready and new, register it and move it to the active set
                            self.register_new_signer(signer_provider)
                                .map(|register_result| match register_result {
                                    RegisterResult::NotReady => {
                                        // Strange, it was ready just now when we verified it ... leave it in the
                                        // pending set and try again next time.
                                        trace!("Signer '{}' is not ready", signer_name);
                                        true
                                    }
                                    RegisterResult::ReadyVerified(signer_handle) => {
                                        // Signer is ready and verified, add it to the active set.
                                        self.active_signers
                                            .write()
                                            .unwrap()
                                            .insert(signer_handle, signer_provider.clone());
                                        info!("Signer '{}' is ready for use", signer_name);
                                        // And remove it from the pending set
                                        false
                                    }
                                    RegisterResult::ReadyUnusable => {
                                        // Signer registration failed, remove it from the pending set
                                        warn!("Signer '{}' could not be registered: signer is not usable", signer_name);
                                        false
                                    }
                                })
                        }
                        IdentifyResult::Unusable => {
                            // Signer is ready and unusable, remove it from the pending set
                            warn!("Signer '{}' could not be identified: signer is not usable", signer_name);
                            Ok(false)
                        }
                        IdentifyResult::Corrupt => {
                            // This case should never happen as this variant is handled in the called code
                            Err(ErrorString::new("Internal error: invalid handle"))
                        }
                    })
                    .unwrap_or_else(|err| {
                        error!("Signer '{}' could not be bound: {}. Aborting.", signer_name, *err);
                        abort_flag = true;
                        true
                    })
            });
        }

        Ok(())
    }

    /// Retrieves the set of signer handles known to the signer mapper.
    fn get_candidate_signer_handles(&self) -> Result<Vec<SignerHandle>, String> {
        // TODO: Filter out already bound signers?
        self.signer_mapper
            .as_ref()
            .unwrap()
            .get_signer_handles()
            .map_err(|err| format!("Failed to get signer handles: {}", err))
    }

    /// Checks if the signer identity can be shown to match one of the known signer public keys.
    fn identify_signer(
        &self,
        signer_provider: &Arc<SignerProvider>,
        candidate_handles: &[SignerHandle],
    ) -> Result<IdentifyResult, ErrorString> {
        let config_signer_name = signer_provider.get_name().to_string();

        // First try any candidate handle whose signer name matches the name of the signer provider then fall back to
        // trying other candidate handles, as perhaps the signer was renamed in the config file and no longer matches by
        // name but can still be matched by verifying a new signing signature with the stored public key of the other
        // candidate handles.
        let mut ordered_candidate_handles = Vec::new();
        for candidate_handle in candidate_handles {
            let stored_signer_name = self.signer_mapper.as_ref().unwrap().get_signer_name(candidate_handle)?;
            if stored_signer_name == config_signer_name {
                ordered_candidate_handles.insert(0, candidate_handle);
            } else {
                ordered_candidate_handles.push(candidate_handle);
            }
        }

        for candidate_handle in ordered_candidate_handles {
            let res = self.is_signer_identified_by_handle(signer_provider, candidate_handle)?;
            match res {
                IdentifyResult::Unidentified => {
                    // Signer was contacted and no errors were encountered but it doesn't know the key encoded in the
                    // given handle. Try again with the next handle.
                    continue;
                }
                IdentifyResult::Corrupt => {
                    // The candidate handle or signer public key is invalid so no key could be extracted to present to
                    // the signer. Try again with the next handle.
                    continue;
                }
                IdentifyResult::Unavailable | IdentifyResult::Unusable | IdentifyResult::Identified(_) => {
                    // No need to try the next candidate key, let the caller process the result.
                    return Ok(res);
                }
            }
        }

        // No errors occurred while contacting the signer but it doesn't know any of our candidate keys so this must be
        // a new signer that should be registered.
        Ok(IdentifyResult::Unidentified)
    }

    /// Checks if the signer identity matches the signer public key associated with a given signer handle.
    ///
    /// To match the signer backend must have access to a key whose signer internal key ID matches one we stored when
    /// the signer was previously registered, and when used to sign a challenge the signature must match the public
    /// key we have on record (also stored when the signer was previously registered).
    fn is_signer_identified_by_handle(
        &self,
        signer_provider: &Arc<SignerProvider>,
        candidate_handle: &SignerHandle,
    ) -> Result<IdentifyResult, ErrorString> {
        let handle_name = self.signer_mapper.as_ref().unwrap().get_signer_name(candidate_handle)?;
        let signer_name = signer_provider.get_name().to_string();
        trace!(
            "Attempting to identify signer '{}' using identity key stored for signer '{}'",
            signer_name,
            handle_name
        );

        let public_key = match self
            .signer_mapper
            .as_ref()
            .unwrap()
            .get_signer_public_key(candidate_handle)
        {
            Ok(res) => Ok(res),
            Err(err) => match err {
                crate::commons::error::Error::SignerError(err) => {
                    error!(
                        "Internal error: Identity public key for signer '{}' is invalid: {}",
                        handle_name, err
                    );
                    return Ok(IdentifyResult::Corrupt);
                }
                err => Err(err),
            },
        }?;

        let signer_private_key_id = self
            .signer_mapper
            .as_ref()
            .unwrap()
            .get_signer_private_key_internal_id(candidate_handle)?;

        let challenge = "Krill signer verification challenge".as_bytes();
        let signature = match signer_provider.sign_registration_challenge(&signer_private_key_id, challenge) {
            Err(SignerError::TemporarilyUnavailable) => {
                debug!("Signer '{}' could not be contacted", signer_name);
                return Ok(IdentifyResult::Unavailable);
            }
            Err(SignerError::KeyNotFound) => {
                debug!(
                    "Signer '{}' not matched: private key id '{}' not found",
                    signer_name, signer_private_key_id
                );
                return Ok(IdentifyResult::Unidentified);
            }
            Err(err) => {
                error!("Signer '{}' is unusable: {}", signer_name, err);
                return Ok(IdentifyResult::Unusable);
            }
            Ok(res) => res,
        };

        if public_key.verify(challenge, &signature).is_ok() {
            debug!("Signer '{}' is ready and known, binding", signer_name);
            let signer_info = signer_provider
                .get_info()
                .unwrap_or_else(|| "No signer info".to_string());

            signer_provider.set_handle(candidate_handle.clone());

            if let Err(err) = self
                .signer_mapper
                .as_ref()
                .unwrap()
                .change_signer_name(candidate_handle, &signer_name)
            {
                // This is unexpected and perhaps indicative of a deeper problem but log and keep going.
                error!(
                    "Internal error: Failed to change name of signer to '{}': {}",
                    signer_name, err
                );
            }
            if let Err(err) = self
                .signer_mapper
                .as_ref()
                .unwrap()
                .change_signer_info(candidate_handle, &signer_info)
            {
                // This is unexpected and perhaps indicative of a deeper problem but log and keep going.
                error!(
                    "Internal error: Failed to change info for signer '{}' to '{}': {}",
                    signer_name, signer_info, err
                );
            }

            debug!(
                "Signer '{}' bound to signer mapper handle '{}'",
                signer_name, candidate_handle
            );
        } else {
            debug!(
                "Signer '{}' not matched: incorrect signature created with private key '{}'",
                signer_name, signer_private_key_id
            );
        }

        Ok(IdentifyResult::Identified(candidate_handle.clone()))
    }

    /// Register a signer backend so that we can identify it later.
    ///
    /// Registration creates a key pair in the signer backend and stores the signer specific internal ID of the created
    /// private key and the content of the created public key. Registration also verifies that the signer is able to
    /// sign using the newly created private key such that the created signature matches the created public key.
    fn register_new_signer(&self, signer_provider: &Arc<SignerProvider>) -> Result<RegisterResult, ErrorString> {
        let signer_name = signer_provider.get_name().to_string();

        trace!("Attempting to register signer '{}'", signer_name);

        let (public_key, signer_private_key_id) = match signer_provider.create_registration_key() {
            Err(SignerError::TemporarilyUnavailable) => return Ok(RegisterResult::NotReady),
            Err(_) => return Ok(RegisterResult::ReadyUnusable),
            Ok(res) => res,
        };

        let challenge = "Krill signer verification challenge".as_bytes();
        let signature = match signer_provider.sign_registration_challenge(&signer_private_key_id, challenge) {
            Err(SignerError::TemporarilyUnavailable) => return Ok(RegisterResult::NotReady),
            Err(_) => return Ok(RegisterResult::ReadyUnusable),
            Ok(res) => res,
        };

        if public_key.verify(challenge, &signature).is_err() {
            error!("Signer '{}' challenge signature is invalid", signer_name);
            return Ok(RegisterResult::ReadyUnusable);
        }

        debug!("Signer '{}' is ready and new, binding", signer_name);

        let signer_info = signer_provider
            .get_info()
            .unwrap_or_else(|| "No signer info".to_string());

        let signer_handle = self.signer_mapper.as_ref().unwrap().add_signer(
            &signer_name,
            &signer_info,
            &public_key,
            &signer_private_key_id,
        )?;

        signer_provider.set_handle(signer_handle.clone());

        debug!("Signer '{}' bound to signer handle '{}'", signer_name, signer_handle);
        Ok(RegisterResult::ReadyVerified(signer_handle))
    }
}

impl Signer for SignerRouter {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        self.bind_ready_signers();
        self.default_signer.create_key(algorithm)
    }

    fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<Self::Error>> {
        self.bind_ready_signers();
        self.get_signer_for_key(key_id)?.get_key_info(key_id)
    }

    fn destroy_key(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<Self::Error>> {
        self.bind_ready_signers();
        self.get_signer_for_key(key_id)?.destroy_key(key_id)
    }

    fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SigningError<Self::Error>> {
        self.bind_ready_signers();
        self.get_signer_for_key(key_id)?.sign(key_id, algorithm, data)
    }

    fn sign_one_off<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: Alg,
        data: &D,
    ) -> Result<(Signature<Alg>, PublicKey), Self::Error> {
        self.bind_ready_signers();
        self.one_off_signer.sign_one_off(algorithm, data)
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.bind_ready_signers();
        openssl::rand::rand_bytes(target).map_err(SignerError::OpenSslError)
    }
}

#[cfg(all(test, feature = "hsm"))]
pub mod tests {
    use rpki::crypto::RpkiSignatureAlgorithm;

    use crate::{
        commons::crypto::{
            dispatch::signerprovider::SignerFlags,
            signers::mocksigner::{
                CreateRegistrationKeyErrorCb, FnIdx, MockSigner, MockSignerCallCounts, SignRegistrationChallengeErrorCb,
            },
        },
        test,
    };

    use super::*;

    fn create_signer_router(all_signers: &[Arc<SignerProvider>], signer_mapper: Arc<SignerMapper>) -> SignerRouter {
        SignerRouter {
            default_signer: all_signers[0].clone(),
            one_off_signer: all_signers[0].clone(),
            signer_mapper: Some(signer_mapper.clone()),
            active_signers: RwLock::new(HashMap::new()),
            pending_signers: RwLock::new(all_signers.to_vec()),
        }
    }

    #[test]
    pub fn verify_that_a_usable_signer_is_registered_and_can_be_used() {
        test::test_under_tmp(|d| {
            #[allow(non_snake_case)]
            let DEF_SIG_ALG = RpkiSignatureAlgorithm::default();

            // Build a mock signer that is contactable and usable for the SignerRouter
            let call_counts = Arc::new(MockSignerCallCounts::new());
            let signer_mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let mock_signer = MockSigner::new("mock signer", signer_mapper.clone(), call_counts.clone(), None, None);
            let mock_signer = Arc::new(SignerProvider::Mock(SignerFlags::default(), mock_signer));

            // Create a SignerRouter that uses the mock signer with the mock signer starting in the pending signer set.
            let router = create_signer_router(&[mock_signer.clone()], signer_mapper.clone());

            // No signers have been registered with the SignerMapper yet
            assert_eq!(0, signer_mapper.get_signer_handles().unwrap().len());

            // Verify that initially none of the functions in the mock signer have been called
            assert_eq!(0, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(0, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(0, call_counts.get(FnIdx::GetInfo));
            assert_eq!(0, call_counts.get(FnIdx::SetHandle));
            assert_eq!(0, call_counts.get(FnIdx::CreateKey));
            assert_eq!(0, call_counts.get(FnIdx::Sign));
            assert_eq!(0, call_counts.get(FnIdx::DestroyKey));

            // Try to use the SignerRouter to generate a random value. This should cause the SignerRouter to contact
            // the mock signer, ask it to create a registration key, verify that it can sign correctly with that key,
            // assign a signer mapper handle to the signer, then check for random number generation support and finally
            // actually generate the random number.
            let mut out_buf: [u8; 1] = [0; 1];
            router.rand(&mut out_buf).unwrap();
            assert_eq!(1, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(1, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(1, call_counts.get(FnIdx::GetInfo));
            assert_eq!(1, call_counts.get(FnIdx::SetHandle));

            // One signer has been registered with the SignerMapper now
            assert_eq!(1, signer_mapper.get_signer_handles().unwrap().len());

            // Ask for another random number. This time none of the registration steps should be performed as the signer
            // is already registered and active.
            router.rand(&mut out_buf).unwrap();

            // Check that we can create a new key with the mock signer via the SignerRouter and that the key gets
            // registered with the signer mapper.
            let key_identifier = router.create_key(PublicKeyFormat::Rsa).unwrap();
            assert!(signer_mapper.get_signer_for_key(&key_identifier).is_ok());
            assert_eq!(1, call_counts.get(FnIdx::CreateKey));

            // Check that we can sign with the SignerRouter using the Krill key identifier. The SignerRouter should
            // discover from the SignerMapper that the key belongs to the mock signer and so dispatch the signing
            // request to the mock signer.
            router.sign(&key_identifier, DEF_SIG_ALG, &out_buf).unwrap();
            assert_eq!(1, call_counts.get(FnIdx::Sign));

            // Throw the SignerRouter away and create a new one. This is like restarting Krill. Keep the mock signer as
            // otherwise we will lose its in-memory private key store. Keep the SignerMapper as the mock signer is
            // using it, and because destroying it and recreating it would just be like forcing it to re-read it's saved
            // state from disk (and we're not trying to test the AggregateStore here anyway!).
            let router = create_signer_router(&[mock_signer.clone()], signer_mapper.clone());

            // Try to use the SignerRouter to sign again. This time around the SignerMapper should find the existing
            // signer in its records and only ask the signer to sign the registration challenge, but not ask it to
            // create a registration key.
            router.sign(&key_identifier, DEF_SIG_ALG, &out_buf).unwrap();
            assert_eq!(1, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(2, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(2, call_counts.get(FnIdx::GetInfo));
            assert_eq!(2, call_counts.get(FnIdx::SetHandle));
            assert_eq!(2, call_counts.get(FnIdx::Sign));

            // Now delete the key and verify that we can no longer sign with it.
            router.destroy_key(&key_identifier).unwrap();
            assert_eq!(1, call_counts.get(FnIdx::DestroyKey));

            let err = router.sign(&key_identifier, RpkiSignatureAlgorithm::default(), &out_buf);
            // TODO: Should this error from the SignerRouter actually be SigningError::KeyNotFound instead of
            // SigningError::Signer(SignerError::KeyNotFound)?
            assert!(matches!(err, Err(SigningError::Signer(SignerError::KeyNotFound))));

            // The Sign call count is still 2 because the SignerRouter fails to determine which signer owns the key
            // and fails.
            assert_eq!(2, call_counts.get(FnIdx::Sign));

            // Now ask the mock signer to forget its registration key. After this the SignerRouter should fail to
            // verify it and require it to register anew.
            mock_signer.wipe_all_keys();

            // The mock signer still works for the moment because the SignerRouter doesn't do registration again as
            // it thinks it still has an active signer.
            let key_identifier = router.create_key(PublicKeyFormat::Rsa).unwrap();
            router.sign(&key_identifier, DEF_SIG_ALG, &out_buf).unwrap();

            assert_eq!(1, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(2, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(2, call_counts.get(FnIdx::CreateKey));
            assert_eq!(3, call_counts.get(FnIdx::Sign));

            // Throw away the SignerRouter again, thereby forcing the mock signer to be in the pending set again
            // instead of the ready set. Now the SignerRouter should register the mock signer again and we should end
            // up with a second signer in the SignerMapper as the ability to identify the first one has been lost
            // (because above we instructed the mock signer to wipe all its keys). As the SignerMapper contains an
            // existing signer the call count to sign_registration_challenge() in the mock signer will actually
            // increase twice because the SignerRouter will first challenge it to prove that it is the already
            // known signer. Without the identity key however the mock signer fails this identity check and is
            // registered again (and then sign challenged again, hence the double increment).
            let router = create_signer_router(&[mock_signer.clone()], signer_mapper.clone());

            let err = router.sign(&key_identifier, DEF_SIG_ALG, &out_buf);
            assert!(matches!(err, Err(SigningError::Signer(SignerError::KeyNotFound))));

            assert_eq!(2, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(4, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(3, call_counts.get(FnIdx::GetInfo));
            assert_eq!(3, call_counts.get(FnIdx::SetHandle));
            assert_eq!(3, call_counts.get(FnIdx::Sign));

            // Two signers have been registered with the SignerMapper by this point, one of which is now orphaned as
            // the keys that it knows about refer to a signer backend that is no longer able to prove that it is the
            // owner of these keys (because its identity key was deleted in the signer backend). Thus the SignerRouter
            // doesn't know which signer to forward requests to in order to work with the keys owned by the orphaned
            // signer.
            assert_eq!(2, signer_mapper.get_signer_handles().unwrap().len());
        });
    }

    #[test]
    pub fn verify_that_unusable_signers_are_neither_registered_nor_retried() {
        fn perm_unusable(_: &MockSignerCallCounts) -> Result<(), SignerError> {
            Err(SignerError::PermanentlyUnusable)
        }

        fn internal_error(_: &MockSignerCallCounts) -> Result<(), SignerError> {
            Err(SignerError::Other("internal error".to_string()))
        }

        fn temp_unavail(_: &MockSignerCallCounts) -> Result<(), SignerError> {
            Err(SignerError::TemporarilyUnavailable)
        }

        fn create_broken_signer(
            signer_mapper: Arc<SignerMapper>,
            call_counts: Arc<MockSignerCallCounts>,
            create_registration_key_error_cb: Option<CreateRegistrationKeyErrorCb>,
            sign_registration_challenge_error_cb: Option<SignRegistrationChallengeErrorCb>,
        ) -> Arc<SignerProvider> {
            Arc::new(SignerProvider::Mock(
                SignerFlags::default(),
                MockSigner::new(
                    "broken mock signer",
                    signer_mapper,
                    call_counts,
                    create_registration_key_error_cb,
                    sign_registration_challenge_error_cb,
                ),
            ))
        }

        fn create_broken_signers(sm: Arc<SignerMapper>, cc: Arc<MockSignerCallCounts>) -> Vec<Arc<SignerProvider>> {
            let mut broken_signers = Vec::new();
            broken_signers.push(create_broken_signer(sm.clone(), cc.clone(), Some(perm_unusable), None));
            broken_signers.push(create_broken_signer(sm.clone(), cc.clone(), Some(internal_error), None));
            broken_signers.push(create_broken_signer(sm.clone(), cc.clone(), Some(temp_unavail), None));
            broken_signers.push(create_broken_signer(sm.clone(), cc.clone(), None, Some(perm_unusable)));
            broken_signers.push(create_broken_signer(sm.clone(), cc.clone(), None, Some(internal_error)));
            broken_signers.push(create_broken_signer(sm.clone(), cc.clone(), None, Some(temp_unavail)));
            broken_signers
        }

        test::test_under_tmp(|d| {
            let call_counts = Arc::new(MockSignerCallCounts::new());
            let signer_mapper = Arc::new(SignerMapper::build(&d).unwrap());
            let broken_signers = create_broken_signers(signer_mapper.clone(), call_counts.clone());

            // Create a SignerRouter that has access to all of the broken signers
            let router = create_signer_router(broken_signers.as_slice(), signer_mapper.clone());

            // No signers have been registered with the SignerMapper yet
            assert_eq!(0, signer_mapper.get_signer_handles().unwrap().len());

            let mut rand_out: [u8; 1] = [0; 1];

            // Try to use the SignerRouter to generate a random value. This should cause the SignerRouter to contact
            // all of the mock signers, asking them to create a registration key, and if that succeeds to then verify
            // that the signer can sign correctly with that key. None of the broken signers will succeed at these steps
            // and so the counter of registered signers will remain at zero.
            router.rand(&mut rand_out).unwrap();

            // The number of attempts to register a signer should have increased by the number of signers.
            // Half of the signers should fail at the registration step, the other half at the challenge signing step.
            // So the number of signers that we succeeded in moving out of the pending set to the active set and
            // registering with the signer mapper should be zero.
            assert_eq!(6, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(3, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(0, signer_mapper.get_signer_handles().unwrap().len());

            //
            // Try again.
            //
            router.rand(&mut rand_out).unwrap();

            // The signers that were permanently unusable at registration should not be tried again.
            assert_eq!(6 + 2, call_counts.get(FnIdx::CreateRegistrationKey));

            // The signers that were permanently unusable at challenge signing should not be tried again.
            assert_eq!(3 + 1, call_counts.get(FnIdx::SignRegistrationChallenge));

            // And the end result should be that no signers were registered with the signer mapper.
            assert_eq!(0, signer_mapper.get_signer_handles().unwrap().len());
        });
    }

    #[test]
    pub fn verify_that_temporarily_unavailable_signers_are_registered_when_available() {
        fn temp_unavail(call_counts: &MockSignerCallCounts) -> Result<(), SignerError> {
            if call_counts.get(FnIdx::CreateRegistrationKey) == 1 {
                // Fail the first time registration is attempted
                Err(SignerError::TemporarilyUnavailable)
            } else {
                // Succeed on subsequent attempts
                Ok(())
            }
        }

        test::test_under_tmp(|d| {
            let call_counts = Arc::new(MockSignerCallCounts::new());
            let signer_mapper = Arc::new(SignerMapper::build(&d).unwrap());

            let temp_unavail_signer = Arc::new(SignerProvider::Mock(
                SignerFlags::default(),
                MockSigner::new(
                    "mock temporararily unavailable signer",
                    signer_mapper.clone(),
                    call_counts.clone(),
                    Some(temp_unavail),
                    None,
                ),
            ));

            // Create a SignerRouter that uses the mock signer with the mock signer starting in the pending signer set.
            let router = create_signer_router(&[temp_unavail_signer], signer_mapper.clone());

            // No signers have been registered with the SignerMapper yet
            assert_eq!(0, signer_mapper.get_signer_handles().unwrap().len());

            let mut rand_out: [u8; 1] = [0; 1];

            // Try to use the SignerRouter to generate a random value. This should cause the SignerRouter to contact
            // the mock signer, ask it to create a registration key, verify that it can sign correctly with that key,
            // assign a signer mapper handle to the signer, then check for random number generation support and finally
            // actually generate the random number. This should fail the first time due to the logic imlpemented by the
            // temp_avail() function above.
            router.rand(&mut rand_out).unwrap();

            // The number of attempts to register a signer should have increased by one.
            assert_eq!(1, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(0, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(0, signer_mapper.get_signer_handles().unwrap().len());

            //
            // Try again. We should succeed the second time due to the logic imlpemented by the temp_avail() function
            // above.
            //
            router.rand(&mut rand_out).unwrap();

            // We should be all green now
            assert_eq!(2, call_counts.get(FnIdx::CreateRegistrationKey));
            assert_eq!(1, call_counts.get(FnIdx::SignRegistrationChallenge));
            assert_eq!(1, signer_mapper.get_signer_handles().unwrap().len());
        });
    }
}
