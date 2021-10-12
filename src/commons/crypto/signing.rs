//! Support for signing mft, crl, certificates, roas..
//! Common objects for TAs and CAs
use std::{
    sync::{Arc, RwLock},
    {convert::TryFrom, path::Path},
};

use bytes::Bytes;

use rpki::{
    repository::{
        cert::{Cert, KeyUsage, Overclaim, TbsCert},
        crl::{Crl, CrlEntry, TbsCertList},
        crypto::{
            signer::KeyError, DigestAlgorithm, KeyIdentifier, PublicKey, PublicKeyFormat, Signature,
            SignatureAlgorithm, Signer, SigningError,
        },
        csr::Csr,
        manifest::{FileAndHash, Manifest, ManifestContent},
        roa::{Roa, RoaBuilder},
        rta,
        sigobj::SignedObjectBuilder,
        x509::{Name, Serial, Time, Validity},
    },
    uri,
};

use crate::{
    commons::{
        api::{IssuedCert, RcvdCert, ReplacedObject, RepoInfo, RequestResourceLimit, ResourceSet},
        crypto::{
            self,
            signers::{error::SignerError, softsigner::OpenSslSigner},
            CryptoResult,
        },
        error::Error,
        util::AllowedUri,
        KrillResult,
    },
    daemon::ca::CertifiedKey,
};

#[cfg(feature = "hsm")]
use crate::commons::{
    api::Handle,
    crypto::signers::{kmip::KmipSigner, signerinfo::SignerMapper},
};

#[cfg(feature = "hsm")]
use std::collections::HashMap;

//------------ SignerProvider ------------------------------------------------

/// Dispatchers Signer requests to a particular implementation of the Signer trait.
///
/// Named and modelled after the similar AuthProvider concept that already exists in Krill.
#[allow(dead_code)] // Needed as we currently only ever construct one variant
#[derive(Clone, Debug)]
enum SignerProvider {
    OpenSsl(OpenSslSigner),

    #[cfg(feature = "hsm")]
    Kmip(KmipSigner),
}

impl SignerProvider {
    pub fn supports_random(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(signer) => signer.supports_random(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.supports_random(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn create_registration_key(&mut self) -> Result<(PublicKey, String), SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.create_registration_key(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.create_registration_key(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        internal_key_id: String,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_registration_challenge(internal_key_id, challenge),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign_registration_challenge(internal_key_id, challenge),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_handle(&self) -> Option<Handle> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_handle(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_handle(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn set_handle(&mut self, handle: Handle) {
        match self {
            SignerProvider::OpenSsl(signer) => signer.set_handle(handle),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.set_handle(handle),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_name(&self) -> &str {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_name(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_name(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_info(&self) -> Option<String> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_info(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_info(),
        }
    }
}

impl Signer for SignerProvider {
    type KeyId = KeyIdentifier;

    type Error = SignerError;

    fn create_key(&mut self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.create_key(algorithm),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.create_key(algorithm),
        }
    }

    fn get_key_info(&self, key: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_key_info(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_key_info(key),
        }
    }

    fn destroy_key(&mut self, key: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.destroy_key(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.destroy_key(key),
        }
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign(key, algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign(key, algorithm, data),
        }
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_one_off(algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign_one_off(algorithm, data),
        }
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.rand(target),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.rand(target),
        }
    }
}

//------------ SignerRouter --------------------------------------------------

/// Manages multiple Signers and routes requests to the appropriate Signer.
#[derive(Clone, Debug)]
struct SignerRouter {
    // TODO: Remove the [RwLock] around the [SignerProvider] once the [Signer] trait is modified to delegate locking to
    // the implementation and is thus able to drop use of the `&mut self` argument which is what cause us to need the
    // `RwLock`. See: https://github.com/NLnetLabs/rpki-rs/issues/161
    /// The signer to use for creating new keys and generating random numbers.
    ///
    /// Exceptions:
    ///   - One-off signing keys are NOT created by the default signer. See `one_off_signer` below.
    ///   - Random numbers can only be generated by the default signer if it supports it. See `rand_fallback_signer`
    ///     below.
    default_signer: Arc<RwLock<SignerProvider>>,

    /// The signer to create, sign with an destroy a one-off key.
    ///
    /// As the security of a HSM isn't needed for one-off keys, and HSMs are slow, by default this should be an instance
    /// of [OpenSslSigner]. However, if users think the perceived extra security is warranted let them use a different
    /// signer for one-off keys if that's what they want.
    one_off_signer: Arc<RwLock<SignerProvider>>,

    /// The signer to use when a configured signer doesn't support generation of random numbers.
    rand_fallback_signer: Arc<RwLock<SignerProvider>>,

    /// A lookup table for resolving a signer [Handle] to its associated [SignerProvider] instance.
    ///
    /// Used for any operation which must be routed to the signer that owns the key, e.g. key deletion and signing
    /// (except one-off signing).
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
    /// This lookup table includes at least the default, one off and rand fallback signers and may also include other
    /// signers defined in the config file which were used to create keys in the past. Note: a signer can be "defined"
    /// by the configuration without being explicitly present in the config file, e.g. if it is the default for a
    /// setting which was not set in the config file.
    ///
    /// NOTE: Currently we're still using hard-coded signers, we don't yet have support for being configured from the
    /// config file.
    #[cfg(feature = "hsm")]
    signers_by_handle: Arc<RwLock<HashMap<Handle, Arc<RwLock<SignerProvider>>>>>,

    #[cfg(feature = "hsm")]
    signers_without_handle: Arc<RwLock<Vec<Arc<RwLock<SignerProvider>>>>>,

    /// A mechanism for identifying the signer [Handle] that created a particular [KeyIdentifier]].
    ///
    /// Used to route requests to the signer that possesses the key. If a key was created using a signer that is no
    /// longer present in the config file then the [SignerMapper] may return a [Handle] which is not present in
    /// `configured_signers` and thus for which we thus have no way of using the key.
    ///
    /// Conversely, if a key was deleted from the signer/HSM by an external entity without our knowledge then the
    /// [SignerMapper] may return a [Handle] for a signer which no longer possesses the key.
    #[cfg(feature = "hsm")]
    signer_mapper: Arc<SignerMapper>,
}

#[cfg(feature = "hsm")]
struct SignerRoleAssignments {
    default_signer: Arc<RwLock<SignerProvider>>,
    one_off_signer: Arc<RwLock<SignerProvider>>,
    rand_fallback_signer: Arc<RwLock<SignerProvider>>,
}

#[cfg(not(feature = "hsm"))]
impl SignerRouter {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        let openssl_signer = Arc::new(RwLock::new(SignerProvider::OpenSsl(OpenSslSigner::build(work_dir)?)));

        Ok(SignerRouter {
            default_signer: openssl_signer.clone(),
            one_off_signer: openssl_signer.clone(),
            rand_fallback_signer: openssl_signer,
        })
    }

    fn get_signer_for_key(&self, _key_id: &KeyIdentifier) -> Result<Arc<RwLock<SignerProvider>>, SignerError> {
        Ok(self.default_signer.clone())
    }
}

#[cfg(feature = "hsm")]
impl SignerRouter {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        // The types of signer to initialize, the details needed to initialize them and the intended purpose for each
        // signer (e.g. signer for past keys, currently used signer, signer to use for a key roll, etc.) should come
        // from the configuration file. SignerRouter combines that input with its own rules, e.g. to route a signing
        // request to the correct signer we will need to determine which signer possesses the signing key, and the
        // signer to use to create a new key depends on whether the key is one-off or not and whether or not it is
        // being created for a key roll.

        // TODO: Once it becomes possible to configure how an HSM is used by Krill we need to decide what the
        // defaults should be and what should be configurable or not concerning HSM usage, and to document why, if
        // permitted, it is acceptable to use local keys, signing & random number genration instead of the more
        // secure HSM based alternatives (if available).
        let signer_mapper = Arc::new(SignerMapper::build(work_dir)?);

        // We don't know the signer handles yet. The signer implementations have to work out their own signer handle
        // when they are ready. Signers are moved from the signer collection to the map once while running when asked
        // they by that point have determined their own handle.
        let signers_by_handle = Arc::new(RwLock::new(HashMap::new()));

        let roles = Self::build_signers(work_dir, signer_mapper.clone(), signers_by_handle.clone())?;

        // Having the same signer multiple times in this vector is less efficient but the impact is negligible and it
        // doesn't break anything if there are duplicates.
        let signers_without_handle = Arc::new(RwLock::new(vec![
            roles.default_signer.clone(),
            roles.one_off_signer.clone(),
            roles.rand_fallback_signer.clone(),
        ]));

        // TODO: Once we can configure ourselves from the configuration file, we also need to create any signers that
        // are defined in the config but which don't have an active role, i.e. only exist to work with keys created by
        // a still active signer but not one that we create new keys with.

        Ok(SignerRouter {
            default_signer: roles.default_signer,
            one_off_signer: roles.one_off_signer,
            rand_fallback_signer: roles.rand_fallback_signer,
            signers_by_handle,
            signers_without_handle,
            signer_mapper,
        })
    }

    #[cfg(not(feature = "hsm-tests"))]
    fn build_signers(
        work_dir: &Path,
        signer_mapper: Arc<SignerMapper>,
        _signers_by_handle: Arc<RwLock<HashMap<Handle, Arc<RwLock<SignerProvider>>>>>,
    ) -> KrillResult<SignerRoleAssignments> {
        // When the HSM feature is activated and we are not in test mode:
        //   - Use the HSM for key creation, signing, deletion, except for one-off keys.
        //   - Use the HSM for random number generation, if supported, else use the OpenSSL signer.
        //   - Use the OpenSSL signer for one-off keys.

        // TODO: When configuration file based setup is added the operator should choose the signer handle themselves
        // or else we need a way to generate handle for a given signer config block that remains stable across changes
        // to the configuration file settings.
        //
        // Keys created by the signer are associated with the signer handle. When later the key needs to be used we
        // need to locate the owning signer by the KeyIdentifier. This lookup will result in a handle which we can then
        // map back to the SignerProvider instance that we created for that handle when processing the configuration
        // file.
        //
        // If the name given by the operator to the signer in the configuration file is deemed to be undesirable or
        // worse factually incorrect and/or misleading (e.g. naming a signer OpenSSL when it is in fact a PKCS#11
        // powered connection to an AWS Cloud HSM) then the operator may want to change the "name" used for the signer
        // (the need for this depends a bit on where we will show this name, presumably it will/could appear in logs,
        // API, krillc and/or UI). If the Signer has a separate name to its handle we can permit the name to be
        // changed without changing the handle and thus keys owned by the signer can still be found.
        //
        // TODO: We could record the "type" (e.g. OpenSSL, PKCS#11 or KMIP) of the Signer in the Signer history then
        // when we create the Signer if it already exists but with a different "type" we could log a warning.
        //
        // TODO: If we find the KeyIdentifier but the found signer handle doesn't match any configured signer, should
        // we see if any of the configured signers exactly match a configured signer (which has a different name or
        // handle or perhaps no handle at all if we can make that work?). That require persisting key characteristics
        // of each configured signer that can be later matched against the config to determine that it is the same
        // actual signer. The name may be volatile, but so also may the PKCS#11 library path, server IP address or
        // FQDN, and access credentials too. What does that leave that we can use to determine that a given signer
        // matches the one in the configuration file? One option might be if the backend is able to report a unique
        // identifier for itself irrespective of its IP address or FQDN etc. We could store that in the signer history
        // and match a changed signer configuration block to the same actual signer by fetching this value from the
        // backend and using it (or an equivalent value) as the signer handle. The KMIP 1.0 specification defines the
        // Query operation which MUST return a "Vendor Identification" text string that "uniquely identifies the
        // vendor", but it could be a different HSM by the same vendor. It also defines a "Server Information" value
        // that MAY be returne by the Query operation but whose format and content is vendor specific and is optional
        // for the server to return, so we can't use that either. Even if we could "fingerprint" the server we don't
        // have much information to go on and it can all legally change (e.g. IP address, port number, supported
        // protocol versions or operations or object types, the former things could legally change as part of cluster
        // expansion or deployment or fail over or restore from backup etc, and the latter things could legally change
        // as part of a HSM upgrade).
        //
        // TODO: A different idea could be to MARK the server so that we can identify it again later. We could do this
        // by creating a key that we don't use for anything except to identify that this is the same signer backend
        // that we were talking to before. In fact we don't even care that it is the same signer backend, only that it
        // has the keys that we are looking for. We *do* care that we don't maliciously get directed to use a bad
        // backend in place of the good backend but we leave that to things like TLS certificate checks and operators
        // to manage, though maybe we could warn about any detected changes in the server compared to what we earlier
        // recorded. For this to work we would have to be able to lookup the marking key by an expected name. For KMIP
        // we rename the key after creation to give it a meaningful identifier for the KMIP server operator in case the
        // server is not only used by Krill to make it clear which were created by Krill. In the Krill HSM prototype
        // the PKCS#11 signer is not similarly able to name the keys after creation, instead it sets the CKA_ID byte
        // array to a random value and remembers it for retrieving the key later based on that value. For OpenSSL the
        // KeyIdentifier is the unique identifier for using the key, we can remember that as the signer ID. The act of
        // "marking" the signer can also serve as a way to verify that the signer functions correctly, we could even
        // use the new key for signing and verify that the signed output is correct.
        //
        // The signer would try to find a key whose name/CKA_ID is the Krill mark identifier, or create it if missing.
        // It would then add itself to the SignerMapper using the KeyIdentifier of the created mark key as the handle
        // of the signer to create if not already present. When the SignerRouter is asked to sign using a key it would
        // ask the SignerMapper for the handle of the owning signer and then lookup that handle in its own map of
        // Handle to SignerProvider. If not map entry is found it would try to ask any unmapped signers for their
        // handle and see if it matches the one we just got from the SignerMapper and if so establish that mapping for
        // future use by this Krill process. The OpenSslSigner has no notion of key metadata, a key is just a
        // KeyIdentifier. The mark should not be a Krill constant identifier but an identifier created for this Krill
        // instance, otherwise connecting to a HSM already previously used by a different/earlier Krill instance would
        // leave us thinking it has the keys are looking for when it doesn't.
        //
        // So, maybe better yet, if this is about making sure keys are found as expected, generate any key and use its
        // key identifier + persistent HSM id as the signer handle (use both to differentiate between two signers who
        // both just number their HSM ids from 1 onwards, for example). Then just lookup the signer handles in the HSM
        // and see which one we can find.
        //
        // We could even go further and store the public half of the created key pair in the Signer store and use it to
        // verify data that we ask the signer to sign with its "handle" key to verify that it is indeed the correct
        // signer to use.

        let openssl_signer = Arc::new(RwLock::new(SignerProvider::OpenSsl(OpenSslSigner::build(
            work_dir,
            "OpenSslSigner - No config file name available yet",
            Some(signer_mapper.clone()),
        )?)));

        let kmip_signer = Arc::new(RwLock::new(SignerProvider::Kmip(KmipSigner::build(
            "KmipSigner - No config file name available yet",
            signer_mapper,
        )?)));

        Ok(SignerRoleAssignments {
            default_signer: kmip_signer.clone(),
            one_off_signer: openssl_signer.clone(),
            rand_fallback_signer: openssl_signer,
        })
    }

    // TODO: Delete me once setup from Krill configuration is supported.
    #[cfg(feature = "hsm-tests")]
    fn build_signers(
        work_dir: &Path,
        signer_mapper: Arc<SignerMapper>,
        _signers_by_handle: Arc<RwLock<HashMap<Handle, Arc<RwLock<SignerProvider>>>>>,
    ) -> KrillResult<SignerRoleAssignments> {
        // When the HSM feature is activated AND test mode is activated:
        //   - Use the HSM for as much as possible to depend on it as broadly as possible in the Krill test suite..
        //   - Fallback to OpenSSL for random number generation if the HSM doesn't support it.
        let openssl_signer = Arc::new(RwLock::new(SignerProvider::OpenSsl(OpenSslSigner::build(
            work_dir,
            "OpenSslSigner - No config file name available yet",
            Some(signer_mapper.clone()),
        )?)));

        let kmip_signer = Arc::new(RwLock::new(SignerProvider::Kmip(KmipSigner::build(
            "KmipSigner - No config file name available yet",
            signer_mapper,
        )?)));

        Ok(SignerRoleAssignments {
            default_signer: kmip_signer.clone(),
            one_off_signer: kmip_signer.clone(),
            rand_fallback_signer: openssl_signer,
        })
    }

    fn get_signer_for_key(&self, key_id: &KeyIdentifier) -> Result<Arc<RwLock<SignerProvider>>, SignerError> {
        // Get the signer handle for the key
        let signer_handle = self
            .signer_mapper
            .get_signer_for_key(key_id)
            .map_err(|_| SignerError::KeyNotFound)?;

        let signer = self.get_signer_for_handle(&signer_handle);

        signer.ok_or(SignerError::KeyNotFound)
    }

    fn get_signer_for_handle(&self, signer_handle: &Handle) -> Option<Arc<RwLock<SignerProvider>>> {
        self.signers_by_handle.read().unwrap().get(signer_handle).cloned()
    }
}

// Variants of the `Signer` trait functions that take `&mut` arguments and so must be locked to use them, but for which
// we don't want the caller to have to lock the entire `SignerRouter`, only the single `Signer` being used. Ideally the
// `Signer` trait wouldn't use `&mut` at all and rather require the implementation to use the interior mutability
// pattern with as much or as little locking internally at the finest level of granularity possible.
// Update: https://github.com/NLnetLabs/rpki-rs/pull/162 removes the &mut.
impl SignerRouter {
    fn create_key_minimally_locking(&self, algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        self.register_pending_signers()?;
        self.default_signer.write().unwrap().create_key(algorithm)
    }

    fn destroy_key_minimally_locking(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        self.register_pending_signers()?;
        self.get_signer_for_key(key_id)?.write().unwrap().destroy_key(key_id)
    }

    #[cfg(not(feature = "hsm"))]
    fn register_pending_signers(&self) -> Result<(), SignerError> {
        Ok(())
    }

    #[cfg(feature = "hsm")]
    fn register_pending_signers(&self) -> Result<(), SignerError> {
        use std::str::FromStr;

        let has_unmapped_signers = !self.signers_without_handle.read().unwrap().is_empty();

        if has_unmapped_signers {
            // For each unmapped signer in the store attempt to lookup its handle "key" in this signer to see if this
            // signer is the owner of that key and is thus an interface to the signer that created the keys attributed
            // to that signer in the store.

            // Each signer has a handle which is actually a combination of a public key KeyIdentifier and an internal
            // HSM specific private key identifier. These can be matched to a signer backend to show that it really is
            // the owner of the set of keys associated with the signer. When we attempt to identify which key set a
            // given signer backend owns we try using each of the signer handles in turn to see if the signer backend
            // matches. One side-effect of checking all signer handles, not just those that are mapped, is that if the
            // config defines two signers, and one is a near continuous replica of the other, then when Krill starts it
            // will use whichever one it can connect to and verify. It's not deliberate however and so if the one it
            // uses later dies while Krill is running Krill won't then switch to the other one as it has no logic at
            // present for removing a signer from the active set.
            let candidate_handles = self
                .signer_mapper
                .get_signer_handles()
                .map_err(|err| SignerError::Custom(err.to_string()))?;

            // Are any of the given handles the string representations of a key id of a key that we own? If so then that
            // must be our signer handle.
            self.signers_without_handle.write().unwrap().retain(|signer_provider| {
                //TODO: handle me
                let (signer_handle, signer_name) = {
                    let sp = signer_provider.read().unwrap(); //TODO: handle me
                    let signer_handle = sp.get_handle();
                    let signer_name = sp.get_name().to_string();
                    (signer_handle, signer_name)
                };

                // Does the signer provider really have no handle? or did we assign one to it below?
                if signer_handle.is_some() {
                    // Do NOT retain this signer in the vec as it is NOT lacking a handle
                    return false;
                }

                debug!("Checking if signer '{}' is ready and known", signer_name);

                for candidate_handle in &candidate_handles {
                    // The signer handle is a combination of KeyIdentifier and internal key id
                    let candidate_handle_bytes = hex::decode(candidate_handle).unwrap(); //TODO: handle me
                    let candidate_handle_str = String::from_utf8(candidate_handle_bytes).unwrap(); //TODO: handle me
                    let (wanted_key_id, internal_key_id) = candidate_handle_str.split_once('-').unwrap(); //TODO: handle me

                    if let Ok(wanted_key_id) = KeyIdentifier::from_str(wanted_key_id) {
                        let public_key_hex_str = self
                            .signer_mapper
                            .get_signer_public_key(candidate_handle)
                            .unwrap() //TODO: handle me
                            .unwrap(); //TODO: handle me

                        if let Ok(public_key_bytes) = hex::decode(public_key_hex_str) {
                            let public_key = PublicKey::decode(&*public_key_bytes).unwrap(); //TODO: handle me
                            let found_key_id = public_key.key_identifier();

                            if found_key_id == wanted_key_id {
                                let challenge = "Krill signer verification challenge".as_bytes();
                                let signature = {
                                    signer_provider
                                        .read()
                                        .unwrap() //TODO: handle me
                                        .sign_registration_challenge(internal_key_id.to_string(), challenge)
                                };

                                if let Ok(signature) = signature {
                                    if public_key.verify(challenge, &signature).is_ok() {
                                        debug!("Signer '{}' is ready and known, binding", signer_name);

                                        let mut sp = signer_provider.write().unwrap();
                                        let signer_info = sp.get_info().unwrap_or("No signer info".to_string());
                                        self.signer_mapper
                                            .change_signer_name(candidate_handle, &signer_name)
                                            .unwrap(); //TODO: handle me
                                        self.signer_mapper
                                            .change_signer_info(candidate_handle, &signer_info)
                                            .unwrap(); //TODO: handle me
                                        sp.set_handle(candidate_handle.clone()); //TODO: handle me
                                        self.signers_by_handle
                                            .write()
                                            .unwrap()
                                            .insert(candidate_handle.clone(), signer_provider.clone()); //TODO: handle me

                                        debug!("Signer '{}' binding complete", signer_name);
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                }

                let mut sp = signer_provider.write().unwrap();
                let create_result = sp.create_registration_key(); //TODO: handle me
                if let Ok((public_key, internal_key_id)) = create_result {
                    let challenge = "Krill signer verification challenge".as_bytes();
                    let signature = sp.sign_registration_challenge(internal_key_id.to_string(), challenge);

                    if let Ok(signature) = signature {
                        if public_key.verify(challenge, &signature).is_ok() {
                            debug!("Signer '{}' is ready and new, binding", signer_name);

                            let key_id = public_key.key_identifier();
                            let new_signer_handle = format!("{}-{}", key_id, internal_key_id);
                            let new_signer_handle = hex::encode(new_signer_handle);
                            let new_signer_handle = Handle::from_str(&new_signer_handle).unwrap(); // TODO: handle me
                            let signer_info = sp.get_info().unwrap_or("No signer info".to_string());
                            let public_key_bytes = public_key.to_info_bytes();
                            let public_key = Some(hex::encode(public_key_bytes));
                            let public_key_ref = public_key.as_ref().map(|v| v.as_str());

                            self.signer_mapper
                                .add_signer(&new_signer_handle, &signer_name, &signer_info, public_key_ref)
                                .unwrap(); // TODO: handle me
                            sp.set_handle(new_signer_handle.clone());
                            self.signers_by_handle
                                .write()
                                .unwrap()
                                .insert(new_signer_handle.clone(), signer_provider.clone());

                            debug!("Signer '{}' binding complete", signer_name);
                            return false;
                        }
                    }
                }

                true
            });
        }

        Ok(())
    }
}

impl Signer for SignerRouter {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&mut self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        self.register_pending_signers()?;
        self.default_signer.write().unwrap().create_key(algorithm)
    }

    fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<Self::Error>> {
        self.register_pending_signers()?;
        self.get_signer_for_key(key_id)?.read().unwrap().get_key_info(key_id)
    }

    fn destroy_key(&mut self, key_id: &KeyIdentifier) -> Result<(), KeyError<Self::Error>> {
        self.register_pending_signers()?;
        self.get_signer_for_key(key_id)?.write().unwrap().destroy_key(key_id)
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        self.register_pending_signers()?;
        self.get_signer_for_key(key_id)?
            .read()
            .unwrap()
            .sign(key_id, algorithm, data)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        self.register_pending_signers()?;
        self.one_off_signer.read().unwrap().sign_one_off(algorithm, data)
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.register_pending_signers()?;
        let signer = self.default_signer.read().unwrap();
        if signer.supports_random() {
            signer.rand(target)
        } else {
            self.rand_fallback_signer.read().unwrap().rand(target)
        }
    }
}

//------------ KrillSigner ---------------------------------------------------

/// High level signing interface between Krill and the Signer backends.
///
/// KrillSigner:
///   - Is configured via the Krill configuration file.
///   - Maps Result<SignerError> to KrillResult.
///   - Directs signers to use the RPKI standard key format (RSA).
///   - Directs signers to use the RPKI standard signature algorithm (RSA PKCS #1 v1.5 with SHA-256).
///   - Offers a higher level interface than the Signer trait.
#[derive(Clone, Debug)]
pub struct KrillSigner {
    router: SignerRouter,
}

impl KrillSigner {
    pub fn build(work_dir: &Path) -> KrillResult<Self> {
        Ok(KrillSigner {
            router: SignerRouter::build(work_dir)?,
        })
    }

    pub fn create_key(&self) -> CryptoResult<KeyIdentifier> {
        self.router
            .create_key_minimally_locking(PublicKeyFormat::Rsa)
            .map_err(crypto::Error::signer)
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> CryptoResult<()> {
        self.router
            .destroy_key_minimally_locking(key_id)
            .map_err(crypto::Error::key_error)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> CryptoResult<PublicKey> {
        self.router.get_key_info(key_id).map_err(crypto::Error::key_error)
    }

    pub fn random_serial(&self) -> CryptoResult<Serial> {
        Serial::random(&self.router).map_err(crypto::Error::signer)
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(&self, key_id: &KeyIdentifier, data: &D) -> CryptoResult<Signature> {
        self.router
            .sign(key_id, SignatureAlgorithm::default(), data)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(&self, data: &D) -> CryptoResult<(Signature, PublicKey)> {
        self.router
            .sign_one_off(SignatureAlgorithm::default(), data)
            .map_err(crypto::Error::signer)
    }

    pub fn sign_csr(&self, base_repo: &RepoInfo, name_space: &str, key: &KeyIdentifier) -> CryptoResult<Csr> {
        let pub_key = self.router.get_key_info(key).map_err(crypto::Error::key_error)?;
        let enc = Csr::construct(
            &self.router,
            key,
            &base_repo.ca_repository(name_space).join(&[]).unwrap(), // force trailing slash
            &base_repo.rpki_manifest(name_space, &pub_key.key_identifier()),
            Some(&base_repo.rpki_notify()),
        )
        .map_err(crypto::Error::signing)?;
        Ok(Csr::decode(enc.as_slice())?)
    }

    pub fn sign_cert(&self, tbs: TbsCert, key_id: &KeyIdentifier) -> CryptoResult<Cert> {
        tbs.into_cert(&self.router, key_id).map_err(crypto::Error::signing)
    }

    pub fn sign_crl(&self, tbs: TbsCertList<Vec<CrlEntry>>, key_id: &KeyIdentifier) -> CryptoResult<Crl> {
        tbs.into_crl(&self.router, key_id).map_err(crypto::Error::signing)
    }

    pub fn sign_manifest(
        &self,
        content: ManifestContent,
        builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Manifest> {
        content
            .into_manifest(builder, &self.router, key_id)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_roa(
        &self,
        roa_builder: RoaBuilder,
        object_builder: SignedObjectBuilder,
        key_id: &KeyIdentifier,
    ) -> CryptoResult<Roa> {
        roa_builder
            .finalize(object_builder, &self.router, key_id)
            .map_err(crypto::Error::signing)
    }

    pub fn sign_rta(&self, rta_builder: &mut rta::RtaBuilder, ee: Cert) -> CryptoResult<()> {
        let key = ee.subject_key_identifier();
        rta_builder.push_cert(ee);
        rta_builder
            .sign(&self.router, &key, None, None)
            .map_err(crypto::Error::signing)
    }
}

//------------ CsrInfo -------------------------------------------------------

pub type CaRepository = uri::Rsync;
pub type RpkiManifest = uri::Rsync;
pub type RpkiNotify = uri::Https;

pub struct CsrInfo {
    ca_repository: CaRepository,
    rpki_manifest: RpkiManifest,
    rpki_notify: Option<RpkiNotify>,
    key: PublicKey,
}

impl CsrInfo {
    pub fn new(
        ca_repository: CaRepository,
        rpki_manifest: RpkiManifest,
        rpki_notify: Option<RpkiNotify>,
        key: PublicKey,
    ) -> Self {
        CsrInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
            key,
        }
    }

    pub fn global_uris(&self) -> bool {
        self.ca_repository.seems_global_uri()
            && self.rpki_manifest.seems_global_uri()
            && self
                .rpki_notify
                .as_ref()
                .map(|uri| uri.seems_global_uri())
                .unwrap_or_else(|| true)
    }

    pub fn unpack(self) -> (CaRepository, RpkiManifest, Option<RpkiNotify>, PublicKey) {
        (self.ca_repository, self.rpki_manifest, self.rpki_notify, self.key)
    }

    pub fn key_id(&self) -> KeyIdentifier {
        self.key.key_identifier()
    }
}

impl TryFrom<&Csr> for CsrInfo {
    type Error = Error;

    fn try_from(csr: &Csr) -> KrillResult<CsrInfo> {
        csr.validate().map_err(|_| Error::invalid_csr("invalid signature"))?;
        let ca_repository = csr
            .ca_repository()
            .cloned()
            .ok_or_else(|| Error::invalid_csr("missing ca repository"))?;
        let rpki_manifest = csr
            .rpki_manifest()
            .cloned()
            .ok_or_else(|| Error::invalid_csr("missing rpki manifest"))?;
        let rpki_notify = csr.rpki_notify().cloned();
        let key = csr.public_key().clone();
        Ok(CsrInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
            key,
        })
    }
}

impl From<&Cert> for CsrInfo {
    fn from(issued: &Cert) -> Self {
        let ca_repository = issued.ca_repository().cloned().unwrap();
        let rpki_manifest = issued.rpki_manifest().cloned().unwrap();
        let rpki_notify = issued.rpki_notify().cloned();
        let key = issued.subject_public_key_info().clone();
        CsrInfo {
            ca_repository,
            rpki_manifest,
            rpki_notify,
            key,
        }
    }
}

//------------ CaSignSupport -------------------------------------------------

/// Support signing by CAs
pub struct SignSupport;

impl SignSupport {
    /// Create an IssuedCert
    pub fn make_issued_cert(
        csr: CsrInfo,
        resources: &ResourceSet,
        limit: RequestResourceLimit,
        replaces: Option<ReplacedObject>,
        signing_key: &CertifiedKey,
        weeks: i64,
        signer: &KrillSigner,
    ) -> KrillResult<IssuedCert> {
        let signing_cert = signing_key.incoming_cert();
        let resources = resources.apply_limit(&limit)?;
        if !signing_cert.resources().contains(&resources) {
            return Err(Error::MissingResources);
        }

        let validity = Self::sign_validity_weeks(weeks);
        let request = CertRequest::Ca(csr, validity);

        let tbs = Self::make_tbs_cert(&resources, signing_cert, request, signer)?;
        let cert = signer.sign_cert(tbs, signing_key.key_id())?;

        let cert_uri = signing_cert.uri_for_object(&cert);

        Ok(IssuedCert::new(cert_uri, limit, resources, cert, replaces))
    }

    /// Create an EE certificate for use in ResourceTaggedAttestations.
    /// Note that for RPKI signed objects such as ROAs and Manifests, the
    /// EE certificate is created by the rpki.rs library instead.
    pub fn make_rta_ee_cert(
        resources: &ResourceSet,
        signing_key: &CertifiedKey,
        validity: Validity,
        pub_key: PublicKey,
        signer: &KrillSigner,
    ) -> KrillResult<Cert> {
        let signing_cert = signing_key.incoming_cert();
        let request = CertRequest::Ee(pub_key, validity);
        let tbs = Self::make_tbs_cert(resources, signing_cert, request, signer)?;

        let cert = signer.sign_cert(tbs, signing_key.key_id())?;
        Ok(cert)
    }

    fn make_tbs_cert(
        resources: &ResourceSet,
        signing_cert: &RcvdCert,
        request: CertRequest,
        signer: &KrillSigner,
    ) -> KrillResult<TbsCert> {
        let serial = signer.random_serial()?;
        let issuer = signing_cert.cert().subject().clone();

        let validity = match &request {
            CertRequest::Ca(_, validity) => *validity,
            CertRequest::Ee(_, validity) => *validity,
        };

        let pub_key = match &request {
            CertRequest::Ca(info, _) => info.key.clone(),
            CertRequest::Ee(key, _) => key.clone(),
        };

        let subject = Some(Name::from_pub_key(&pub_key));

        let key_usage = match &request {
            CertRequest::Ca(_, _) => KeyUsage::Ca,
            CertRequest::Ee(_, _) => KeyUsage::Ee,
        };

        let overclaim = Overclaim::Refuse;

        let mut cert = TbsCert::new(serial, issuer, validity, subject, pub_key, key_usage, overclaim);

        let asns = resources.to_as_resources();
        if asns.is_inherited() || !asns.to_blocks().unwrap().is_empty() {
            cert.set_as_resources(asns);
        }

        let ipv4 = resources.to_ip_resources_v4();
        if ipv4.is_inherited() || !ipv4.to_blocks().unwrap().is_empty() {
            cert.set_v4_resources(ipv4);
        }

        let ipv6 = resources.to_ip_resources_v6();
        if ipv6.is_inherited() || !ipv6.to_blocks().unwrap().is_empty() {
            cert.set_v6_resources(ipv6);
        }

        cert.set_authority_key_identifier(Some(signing_cert.cert().subject_key_identifier()));
        cert.set_ca_issuer(Some(signing_cert.uri().clone()));
        cert.set_crl_uri(Some(signing_cert.crl_uri()));

        match request {
            CertRequest::Ca(csr, _) => {
                let (ca_repository, rpki_manifest, rpki_notify, _pub_key) = csr.unpack();
                cert.set_basic_ca(Some(true));
                cert.set_ca_repository(Some(ca_repository));
                cert.set_rpki_manifest(Some(rpki_manifest));
                cert.set_rpki_notify(rpki_notify);
            }
            CertRequest::Ee(_, _) => {
                // cert.set_signed_object() ??
            }
        }

        Ok(cert)
    }

    /// Returns a validity period from 5 minutes ago (in case of NTP mess-up), to
    /// X weeks from now.
    pub fn sign_validity_weeks(weeks: i64) -> Validity {
        let from = Time::five_minutes_ago();
        let until = Time::now() + chrono::Duration::weeks(weeks);
        Validity::new(from, until)
    }

    pub fn sign_validity_days(days: i64) -> Validity {
        let from = Time::five_minutes_ago();
        let until = Time::now() + chrono::Duration::days(days);
        Validity::new(from, until)
    }
}

#[allow(clippy::large_enum_variant)]
enum CertRequest {
    Ca(CsrInfo, Validity),
    Ee(PublicKey, Validity),
}

trait ManifestEntry {
    fn mft_bytes(&self) -> Bytes;
    fn mft_hash(&self) -> Bytes {
        let digest = DigestAlgorithm::default().digest(self.mft_bytes().as_ref());
        Bytes::copy_from_slice(digest.as_ref())
    }
    fn mft_entry(&self, name: &str) -> FileAndHash<Bytes, Bytes> {
        FileAndHash::new(Bytes::copy_from_slice(name.as_bytes()), self.mft_hash())
    }
}

impl ManifestEntry for Crl {
    fn mft_bytes(&self) -> Bytes {
        self.to_captured().into_bytes()
    }
}
