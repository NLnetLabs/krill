use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, SigningError,
};

use crate::commons::crypto::signers::{error::SignerError, softsigner::OpenSslSigner};

#[cfg(all(test, feature = "hsm"))]
use crate::commons::crypto::signers::mocksigner::MockSigner;

#[cfg(feature = "hsm")]
use crate::commons::{
    api::Handle,
    crypto::signers::{kmip::KmipSigner, pkcs11::Pkcs11Signer},
};

//------------ SignerProvider ------------------------------------------------

#[cfg(not(feature = "hsm"))]
#[derive(Debug)]
pub(crate) struct SignerFlags;

#[cfg(not(feature = "hsm"))]
impl Default for SignerFlags {
    fn default() -> Self {
        Self
    }
}

#[cfg(feature = "hsm")]
#[derive(Debug)]
pub(crate) struct SignerFlags {
    pub is_default_signer: bool,
    pub is_one_off_signer: bool,
    pub is_rand_fallback_signer: bool,
}

#[cfg(feature = "hsm")]
impl std::fmt::Display for SignerFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "default: {}, oneoff: {}, random: {}",
            self.is_default_signer, self.is_one_off_signer, self.is_rand_fallback_signer
        ))
    }
}

#[cfg(feature = "hsm")]
impl Default for SignerFlags {
    fn default() -> Self {
        // Making round trips to an HSM to generate random numbers or to create, sign with and destroy one-off
        // throwaway signing keys can be slow. Therefore by default we don't use the default signer for one-off signing
        // or random number generation but instead create an OpenSSL signer for these purposes.
        Self {
            is_default_signer: true,
            is_one_off_signer: false,
            is_rand_fallback_signer: false,
        }
    }
}

#[cfg(feature = "hsm")]
impl SignerFlags {
    pub(crate) fn new(is_default_signer: bool, is_one_off_signer: bool, is_rand_fallback_signer: bool) -> Self {
        Self {
            is_default_signer,
            is_one_off_signer,
            is_rand_fallback_signer,
        }
    }
}

/// Dispatchers Signer requests to a particular implementation of the Signer trait.
///
/// Named and modelled after the similar AuthProvider concept that already exists in Krill.
#[allow(dead_code)] // Needed as we currently only ever construct one variant
#[derive(Debug)]
pub(crate) enum SignerProvider {
    OpenSsl(SignerFlags, OpenSslSigner),

    #[cfg(feature = "hsm")]
    Kmip(SignerFlags, KmipSigner),

    #[cfg(feature = "hsm")]
    Pkcs11(SignerFlags, Pkcs11Signer),

    #[cfg(all(test, feature = "hsm"))]
    Mock(SignerFlags, MockSigner),
}

impl SignerProvider {
    #[cfg(feature = "hsm")]
    pub fn is_default_signer(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(flags, _) => flags.is_default_signer,
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(flags, _) => flags.is_default_signer,
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(flags, _) => flags.is_default_signer,
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(flags, _) => flags.is_default_signer,
        }
    }

    #[cfg(feature = "hsm")]
    pub fn is_one_off_signer(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(flags, _) => flags.is_one_off_signer,
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(flags, _) => flags.is_one_off_signer,
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(flags, _) => flags.is_one_off_signer,
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(flags, _) => flags.is_one_off_signer,
        }
    }

    #[cfg(feature = "hsm")]
    pub fn is_rand_fallback_signer(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(flags, _) => flags.is_rand_fallback_signer,
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(flags, _) => flags.is_rand_fallback_signer,
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(flags, _) => flags.is_rand_fallback_signer,
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(flags, _) => flags.is_rand_fallback_signer,
        }
    }

    pub fn supports_random(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.supports_random(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.supports_random(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.supports_random(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.supports_random(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.create_registration_key(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.create_registration_key(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.create_registration_key(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.create_registration_key(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn set_handle(&self, handle: Handle) {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.set_handle(handle),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.set_handle(handle),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.set_handle(handle),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.set_handle(handle),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_name(&self) -> &str {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.get_name(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.get_name(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.get_name(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.get_name(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_info(&self) -> Option<String> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.get_info(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.get_info(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.get_info(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.get_info(),
        }
    }
}

// Implement the functions defined by the `Signer` trait because `SignerRouter` expects to invoke them, but as the
// dispatching is not trait based we don't actually have to implement the `Signer` trait.
impl SignerProvider {
    pub(crate) fn create_key(&self, algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.create_key(algorithm),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.create_key(algorithm),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.create_key(algorithm),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.create_key(algorithm),
        }
    }

    pub(crate) fn get_key_info(&self, key: &KeyIdentifier) -> Result<PublicKey, KeyError<SignerError>> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.get_key_info(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.get_key_info(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.get_key_info(key),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.get_key_info(key),
        }
    }

    pub(crate) fn destroy_key(&self, key: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.destroy_key(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.destroy_key(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.destroy_key(key),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.destroy_key(key),
        }
    }

    pub(crate) fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &KeyIdentifier,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<SignerError>> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.sign(key, algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.sign(key, algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.sign(key, algorithm, data),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.sign(key, algorithm, data),
        }
    }

    pub(crate) fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.sign_one_off(algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.sign_one_off(algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.sign_one_off(algorithm, data),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.sign_one_off(algorithm, data),
        }
    }

    pub(crate) fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        match self {
            SignerProvider::OpenSsl(_, signer) => signer.rand(target),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(_, signer) => signer.rand(target),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(_, signer) => signer.rand(target),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(_, signer) => signer.rand(target),
        }
    }
}
