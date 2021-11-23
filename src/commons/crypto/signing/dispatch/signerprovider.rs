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

/// Dispatchers Signer requests to a particular implementation of the Signer trait.
///
/// Named and modelled after the similar AuthProvider concept that already exists in Krill.
#[allow(dead_code)] // Needed as we currently only ever construct one variant
#[derive(Debug)]
pub(crate) enum SignerProvider {
    OpenSsl(OpenSslSigner),

    #[cfg(feature = "hsm")]
    Kmip(KmipSigner),

    #[cfg(feature = "hsm")]
    Pkcs11(Pkcs11Signer),

    #[cfg(all(test, feature = "hsm"))]
    Mock(MockSigner),
}

impl SignerProvider {
    pub fn supports_random(&self) -> bool {
        match self {
            SignerProvider::OpenSsl(signer) => signer.supports_random(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.supports_random(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.supports_random(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.supports_random(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.create_registration_key(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.create_registration_key(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.create_registration_key(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.create_registration_key(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn set_handle(&self, handle: Handle) {
        match self {
            SignerProvider::OpenSsl(signer) => signer.set_handle(handle),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.set_handle(handle),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.set_handle(handle),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.set_handle(handle),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_name(&self) -> &str {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_name(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_name(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.get_name(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.get_name(),
        }
    }

    #[cfg(feature = "hsm")]
    pub fn get_info(&self) -> Option<String> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_info(),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_info(),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.get_info(),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.get_info(),
        }
    }
}

// Implement the functions defined by the `Signer` trait because `SignerRouter` expects to invoke them, but as the
// dispatching is not trait based we don't actually have to implement the `Signer` trait.
impl SignerProvider {
    pub(super) fn create_key(&self, algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.create_key(algorithm),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.create_key(algorithm),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.create_key(algorithm),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.create_key(algorithm),
        }
    }

    pub(super) fn get_key_info(&self, key: &KeyIdentifier) -> Result<PublicKey, KeyError<SignerError>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.get_key_info(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.get_key_info(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.get_key_info(key),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.get_key_info(key),
        }
    }

    pub(super) fn destroy_key(&self, key: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.destroy_key(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.destroy_key(key),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.destroy_key(key),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.destroy_key(key),
        }
    }

    pub(super) fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &KeyIdentifier,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<SignerError>> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign(key, algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign(key, algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.sign(key, algorithm, data),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.sign(key, algorithm, data),
        }
    }

    pub(super) fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_one_off(algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign_one_off(algorithm, data),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.sign_one_off(algorithm, data),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.sign_one_off(algorithm, data),
        }
    }

    pub(super) fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.rand(target),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.rand(target),
            #[cfg(feature = "hsm")]
            SignerProvider::Pkcs11(signer) => signer.rand(target),
            #[cfg(all(test, feature = "hsm"))]
            SignerProvider::Mock(signer) => signer.rand(target),
        }
    }
}
