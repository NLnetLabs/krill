use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::crypto::signers::{error::SignerError, softsigner::OpenSslSigner};

#[cfg(feature = "hsm")]
use crate::commons::{api::Handle, crypto::signers::kmip::KmipSigner};

//------------ SignerProvider ------------------------------------------------

/// Dispatchers Signer requests to a particular implementation of the Signer trait.
///
/// Named and modelled after the similar AuthProvider concept that already exists in Krill.
#[allow(dead_code)] // Needed as we currently only ever construct one variant
#[derive(Clone, Debug)]
pub enum SignerProvider {
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
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        match self {
            SignerProvider::OpenSsl(signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
            #[cfg(feature = "hsm")]
            SignerProvider::Kmip(signer) => signer.sign_registration_challenge(signer_private_key_id, challenge),
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
