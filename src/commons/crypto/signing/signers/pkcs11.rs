use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::crypto::SignerError;

#[derive(Debug)]
pub struct Pkcs11Signer {}

impl Signer for Pkcs11Signer {
    type KeyId = KeyIdentifier;

    type Error = SignerError;

    fn create_key(&self, _algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        todo!()
    }

    fn get_key_info(&self, _key: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        todo!()
    }

    fn destroy_key(&self, _key: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        todo!()
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        _key: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        _data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        todo!()
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        _data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        todo!()
    }

    fn rand(&self, _target: &mut [u8]) -> Result<(), Self::Error> {
        todo!()
    }
}

impl Pkcs11Signer {
    pub fn supports_random(&self) -> bool {
        todo!()
    }

    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        todo!()
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        _signer_private_key_id: &str,
        _challenge: &D,
    ) -> Result<Signature, SignerError> {
        todo!()
    }

    pub fn set_handle(&self, _handle: crate::commons::api::Handle) {
        todo!()
    }

    pub fn get_name(&self) -> &str {
        todo!()
    }

    pub fn get_info(&self) -> Option<String> {
        todo!()
    }
}
