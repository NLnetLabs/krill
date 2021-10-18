use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::crypto::{signers::pkcs11::Pkcs11Signer, SignerError};

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
