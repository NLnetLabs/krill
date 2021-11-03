use rpki::repository::crypto::{KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer};

use super::softsigner::SignerError;

/// A dummy signer to prove that compilation with two different Signer implementations works
#[derive(Clone, Debug)]
pub struct DummySigner;

impl Signer for DummySigner {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&self, _: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        unreachable!()
    }

    fn get_key_info(
        &self,
        _: &Self::KeyId,
    ) -> Result<PublicKey, rpki::repository::crypto::signer::KeyError<Self::Error>> {
        unreachable!()
    }

    fn destroy_key(&self, _: &Self::KeyId) -> Result<(), rpki::repository::crypto::signer::KeyError<Self::Error>> {
        unreachable!()
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        _: &Self::KeyId,
        _: SignatureAlgorithm,
        _: &D,
    ) -> Result<Signature, rpki::repository::crypto::SigningError<Self::Error>> {
        unreachable!()
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _: SignatureAlgorithm,
        _: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        unreachable!()
    }

    fn rand(&self, _: &mut [u8]) -> Result<(), Self::Error> {
        unreachable!()
    }
}
