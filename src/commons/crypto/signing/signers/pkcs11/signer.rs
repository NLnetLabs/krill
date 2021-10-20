use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::crypto::{signers::pkcs11::Pkcs11Signer, SignerError};

impl Signer for Pkcs11Signer {
    type KeyId = KeyIdentifier;

    type Error = SignerError;

    fn create_key(&self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let (key, _, _, internal_key_id) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.remember_key_id(&key_id, internal_key_id)?;
        Ok(key_id)
    }

    fn get_key_info(&self, _key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
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

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        let random_bytes = self.get_random_bytes(target.len())?;

        target.copy_from_slice(&random_bytes);

        Ok(())
    }
}
