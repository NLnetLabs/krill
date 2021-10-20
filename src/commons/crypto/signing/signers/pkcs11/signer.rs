use pkcs11::types::{CKO_PRIVATE_KEY, CKO_PUBLIC_KEY};
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

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let internal_key_id = self.lookup_key_id(key_id)?;
        let pub_handle = self.find_key(&internal_key_id, CKO_PUBLIC_KEY)?;
        self.get_public_key_from_handle(pub_handle)
            .map_err(|err| KeyError::Signer(err))
    }

    fn destroy_key(&self, _key: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        Ok(()) //TODO
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        let internal_key_id = self.lookup_key_id(key_id)?;
        let priv_handle = self
            .find_key(&internal_key_id, CKO_PRIVATE_KEY)
            .map_err(|err| match err {
                KeyError::KeyNotFound => SigningError::KeyNotFound,
                KeyError::Signer(err) => SigningError::Signer(err),
            })?;

        self.sign_with_key(priv_handle, algorithm, data.as_ref())
            .map_err(|err| SigningError::Signer(err))
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        let (key, _, priv_handle, _) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature_res = self
            .sign_with_key(priv_handle, algorithm, data.as_ref())
            .map_err(|err| SignerError::Pkcs11Error(format!("One-off signing of data failed: {}", err)));

        // let _ = self.destroy_key_pair(&kmip_key_pair_ids, KeyStatus::Active);

        let signature = signature_res?;

        Ok((signature, key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        let random_bytes = self.get_random_bytes(target.len())?;

        target.copy_from_slice(&random_bytes);

        Ok(())
    }
}
