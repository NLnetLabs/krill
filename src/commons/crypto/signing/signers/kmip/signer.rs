use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::crypto::signers::{
    error::SignerError,
    kmip::{internal::KeyStatus, KmipSigner},
};

impl Signer for KmipSigner {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    fn create_key(&mut self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let (key, kmip_key_pair_ids) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.remember_kmip_key_ids(&key_id, kmip_key_pair_ids)?;
        Ok(key_id)
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let kmip_key_pair_ids = self.lookup_kmip_key_ids(key_id)?;
        self.get_public_key_from_id(&kmip_key_pair_ids.public_key_id)
            .map_err(|err| KeyError::Signer(err))
    }

    fn destroy_key(&mut self, key_id: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        let kmip_key_pair_ids = self.lookup_kmip_key_ids(key_id)?;
        match self.destroy_key_pair(&kmip_key_pair_ids, KeyStatus::Active)? {
            true => Ok(()),
            false => Err(
                SignerError::KmipError(
                    format!("Failed to completely destroy KMIP key pair for Krill KeyIdentifier '{:?}', KMIP public key '{}' and KMIP private key '{}'",
                        key_id, kmip_key_pair_ids.public_key_id, kmip_key_pair_ids.private_key_id)))?,
        }
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        let kmip_key_pair_ids = self.lookup_kmip_key_ids(key_id)?;

        let signature = self
            .sign_with_key(&kmip_key_pair_ids.private_key_id, algorithm, data.as_ref())
            .map_err(|err| {
                SigningError::Signer(SignerError::KmipError(format!(
                    "Signing data failed for Krill KeyIdentifier '{}' and KMIP private key id '{}': {}",
                    key_id, kmip_key_pair_ids.private_key_id, err
                )))
            })?;

        Ok(signature)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        // TODO: Is it possible to use a KMIP batch request to implement the create, activate, sign, deactivate, delete
        // in one round-trip to the server?
        let (key, kmip_key_pair_ids) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature_res = self
            .sign_with_key(&kmip_key_pair_ids.private_key_id, algorithm, data.as_ref())
            .map_err(|err| SignerError::KmipError(format!("One-off signing of data failed: {}", err)));

        let _ = self.destroy_key_pair(&kmip_key_pair_ids, KeyStatus::Active);

        let signature = signature_res?;

        Ok((signature, key))
    }

    fn rand(&self, data: &mut [u8]) -> Result<(), Self::Error> {
        let random_bytes = self.get_random_bytes(data.len())?;

        data.copy_from_slice(&random_bytes);

        Ok(())
    }
}