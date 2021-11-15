use pkcs11::types::{CKO_PRIVATE_KEY, CKO_PUBLIC_KEY};
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, SigningError,
};

use crate::commons::crypto::{signers::pkcs11::Pkcs11Signer, SignerError};

// Implement the functions defined by the `Signer` trait because `SignerProvider` expects to invoke them, but as the
// dispatching is not trait based we don't actually have to implement the `Signer` trait.
impl Pkcs11Signer {
    pub fn create_key(&self, algorithm: PublicKeyFormat) -> Result<KeyIdentifier, SignerError> {
        let (key, _, _, internal_key_id) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.remember_key_id(&key_id, internal_key_id)?;
        Ok(key_id)
    }

    pub fn get_key_info(&self, key_id: &KeyIdentifier) -> Result<PublicKey, KeyError<SignerError>> {
        let internal_key_id = self.lookup_key_id(key_id)?;
        let pub_handle = self.find_key(&internal_key_id, CKO_PUBLIC_KEY)?;
        self.get_public_key_from_handle(pub_handle)
            .map_err(|err| KeyError::Signer(err))
    }

    pub fn destroy_key(&self, key_id: &KeyIdentifier) -> Result<(), KeyError<SignerError>> {
        debug!("PKCS#11: Deleting key pair with ID {}", key_id);
        let internal_key_id = self.lookup_key_id(key_id)?;
        let mut res: Result<(), KeyError<SignerError>> = Ok(());
        if let Ok(pub_handle) = self.find_key(&internal_key_id, CKO_PUBLIC_KEY) {
            res = self.destroy_key_by_handle(pub_handle).map_err(|err| match err {
                SignerError::KeyNotFound => KeyError::KeyNotFound,
                _ => KeyError::Signer(err),
            });
        }
        if let Ok(priv_handle) = self.find_key(&internal_key_id, CKO_PRIVATE_KEY) {
            let res2 = self.destroy_key_by_handle(priv_handle).map_err(|err| match err {
                SignerError::KeyNotFound => KeyError::KeyNotFound,
                _ => KeyError::Signer(err),
            });
            res = res.and(res2);
        }
        res
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<SignerError>> {
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

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        let (key, pub_handle, priv_handle, _) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature_res = self
            .sign_with_key(priv_handle, algorithm, data.as_ref())
            .map_err(|err| SignerError::Pkcs11Error(format!("One-off signing of data failed: {}", err)));

        let _ = self.destroy_key_by_handle(pub_handle);
        let _ = self.destroy_key_by_handle(priv_handle);

        let signature = signature_res?;

        Ok((signature, key))
    }

    pub fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        let random_bytes = self.get_random_bytes(target.len())?;

        target.copy_from_slice(&random_bytes);

        Ok(())
    }
}
