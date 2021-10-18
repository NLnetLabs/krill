use std::sync::{Arc, RwLock};

use rpki::repository::crypto::{PublicKey, Signature};

use crate::commons::{
    api::Handle,
    crypto::{dispatch::signerinfo::SignerMapper, SignerError},
};

#[derive(Debug)]
pub struct Pkcs11Signer {
    name: String,

    handle: RwLock<Option<Handle>>,

    mapper: Arc<SignerMapper>,
}

impl Pkcs11Signer {
    /// Creates a new instance of Pkcs11Signer.
    pub fn build(name: &str, mapper: Arc<SignerMapper>) -> Result<Self, SignerError> {
        let s = Pkcs11Signer {
            name: name.to_string(),
            handle: RwLock::new(None),
            mapper: mapper.clone(),
        };

        Ok(s)
    }

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
