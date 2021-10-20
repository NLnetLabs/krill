use std::sync::{Arc, RwLock};

use pkcs11::types::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CK_ATTRIBUTE, CK_MECHANISM, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_USER_TYPE,
};

use crate::commons::crypto::signers::pkcs11::context::Pkcs11Context;

#[derive(Debug)]
pub(super) struct Pkcs11Session {
    context: Arc<RwLock<Pkcs11Context>>,

    handle: CK_SESSION_HANDLE,
}

impl Pkcs11Session {
    pub(super) fn new(
        context: Arc<RwLock<Pkcs11Context>>,
        slot_id: CK_SLOT_ID,
    ) -> Result<Pkcs11Session, pkcs11::errors::Error> {
        let handle = context
            .read()
            .unwrap()
            .open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)?;
        Ok(Pkcs11Session { context, handle })
    }

    pub(super) fn generate_key_pair(
        &self,
        mechanism: &CK_MECHANISM,
        pub_template: &[CK_ATTRIBUTE],
        priv_template: &[CK_ATTRIBUTE],
    ) -> Result<(u64, u64), pkcs11::errors::Error> {
        self.context
            .read()
            .unwrap()
            .generate_key_pair(self.handle, mechanism, pub_template, priv_template)
    }

    pub(super) fn get_attribute_value<'a>(
        &self,
        pub_handle: u64,
        pub_template: &'a mut Vec<CK_ATTRIBUTE>,
    ) -> Result<(CK_RV, &'a Vec<CK_ATTRIBUTE>), pkcs11::errors::Error> {
        self.context
            .read()
            .unwrap()
            .get_attribute_value(self.handle, pub_handle, pub_template)
    }

    pub(super) fn login(&self, user_type: CK_USER_TYPE, user_pin: Option<&str>) -> Result<(), pkcs11::errors::Error> {
        self.context.read().unwrap().login(self.handle, user_type, user_pin)
    }
}
