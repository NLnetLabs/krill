use std::sync::{Arc, RwLock};

use pkcs11::types::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CK_ATTRIBUTE, CK_BYTE, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV,
    CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_USER_TYPE,
};

use crate::commons::crypto::signers::pkcs11::context::Pkcs11Context;

#[derive(Debug)]
pub(super) struct Pkcs11Session {
    context: Arc<RwLock<Pkcs11Context>>,

    handle: CK_SESSION_HANDLE,
}

impl Pkcs11Session {
    pub fn new(
        context: Arc<RwLock<Pkcs11Context>>,
        slot_id: CK_SLOT_ID,
    ) -> Result<Pkcs11Session, pkcs11::errors::Error> {
        // Section 11.6 "Session management functions" under "C_OpenSession" says:
        //    "For legacy reasons, the CKF_SERIAL_SESSION bit must always be set; if a call to C_OpenSession does not
        //     have this bit set, the call should return unsuccessfully with the error code
        //     CKR_PARALLEL_NOT_SUPPORTED."
        //
        // Note that we don't track whether or not the session logs in so that we can later logout because the spec
        // we invoke C_CloseSession on drop and the spec for C_CloseSession says:
        //    "If this function is successful and it closes the last session between the application and the token, the
        //    login state of the token for the application returns to public sessions. Any new sessions to the token
        //    opened by the application will be either R/O Public or R/W Public sessions."
        //
        // In the spirit of not doing anything we don't have to do, we can keep the code simpler by not calling
        // C_Logout because we don't have to.
        let handle = context
            .read()
            .unwrap()
            .open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)?;
        Ok(Pkcs11Session { context, handle })
    }
}

// TODO: Is this ever actually called, or does Krill do an immediate unclean shutdown if terminated?
impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        let _ = self.context.read().unwrap().close_session(self.handle);
    }
}

impl Pkcs11Session {
    pub fn generate_key_pair(
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

    pub fn get_attribute_value<'a>(
        &self,
        pub_handle: u64,
        pub_template: &'a mut Vec<CK_ATTRIBUTE>,
    ) -> Result<(CK_RV, &'a Vec<CK_ATTRIBUTE>), pkcs11::errors::Error> {
        self.context
            .read()
            .unwrap()
            .get_attribute_value(self.handle, pub_handle, pub_template)
    }

    pub fn login(&self, user_type: CK_USER_TYPE, user_pin: Option<&str>) -> Result<(), pkcs11::errors::Error> {
        self.context.read().unwrap().login(self.handle, user_type, user_pin)
    }

    // Note: Cryptographic operations can fail if the key has CKA_ALWAYS_AUTHENTICATE set as that requires that we call
    // C_Login immediately prior to calling C_SignInit, and we don't support that yet (would it ever make sense as this
    // could for example require an operator to enter a pin code in a key pad on every signing moment?).
    pub fn sign_init(&self, mechanism: &CK_MECHANISM, key: CK_OBJECT_HANDLE) -> Result<(), pkcs11::errors::Error> {
        self.context.read().unwrap().sign_init(self.handle, mechanism, key)
    }

    pub fn sign(&self, data: &[CK_BYTE]) -> Result<Vec<CK_BYTE>, pkcs11::errors::Error> {
        self.context.read().unwrap().sign(self.handle, data)
    }

    pub fn find_objects_init(&self, template: &[CK_ATTRIBUTE]) -> Result<(), pkcs11::errors::Error> {
        self.context.read().unwrap().find_objects_init(self.handle, template)
    }

    pub fn find_objects(&self, max_object_count: CK_ULONG) -> Result<Vec<CK_OBJECT_HANDLE>, pkcs11::errors::Error> {
        self.context.read().unwrap().find_objects(self.handle, max_object_count)
    }

    pub fn find_objects_final(&self) -> Result<(), pkcs11::errors::Error> {
        self.context.read().unwrap().find_objects_final(self.handle)
    }
}
