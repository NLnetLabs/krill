use pkcs11::types::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CK_ATTRIBUTE, CK_BYTE, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV,
    CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_USER_TYPE,
};

use pkcs11::errors::Error as Pkcs11Error;

use crate::commons::crypto::signers::pkcs11::context::ThreadSafePkcs11Context;

#[derive(Debug)]
pub(super) struct Pkcs11Session {
    context: ThreadSafePkcs11Context,

    session_handle: CK_SESSION_HANDLE,
}

impl Pkcs11Session {
    pub fn new(context: ThreadSafePkcs11Context, slot_id: CK_SLOT_ID) -> Result<Pkcs11Session, Pkcs11Error> {
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
        let session_handle =
            context
                .read()
                .unwrap()
                .open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)?;
        Ok(Pkcs11Session {
            context,
            session_handle,
        })
    }
}

// TODO: Is this ever actually called, or does Krill do an immediate unclean shutdown if terminated?
impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        let _ = self.context.read().unwrap().close_session(self.session_handle);
    }
}

impl Pkcs11Session {
    pub fn generate_key_pair(
        &self,
        mechanism: &CK_MECHANISM,
        pub_template: &[CK_ATTRIBUTE],
        priv_template: &[CK_ATTRIBUTE],
    ) -> Result<(u64, u64), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .generate_key_pair(self.session_handle, mechanism, pub_template, priv_template)
    }

    pub fn get_attribute_value<'a>(
        &self,
        pub_handle: u64,
        pub_template: &'a mut Vec<CK_ATTRIBUTE>,
    ) -> Result<(CK_RV, &'a Vec<CK_ATTRIBUTE>), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .get_attribute_value(self.session_handle, pub_handle, pub_template)
    }

    pub fn login(&self, user_type: CK_USER_TYPE, user_pin: Option<&str>) -> Result<(), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .login(self.session_handle, user_type, user_pin)
    }

    // Note: Cryptographic operations can fail if the key has CKA_ALWAYS_AUTHENTICATE set as that requires that we call
    // C_Login immediately prior to calling C_SignInit, and we don't support that yet (would it ever make sense as this
    // could for example require an operator to enter a pin code in a key pad on every signing moment?).
    pub fn sign_init(&self, mechanism: &CK_MECHANISM, key: CK_OBJECT_HANDLE) -> Result<(), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .sign_init(self.session_handle, mechanism, key)
    }

    pub fn sign(&self, data: &[CK_BYTE]) -> Result<Vec<CK_BYTE>, Pkcs11Error> {
        self.context.read().unwrap().sign(self.session_handle, data)
    }

    pub fn find_objects_init(&self, template: &[CK_ATTRIBUTE]) -> Result<(), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .find_objects_init(self.session_handle, template)
    }

    pub fn find_objects(&self, max_object_count: CK_ULONG) -> Result<Vec<CK_OBJECT_HANDLE>, Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .find_objects(self.session_handle, max_object_count)
    }

    pub fn find_objects_final(&self) -> Result<(), Pkcs11Error> {
        self.context.read().unwrap().find_objects_final(self.session_handle)
    }

    pub fn destroy_object(&self, object_handle: CK_OBJECT_HANDLE) -> Result<(), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .destroy_object(self.session_handle, object_handle)
    }

    pub fn generate_random(&self, num_bytes_wanted: CK_ULONG) -> Result<Vec<u8>, Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .generate_random(self.session_handle, num_bytes_wanted)
    }
}