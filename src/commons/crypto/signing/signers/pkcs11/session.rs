use std::sync::{Arc, Mutex};

use cryptoki::error::Error as Pkcs11Error;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::commons::crypto::signers::pkcs11::context::ThreadSafePkcs11Context;

#[derive(Debug)]
pub(super) struct Pkcs11Session {
    context: ThreadSafePkcs11Context,

    session_handle: Arc<Mutex<Session>>,
}

impl Pkcs11Session {
    pub fn new(context: ThreadSafePkcs11Context, slot: Slot) -> Result<Pkcs11Session, Pkcs11Error> {
        //
        // Note that we don't track whether or not the session logs in so that we can later logout because the spec
        // we invoke C_CloseSession on drop and the spec for C_CloseSession says:
        //    "If this function is successful and it closes the last session between the application and the token, the
        //    login state of the token for the application returns to public sessions. Any new sessions to the token
        //    opened by the application will be either R/O Public or R/W Public sessions."
        //
        // In the spirit of not doing anything we don't have to do, we can keep the code simpler by not calling
        // C_Logout because we don't have to.
        let session_handle = context.read().unwrap().open_rw_session(slot)?;
        Ok(Pkcs11Session {
            context,
            session_handle: Arc::new(Mutex::new(session_handle)),
        })
    }
}

impl Pkcs11Session {
    pub fn generate_key_pair(
        &self,
        mechanism: &Mechanism,
        pub_template: &[Attribute],
        priv_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle), Pkcs11Error> {
        self.context.read().unwrap().generate_key_pair(
            self.session_handle.clone(),
            mechanism,
            pub_template,
            priv_template,
        )
    }

    pub fn get_attributes(
        &self,
        pub_handle: ObjectHandle,
        pub_template: &[AttributeType],
    ) -> Result<Vec<Attribute>, Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .get_attributes(self.session_handle.clone(), pub_handle, pub_template)
    }

    pub fn login(
        &self, user_type: UserType, user_pin: Option<&AuthPin>
    ) -> Result<(), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .login(self.session_handle.clone(), user_type, user_pin)
    }

    // Note: Cryptographic operations can fail if the key has CKA_ALWAYS_AUTHENTICATE set as that requires that we call
    // C_Login immediately prior to calling C_SignInit, and we don't support that yet (would it ever make sense as this
    // could for example require an operator to enter a pin code in a key pad on every signing moment?).
    pub fn sign(&self, mechanism: &Mechanism, key: ObjectHandle, data: &[u8]) -> Result<Vec<u8>, Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .sign(self.session_handle.clone(), mechanism, key, data)
    }

    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>, Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .find_objects(self.session_handle.clone(), template)
    }

    pub fn destroy_object(&self, object_handle: ObjectHandle) -> Result<(), Pkcs11Error> {
        self.context
            .read()
            .unwrap()
            .destroy_object(self.session_handle.clone(), object_handle)
    }
}
