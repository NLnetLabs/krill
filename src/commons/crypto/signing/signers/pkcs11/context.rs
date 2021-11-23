//! The PKCS#11 "Cryptoki" context.
//!
//! The term "context" isn't part of the PKCS#11 specification, it's the name given by the `pkcs11` Rust crate to the
//! root data structure that represents a loaded PKCS#11 library and gives access to the functions exported by it.
//!
//! Each PKCS#11 library must be initialized only once by a single application using it, irrespective of however many
//! threads there are within the application that use it.
//!
//! # Known issues
//!
//! There are no timeouts around the calls into the PKCS#11 context and yet we have no idea what the PKCS#11 library
//! is going to do when invoked. If it uses a TCP/IP connection to a remote service which is itself not that fast even
//! when operating normally, the invocation could block for quite a while (in computing terms at least). One possible
//! way to improve this could be to invoke the library in another thread and way a maximum amount of time in the
//! invoking thread before deciding to give up on the spawned thread that is taking too long.
use std::{
    collections::{hash_map::Entry, HashMap},
    path::Path,
    sync::{Arc, RwLock},
};

use once_cell::sync::OnceCell;
use pkcs11::{
    types::{
        CKF_OS_LOCKING_OK, CK_ATTRIBUTE, CK_BYTE, CK_C_INITIALIZE_ARGS, CK_FLAGS, CK_INFO, CK_MECHANISM, CK_NOTIFY,
        CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_USER_TYPE,
        CK_VOID_PTR,
    },
    Ctx,
};

use crate::commons::crypto::SignerError;

#[derive(Debug, Clone)]
pub(super) struct ThreadSafePkcs11Context(Arc<RwLock<Pkcs11Context>>);

impl std::ops::Deref for ThreadSafePkcs11Context {
    type Target = Arc<RwLock<Pkcs11Context>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ThreadSafePkcs11Context {
    pub fn new(file_name: &str, ctx: Ctx) -> Self {
        Self(Arc::new(RwLock::new(Pkcs11Context {
            lib_file_name: file_name.to_string(),
            ctx: Some(ctx),
        })))
    }
}

/// To enable use cases such as migrating from one PKCS#11 provider to another we need to support loading more than one
/// PKCS#11 library at once and so need to distinguish one library from another. Prior to actually initializing the
/// library the only means we have for differentiating one from another is the file system path which the library is
/// loaded from. This may not actually be unique, it could be two copies of the same library (or two different versions
/// of the same library), or it could be some sort of symbolic link or duplicate mount or other mechanism for making two
/// file system paths point to the same underlying file. To avoid attempts to load different versions of the same
/// library we use the filename as the unique identifier rather than the entire path so that two library files at
/// different filesystem locations with the same name are not both loaded into the memory of our process at the same
/// time.
///
/// To give access to the same loaded library from a second or subsequent caller without double loading or
/// initialization of the library we need a means of looking up the library context by filename. We use a simple
/// RwLock'd HashMap for this.
type Pkcs11ContextsByFileName = Arc<RwLock<HashMap<String, ThreadSafePkcs11Context>>>;
static CONTEXTS: OnceCell<Pkcs11ContextsByFileName> = OnceCell::new();

#[derive(Debug)]
pub(super) struct Pkcs11Context {
    lib_file_name: String,

    /// The Rust `pkcs11` Ctx object which gives access to the loaded library functions.
    ///
    /// Some(...) means that the library was successfully loaded and passed the initial checks performed by the
    /// `pkcs11` crate (at the time of writing it checks that a lot of function pointers are available as expected).
    ///
    /// None means that we tried and failed to load the library.
    ctx: Option<Ctx>,
}

impl Pkcs11Context {
    /// Load the PKCS#11 library.
    pub fn get_or_load(lib_path: &Path) -> Result<ThreadSafePkcs11Context, SignerError> {
        // Initialize the singleton map of PKCS#11 contexts. Failure here should be impossible or else so severe that
        // panicking is all we can do.
        let contexts = CONTEXTS
            .get_or_try_init(|| -> Result<Pkcs11ContextsByFileName, ()> { Ok(Arc::new(RwLock::new(HashMap::new()))) })
            .unwrap();

        // Use the file name of the library as the key into the map, if the path represents a file.
        let lib_file_name = lib_path.file_name().ok_or_else(|| {
            SignerError::Pkcs11Error(format!(
                "Failed to load PKCS#11 library '{:?}': path does not refer to a file",
                lib_path
            ))
        })?;

        // Get a reference to either the already loaded library, or to the result of trying to load it.
        let lib_file_name = lib_file_name.to_string_lossy().to_string();
        let mut locked_contexts = contexts.write().unwrap();

        let ctx_ref = Self::or_insert_with_key(locked_contexts.entry(lib_file_name), |file_name| {
            // The library isn't yet in the map, so load it.
            trace!("Loading PKCS#11 library '{:?}'", lib_path);

            let ctx = Ctx::new(lib_path).map_err(|err| {
                SignerError::Pkcs11Error(format!("Failed to load PKCS#11 library '{:?}': {}", lib_path, err))
            })?;

            trace!("Loaded PKCS#11 library '{:?}'", lib_path);
            Ok(ThreadSafePkcs11Context::new(file_name, ctx))
        })?;

        Ok(ctx_ref.clone())
    }

    /// Invoke C_Initialize in the loaded PKCS#11 library, if not already initialized.
    /// We don't do this at the time of loading the library as we don't want to delay or block Krill startup.
    pub fn initialize_if_not_already(&mut self) -> Result<(), SignerError> {
        let ctx = self.ctx.as_mut().ok_or(SignerError::Pkcs11Error(format!(
            "Failed to initialize library '{}': Library is not loaded yet",
            self.lib_file_name
        )))?;

        if !ctx.is_initialized() {
            // These are the defaults used by CK_C_INIITIALIZE_ARGS::new() but it's good to state them explicitly here
            // and gives a place to put the comment about args.pReserved.
            let mut args = CK_C_INITIALIZE_ARGS::new();
            args.CreateMutex = None;
            args.DestroyMutex = None;
            args.LockMutex = None;
            args.UnlockMutex = None;
            args.flags = CKF_OS_LOCKING_OK;
            // args.pReserved // TODO: permit setting this, e.g. YubiHSM uses it to pass settings to the library.

            // TODO: add a timeout around the call to initialize?
            if let Err(err) = self.initialize(Some(args)) {
                error!("Failed to initialize PKCS#11 library '{}': {}", self.lib_file_name, err);
                return Err(SignerError::PermanentlyUnusable);
            }
        }

        Ok(())
    }

    // Entry::or_insert_with_key() isn't available until Rust 1.50
    fn or_insert_with_key<'a, F: FnOnce(&String) -> Result<ThreadSafePkcs11Context, SignerError>>(
        e: Entry<'a, String, ThreadSafePkcs11Context>,
        default: F,
    ) -> Result<&'a mut ThreadSafePkcs11Context, SignerError> {
        let existing_or_new_value = match e {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = default(entry.key())?;
                entry.insert(value)
            }
        };

        Ok(existing_or_new_value)
    }
}

// TODO: Is this ever actually called, or does Krill do an immediate unclean shutdown if terminated?
impl Drop for Pkcs11Context {
    fn drop(&mut self) {
        // We don't call C_CloseSession or C_CloseAllSessions because the Pkcs11Session Drop impl will take care of
        // that for us. The spec says C_Finalize must not be called while other threads are still making Cryptoki
        // calls but as each Pkcs11Session holds a reference to the Pkcs11Context we cannot be dropped until there
        // are no longer any session objects and as all Cryptoki calls are made via session objects there thus cannot
        // any longer be any threads making Cryptoki calls at this point because then we wound't be being Drop'd.
        let _ = self.finalize();
    }
}

//------------ Deref with logging (rather than just impl std::ops::Deref) ---------------------------------------------

// TODO: add a timeout around Cryptoki calls?
impl Pkcs11Context {
    fn logged_cryptoki_call<F, T>(&self, cryptoki_call_name: &'static str, call: F) -> Result<T, pkcs11::errors::Error>
    where
        F: FnOnce(&Ctx) -> Result<T, pkcs11::errors::Error>,
    {
        trace!("{}::{}()", self.lib_file_name, cryptoki_call_name);
        let res = (call)(self.ctx.as_ref().unwrap());
        if let Err(err) = &res {
            error!("{}::{}() failed: {}", self.lib_file_name, cryptoki_call_name, err);
        }
        res
    }

    fn logged_cryptoki_call_mut<F, T>(
        &mut self,
        cryptoki_call_name: &'static str,
        call: F,
    ) -> Result<T, pkcs11::errors::Error>
    where
        F: FnOnce(&mut Ctx) -> Result<T, pkcs11::errors::Error>,
    {
        trace!("{}::{}()", self.lib_file_name, cryptoki_call_name);
        let res = (call)(self.ctx.as_mut().unwrap());
        if let Err(err) = &res {
            // Warn only as we don't know that this issue really affects Krill thus calling it an error would be a bit
            // extreme.
            warn!("{}::{}() failed: {}", self.lib_file_name, cryptoki_call_name, err);
        }
        res
    }
}

impl Pkcs11Context {
    fn initialize(&mut self, init_args: Option<CK_C_INITIALIZE_ARGS>) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call_mut("C_Initialize", |cryptoki| cryptoki.initialize(init_args))
    }

    pub fn finalize(&mut self) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call_mut("C_Finalize", |cryptoki| cryptoki.finalize())
    }

    pub fn get_info(&self) -> Result<CK_INFO, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GetInfo", |cryptoki| cryptoki.get_info())
    }

    pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<CK_SLOT_ID>, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GetSlotList", |cryptoki| cryptoki.get_slot_list(token_present))
    }

    pub fn get_slot_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_SLOT_INFO, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GetSlotInfo", |cryptoki| cryptoki.get_slot_info(slot_id))
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GetTokenInfo", |cryptoki| cryptoki.get_token_info(slot_id))
    }

    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        application: Option<CK_VOID_PTR>,
        notify: CK_NOTIFY,
    ) -> Result<CK_SESSION_HANDLE, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_OpenSession", |cryptoki| {
            cryptoki.open_session(slot_id, flags, application, notify)
        })
    }

    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_CloseSession", |cryptoki| cryptoki.close_session(session))
    }

    pub fn generate_key_pair(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        public_key_template: &[CK_ATTRIBUTE],
        private_key_template: &[CK_ATTRIBUTE],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GenerateKeyPair", |cryptoki| {
            cryptoki.generate_key_pair(session, mechanism, public_key_template, private_key_template)
        })
    }

    pub fn get_attribute_value<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &'a mut Vec<CK_ATTRIBUTE>,
    ) -> Result<(CK_RV, &'a Vec<CK_ATTRIBUTE>), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GetAttributeValue", move |cryptoki| {
            cryptoki.get_attribute_value(session, object, template)
        })
    }

    pub fn login<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: Option<&'a str>,
    ) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_Login", |cryptoki| cryptoki.login(session, user_type, pin))
    }

    pub fn sign_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_SignInit", |cryptoki| cryptoki.sign_init(session, mechanism, key))
    }

    pub fn sign(&self, session: CK_SESSION_HANDLE, data: &[CK_BYTE]) -> Result<Vec<CK_BYTE>, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_Sign", |cryptoki| cryptoki.sign(session, data))
    }

    pub fn find_objects_init(
        &self,
        session: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_FindObjectsInit", |cryptoki| {
            cryptoki.find_objects_init(session, template)
        })
    }

    pub fn find_objects(
        &self,
        session: CK_SESSION_HANDLE,
        max_object_count: CK_ULONG,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_FindObjects", |cryptoki| {
            cryptoki.find_objects(session, max_object_count)
        })
    }

    pub fn find_objects_final(&self, session: CK_SESSION_HANDLE) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_FindObjectsFinal", |cryptoki| cryptoki.find_objects_final(session))
    }

    pub fn destroy_object(
        &self,
        session: CK_SESSION_HANDLE,
        object_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_DeleteObject", |cryptoki| {
            cryptoki.destroy_object(session, object_handle)
        })
    }

    pub fn generate_random(
        &self,
        session: CK_SESSION_HANDLE,
        num_bytes_wanted: CK_ULONG,
    ) -> Result<Vec<u8>, pkcs11::errors::Error> {
        self.logged_cryptoki_call("C_GenerateRandom", |cryptoki| {
            cryptoki.generate_random(session, num_bytes_wanted)
        })
    }
}
