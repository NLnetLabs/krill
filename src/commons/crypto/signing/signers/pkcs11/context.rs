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
    sync::{Arc, RwLock, Mutex},
};

use cryptoki::error::Error as Pkcs11Error;

use cryptoki::{
    context::{CInitializeArgs, Info, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectHandle},
    session::{Session, SessionFlags, UserType},
    slot::{Slot, SlotInfo, TokenInfo},
};
use once_cell::sync::OnceCell;

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
    pub fn new(file_name: &str, ctx: Pkcs11) -> Self {
        Self(Arc::new(RwLock::new(Pkcs11Context {
            lib_file_name: file_name.to_string(),
            ctx: Some(ctx),
            initialized: false,
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
    ctx: Option<Pkcs11>,

    initialized: bool,
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

            let ctx = Pkcs11::new(lib_path).map_err(|err| {
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
        let _ = self.ctx.as_mut().ok_or(SignerError::Pkcs11Error(format!(
            "Failed to initialize library '{}': Library is not loaded yet",
            self.lib_file_name
        )))?;

        if !self.initialized {
            // Note: YubiHSM uses the reserved field of the initialize arguments to pass settings to the library but
            // (the current version of) the `cryptoki` crate doesn't provide a way to set those if we wanted to support
            // this way of configuring the PKCS#11 token.

            // TODO: add a timeout around the call to initialize?
            if let Err(err) = self.initialize(CInitializeArgs::OsThreads) {
                error!("Failed to initialize PKCS#11 library '{}': {}", self.lib_file_name, err);
                return Err(SignerError::PermanentlyUnusable);
            }

            self.initialized = true;
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

//------------ Deref with logging (rather than just impl std::ops::Deref) ---------------------------------------------

// TODO: add a timeout around Cryptoki calls?
impl Pkcs11Context {
    fn logged_cryptoki_call<F, T>(&self, cryptoki_call_name: &'static str, call: F) -> Result<T, Pkcs11Error>
    where
        F: FnOnce(&Pkcs11) -> Result<T, Pkcs11Error>,
    {
        trace!("{}::{}()", self.lib_file_name, cryptoki_call_name);
        let res = (call)(self.ctx.as_ref().unwrap());
        if let Err(err) = &res {
            error!("{}::{}() failed: {}", self.lib_file_name, cryptoki_call_name, err);
        }
        res
    }

    // fn logged_cryptoki_call_take<F, T>(self, cryptoki_call_name: &'static str, call: F) -> Result<T, Pkcs11Error>
    // where
    //     F: FnOnce(Pkcs11) -> Result<T, Pkcs11Error>,
    // {
    //     trace!("{}::{}()", self.lib_file_name, cryptoki_call_name);
    //     let res = (call)(self.ctx.unwrap());
    //     if let Err(err) = &res {
    //         // Warn only as we don't know that this issue really affects Krill thus calling it an error would be a bit
    //         // extreme.
    //         warn!("{}::{}() failed: {}", self.lib_file_name, cryptoki_call_name, err);
    //     }
    //     res
    // }
}

impl Pkcs11Context {
    fn initialize(&self, init_args: CInitializeArgs) -> Result<(), Pkcs11Error> {
        self.logged_cryptoki_call("C_Initialize", |cryptoki| cryptoki.initialize(init_args))
    }

    // pub fn finalize(self) -> Result<(), Pkcs11Error> {
    //     self.logged_cryptoki_call_take("C_Finalize", |cryptoki| Ok(cryptoki.finalize()))
    // }

    pub fn get_info(&self) -> Result<Info, Pkcs11Error> {
        self.logged_cryptoki_call("C_GetInfo", |cryptoki| cryptoki.get_library_info())
    }

    pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<Slot>, Pkcs11Error> {
        self.logged_cryptoki_call("C_GetSlotList", |cryptoki| {
            if token_present {
                cryptoki.get_slots_with_initialized_token()
            } else {
                cryptoki.get_all_slots()
            }
        })
    }

    pub fn get_slot_info(&self, slot: Slot) -> Result<SlotInfo, Pkcs11Error> {
        self.logged_cryptoki_call("C_GetSlotInfo", |cryptoki| cryptoki.get_slot_info(slot))
    }

    pub fn get_token_info(&self, slot: Slot) -> Result<TokenInfo, Pkcs11Error> {
        self.logged_cryptoki_call("C_GetTokenInfo", |cryptoki| cryptoki.get_token_info(slot))
    }

    pub fn open_session(&self, slot: Slot, flags: SessionFlags) -> Result<Session, Pkcs11Error> {
        self.logged_cryptoki_call("C_OpenSession", |cryptoki| {
            cryptoki.open_session_no_callback(slot, flags)
        })
    }

    pub fn generate_key_pair(
        &self,
        session: Arc<Mutex<Session>>,
        mechanism: &Mechanism,
        public_key_template: &[Attribute],
        private_key_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle), Pkcs11Error> {
        self.logged_cryptoki_call("C_GenerateKeyPair", |_| {
            session.lock().unwrap().generate_key_pair(mechanism, public_key_template, private_key_template)
        })
    }

    pub fn get_attribute_value<'a>(
        &self,
        session: Arc<Mutex<Session>>,
        object: ObjectHandle,
        template: &[AttributeType],
    ) -> Result<Vec<Attribute>, Pkcs11Error> {
        self.logged_cryptoki_call("C_GetAttributeValue", move |_| session.lock().unwrap().get_attributes(object, template))
    }

    pub fn login<'a>(&self, session: Arc<Mutex<Session>>, user_type: UserType, pin: Option<&'a str>) -> Result<(), Pkcs11Error> {
        self.logged_cryptoki_call("C_Login", |_| session.lock().unwrap().login(user_type, pin))
    }

    pub fn sign(
        &self,
        session: Arc<Mutex<Session>>,
        mechanism: &Mechanism,
        key: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, Pkcs11Error> {
        self.logged_cryptoki_call("C_SignInit & C_Sign", |_| session.lock().unwrap().sign(mechanism, key, data))
    }

    pub fn find_objects(&self, session: Arc<Mutex<Session>>, template: &[Attribute]) -> Result<Vec<ObjectHandle>, Pkcs11Error> {
        self.logged_cryptoki_call("C_FindObjectsInit, C_FindObjects & C_FindObjectsFinal", |_| {
            session.lock().unwrap().find_objects(template)
        })
    }

    pub fn destroy_object(&self, session: Arc<Mutex<Session>>, object_handle: ObjectHandle) -> Result<(), Pkcs11Error> {
        self.logged_cryptoki_call("C_DeleteObject", |_| session.lock().unwrap().destroy_object(object_handle))
    }
}
