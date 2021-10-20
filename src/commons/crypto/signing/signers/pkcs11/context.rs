use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

use once_cell::sync::OnceCell;
use pkcs11::{
    types::{CKF_OS_LOCKING_OK, CK_C_INITIALIZE_ARGS},
    Ctx,
};

use crate::commons::crypto::SignerError;

/// The PKCS#11 "Cryptoki" context. This term isn't part of the PKCS#11 specification, it's the name given by the
/// `pkcs11` Rust crate to the root data structure that represents a loaded PKCS#11 library and gives access to the
/// functions exported by it.
///
/// Each library must be initialized only once by a single application using it, irrespective of however many threads
/// there are within the application that use it.
///
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
static CONTEXTS: OnceCell<Arc<RwLock<HashMap<String, Arc<RwLock<Pkcs11Context>>>>>> = OnceCell::new();

#[derive(Debug)]
pub(super) struct Pkcs11Context {
    lib_file_name: String,

    ctx: Option<Ctx>,
}

impl Pkcs11Context {
    pub fn get_or_load(lib_path: &Path) -> Result<Arc<RwLock<Self>>, SignerError> {
        let contexts = CONTEXTS.get_or_try_init(
            || -> Result<Arc<RwLock<HashMap<String, Arc<RwLock<Pkcs11Context>>>>>, SignerError> {
                Ok(Arc::new(RwLock::new(HashMap::new())))
            },
        )?;

        let lib_file_name = lib_path
            .file_name()
            .ok_or(SignerError::Pkcs11Error(format!(
                "PKCS#11 library path '{:?}' does not point to a file",
                lib_path
            )))?
            .to_string_lossy()
            .to_string();

        let mut locked_contexts = contexts.write().unwrap();

        let ctx_wrapper = locked_contexts
            .entry(lib_file_name)
            .or_insert_with_key(|lib_file_name| {
                let ctx = match Ctx::new(lib_path) {
                    Ok(ctx) => Some(ctx),
                    Err(err) => {
                        error!("Failed to load PKCS#11 library '{:?}': {}", lib_path, err);
                        None
                    }
                };
                Arc::new(RwLock::new(Pkcs11Context {
                    lib_file_name: lib_file_name.clone(),
                    ctx,
                }))
            });

        if ctx_wrapper.read().unwrap().ctx.is_none() {
            return Err(SignerError::Pkcs11Error(format!(
                "Failed to load PKCS#11 library '{:?}'",
                lib_path
            )));
        }

        Ok(ctx_wrapper.clone())
    }

    pub fn get_lib_file_name(&self) -> String {
        self.lib_file_name.clone()
    }

    pub fn initialize_if_not_already(&mut self) -> Result<(), SignerError> {
        let ctx = self.ctx.as_mut().ok_or(SignerError::Pkcs11Error(format!(
            "Failed to initialize library '{}': Library is not loaded yet",
            self.lib_file_name
        )))?;

        if !ctx.is_initialized() {
            // TODO: are these arg values okay?
            let mut args = CK_C_INITIALIZE_ARGS::new();
            args.CreateMutex = None;
            args.DestroyMutex = None;
            args.LockMutex = None;
            args.UnlockMutex = None;
            args.flags = CKF_OS_LOCKING_OK;

            if let Err(err) = ctx.initialize(Some(args)) {
                error!("Failed to initialize PKCS#11 library '{}': {}", self.lib_file_name, err);
                return Err(SignerError::PermanentlyUnusable);
            }
        }

        Ok(())
    }
}

impl std::ops::Deref for Pkcs11Context {
    type Target = Ctx;

    fn deref(&self) -> &Self::Target {
        self.ctx.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for Pkcs11Context {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx.as_mut().unwrap()
    }
}
