use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use bytes::Bytes;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::commons::{
    api::Handle,
    crypto::{dispatch::signerinfo::SignerMapper, SignerError},
};

pub enum FnIdx {
    SupportsRandom,
    CreateRegistrationKey,
    SignRegistrationChallenge,
    SetHandle,
    GetName,
    GetInfo,
    CreateKey,
    GetKeyInfo,
    DestroyKey,
    Sign,
    SignOneOff,
    Rand,
    Count,
}

#[derive(Debug)]
pub struct MockSignerCallCounts {
    call_counts: RwLock<Vec<u32>>,
}

impl MockSignerCallCounts {
    pub fn new() -> Self {
        let mut call_counts = Vec::with_capacity(FnIdx::Count as usize);
        call_counts.resize(FnIdx::Count as usize, 0);

        Self {
            call_counts: RwLock::new(call_counts),
        }
    }

    pub fn get(&self, fn_idx: FnIdx) -> u32 {
        self.call_counts.read().unwrap()[fn_idx as usize]
    }

    pub fn inc(&self, fn_idx: FnIdx) {
        self.call_counts.write().unwrap()[fn_idx as usize] += 1;
    }
}

pub type CreateRegistrationKeyErrorCb = fn() -> SignerError;
pub type SignRegistrationChallengeErrorCb = fn() -> SignerError;

#[derive(Debug)]
pub struct MockSigner {
    fn_call_counts: Arc<MockSignerCallCounts>,
    supports_random: bool,
    handle: RwLock<Option<Handle>>,
    signer_mapper: Arc<SignerMapper>,
    keys: RwLock<HashMap<String, PKey<Private>>>,
    create_registration_key_error_cb: Option<CreateRegistrationKeyErrorCb>,
    sign_registration_challenge_error_cb: Option<SignRegistrationChallengeErrorCb>,
}

// test interface
impl MockSigner {
    pub fn new(
        signer_mapper: Arc<SignerMapper>,
        supports_random: bool,
        fn_call_counts: Arc<MockSignerCallCounts>,
        create_registration_key_error_cb: Option<CreateRegistrationKeyErrorCb>,
        sign_registration_challenge_error_cb: Option<SignRegistrationChallengeErrorCb>,
    ) -> Self {
        Self {
            fn_call_counts,
            supports_random,
            handle: RwLock::new(None),
            signer_mapper,
            keys: RwLock::new(HashMap::new()),
            create_registration_key_error_cb,
            sign_registration_challenge_error_cb,
        }
    }

    fn inc_fn_call_count(&self, fn_idx: FnIdx) {
        self.fn_call_counts.inc(fn_idx)
    }

    pub fn supports_random(&self) -> bool {
        self.inc_fn_call_count(FnIdx::SupportsRandom);
        self.supports_random
    }

    fn build_key(&self) -> Result<(PublicKey, PKey<Private>, KeyIdentifier, String), SignerError> {
        // generate a key pair
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        let public_key = Self::public_key_from_pkey(&pkey).unwrap();
        let key_identifier = public_key.key_identifier();

        // remember this private key by its "internal id"
        let internal_id = key_identifier.to_string();
        self.keys.write().unwrap().insert(internal_id.clone(), pkey.clone());

        // return the key details to the caller
        Ok((public_key, pkey, key_identifier, internal_id))
    }

    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(pkey: &PKey<Private>, challenge: &D) -> Result<Signature, SignerError> {
        let mut signer = ::openssl::sign::Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.update(challenge.as_ref())?;
        let signature = Signature::new(SignatureAlgorithm::default(), Bytes::from(signer.sign_to_vec()?));
        Ok(signature)
    }

    fn public_key_from_pkey(pkey: &PKey<Private>) -> Result<PublicKey, SignerError> {
        let mut b = Bytes::from(pkey.rsa().unwrap().public_key_to_der().unwrap());
        PublicKey::decode(&mut b).map_err(|_| SignerError::DecodeError)
    }

    fn internal_id_from_key_identifier(&self, key_identifier: &KeyIdentifier) -> Result<String, SignerError> {
        let lock = self.handle.read().unwrap();
        let signer_handle = lock.as_ref().unwrap();
        self.signer_mapper
            .get_key(signer_handle, key_identifier)
            .map_err(|_| SignerError::KeyNotFound)
    }

    fn load_key(&self, internal_id: &str) -> Option<PKey<Private>> {
        // "load" the private key from storage by its "internal id"
        let keys = self.keys.read().unwrap();
        keys.get(internal_id).cloned()
    }
}

// interface expected by SignerProvider
impl MockSigner {
    pub fn create_registration_key(&self) -> Result<(PublicKey, String), SignerError> {
        self.inc_fn_call_count(FnIdx::CreateRegistrationKey);
        if let Some(err_cb) = &self.create_registration_key_error_cb {
            return Err((err_cb)());
        }
        let (public_key, _, _, internal_id) = self.build_key().unwrap();
        Ok((public_key, internal_id))
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<Signature, SignerError> {
        self.inc_fn_call_count(FnIdx::SignRegistrationChallenge);
        if let Some(err_cb) = &self.sign_registration_challenge_error_cb {
            return Err((err_cb)());
        }
        let pkey = self.load_key(signer_private_key_id).ok_or(SignerError::KeyNotFound)?;

        // sign the given data using the loaded private key
        let signature = Self::sign_with_key(&pkey, challenge)?;

        // return the generated signature to the caller
        Ok(signature)
    }

    pub fn set_handle(&self, handle: Handle) {
        self.inc_fn_call_count(FnIdx::SetHandle);
        // remember the handle that has been generated for us so that we can use it when registering keys with the
        // signer mapper
        self.handle.write().unwrap().replace(handle);
    }

    pub fn get_name(&self) -> &str {
        self.inc_fn_call_count(FnIdx::GetName);
        "mock signer"
    }

    pub fn get_info(&self) -> Option<String> {
        self.inc_fn_call_count(FnIdx::GetInfo);
        None
    }
}

impl Signer for MockSigner {
    type KeyId = KeyIdentifier;

    type Error = SignerError;

    fn create_key(&self, _algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        self.inc_fn_call_count(FnIdx::CreateKey);
        let (_, _, key_identifier, internal_id) = self.build_key().unwrap();

        // tell the signer mapper we own this key identifier which maps to our "internal id"
        let lock = self.handle.read().unwrap();
        let signer_handle = lock.as_ref().unwrap();
        self.signer_mapper
            .add_key(signer_handle, &key_identifier, &internal_id)
            .unwrap();

        Ok(key_identifier)
    }

    fn get_key_info(&self, key_identifier: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        self.inc_fn_call_count(FnIdx::GetKeyInfo);
        let internal_id = self.internal_id_from_key_identifier(key_identifier).unwrap();
        let pkey = self.load_key(&internal_id).ok_or(KeyError::KeyNotFound)?;
        let public_key = Self::public_key_from_pkey(&pkey).unwrap();
        Ok(public_key)
    }

    fn destroy_key(&self, key_identifier: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        self.inc_fn_call_count(FnIdx::DestroyKey);
        let internal_id = self.internal_id_from_key_identifier(key_identifier).unwrap();
        let _ = self.keys.write().unwrap().remove(&internal_id);

        // remove the key from the signer mapper as well
        let lock = self.handle.read().unwrap();
        let signer_handle = lock.as_ref().unwrap();
        self.signer_mapper._remove_key(signer_handle, &key_identifier).unwrap();

        Ok(())
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_identifier: &Self::KeyId,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        self.inc_fn_call_count(FnIdx::Sign);
        let internal_id = self.internal_id_from_key_identifier(key_identifier)?;
        let pkey = self.load_key(&internal_id).ok_or(SignerError::KeyNotFound)?;
        Self::sign_with_key(&pkey, data).map_err(|err| SigningError::Signer(err))
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        _algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), Self::Error> {
        self.inc_fn_call_count(FnIdx::SignOneOff);
        let (public_key, pkey, _, internal_id) = self.build_key().unwrap();
        let signature = Self::sign_with_key(&pkey, data).unwrap();
        let _ = self.keys.write().unwrap().remove(&internal_id);
        Ok((signature, public_key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.inc_fn_call_count(FnIdx::Rand);

        // is this a poison pill?
        if target == b"WIPE_ALL_KEYS" {
            // wipe out all our keys, including the identity key used by the SignerRouter to verify that we are an
            // already known signer.
            self.keys.write().unwrap().clear();
        } else {
            // no, don't do anything, just leave the buffer as is
        }

        Ok(())
    }
}