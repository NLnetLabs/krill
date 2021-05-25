use std::{ops::Deref, path::Path, sync::{Arc, atomic::{AtomicU8, Ordering}}};

use bytes::Bytes;
use once_cell::sync::OnceCell;
use pkcs11::{types::*, Ctx};
use rpki::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use crate::constants::test_mode_enabled;

use super::{KeyMap, SignerError};

//------------ Pkcs11Signer --------------------------------------------------

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigSignerPkcs11 {
    pub lib_path: String,
    pub user_pin: String,
    pub slot_id: CK_SLOT_ID,
}

static ONE_CTX: OnceCell<Arc<Ctx>> = OnceCell::new();
static CTX_REF_COUNT: AtomicU8 = AtomicU8::new(0);

#[derive(Debug)]
struct Pkcs11Ctx {
    ctx: Arc<Ctx>,
}

impl Pkcs11Ctx {
    pub fn new(lib_path: &Path) -> Result<Self, SignerError> {
        let ctx = ONE_CTX.get_or_try_init(|| -> Result<Arc<Ctx>, SignerError> {
            info!("PKCS#11: Initializing");

            let mut ctx = Ctx::new(lib_path)
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to create context: {}", err)))?;

            // TODO: are these arg values okay?
            let mut args = CK_C_INITIALIZE_ARGS::new();
            args.CreateMutex = None;
            args.DestroyMutex = None;
            args.LockMutex = None;
            args.UnlockMutex = None;
            args.flags = CKF_OS_LOCKING_OK;

            ctx.initialize(Some(args))
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to initialize context: {}", err)))?;

            Ok(Arc::new(ctx))
        })?;

        Ok(Pkcs11Ctx { ctx: ctx.clone() })
    }
}

impl Deref for Pkcs11Ctx {
    type Target = Ctx;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl Drop for Pkcs11Ctx {
    fn drop(&mut self) {
        if CTX_REF_COUNT.fetch_sub(1, Ordering::SeqCst) == 1 {
            trace!("PKCS#11: Finalizing context..");
            if let Some(ctx) = Arc::get_mut(&mut self.ctx) {
                if let Err(err) = ctx.finalize() {
                    warn!("PKCS#11: Failed to finalize context: {}", err);
                }
            } else {
                warn!("PKCS#11: Failed to finalize context: Internal error: Could not acquire mutable reference");
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Pkcs11Session {
    ctx: Arc<Pkcs11Ctx>,
    handle: CK_SESSION_HANDLE,
    logged_in: bool,
}

impl Pkcs11Session {
    pub fn new(ctx: Arc<Pkcs11Ctx>, slot_id: CK_SLOT_ID) -> Result<Self, SignerError> {
        // PKCS#11 v2.21: "For legacy reasons, the CKF_SERIAL_SESSION bit must always be set"
        let handle = ctx
            .open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to open PKCS#11 session: {}", err)))?;
        Ok(Self {
            ctx,
            handle,
            logged_in: false,
        })
    }

    fn login(&mut self, user: CK_USER_TYPE, pin: Option<&str>) -> Result<(), SignerError> {
        info!("PKCS#11: Logging in");
        self.ctx
            .login(self.handle, user, pin)
            .or_else(|err| {
                if matches!(err, pkcs11::errors::Error::Pkcs11(CKR_USER_ALREADY_LOGGED_IN)) && test_mode_enabled() {
                    warn!("PKCS#11: Ignoring error CKR_USER_ALREADY_LOGGED_IN because test mode is enabled");
                    return Ok(());
                }
                Err(err)
            })
            .map_err(|err| SignerError::Pkcs11Error(format!("Login failed: {}", err)))?;
        self.logged_in = true;
        Ok(())
    }
}

impl Deref for Pkcs11Session {
    type Target = CK_SESSION_HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for Pkcs11Session {
    fn drop(&mut self) {
        trace!("PKCS#11: Auto-closing session");
        if self.logged_in {
            debug!("PKCS#11: Session being closed is a login session, logging out");
            if let Err(err) = self.ctx.logout(self.handle) {
                warn!("PKCS#11: Logout failed: {}", err);
            }
            self.logged_in = false;
        }
        if let Err(err) = self.ctx.close_session(self.handle) {
            warn!("PKCS#11: Close session failed: {}", err);
        }
    }
}

/// A PKCS#11 based signer.
#[derive(Clone, Debug)]
pub struct Pkcs11Signer {
    name: String,
    ctx: Arc<Pkcs11Ctx>,
    login_session: Pkcs11Session,
    slot_id: CK_SLOT_ID,
    key_lookup: Arc<KeyMap>,
}

impl Pkcs11Signer {
    pub fn build(name: &str, config: &ConfigSignerPkcs11, key_lookup: Arc<KeyMap>) -> Result<Self, SignerError> {
        // softhsm2-util --init-token --slot 0 --label "My token 1"
        //    ... User PIN: 7890
        //    ... is re-assigned to slot 313129207
        //
        // Useful commands:
        //   softhsm2-util --show-slots
        //   sudo apt-install -y opensc # to install pkcs11-tool
        //   `
        //   pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -p 7890 --delete-object --id <ID>> --type <privkey|pubkey>
        // let user_pin = "7890";
        // let lib_path = Path::new("/usr/local/lib/softhsm/libsofthsm2.so");
        // let slot_id = 313129207;

        let name = name.to_string();
        let ctx = Arc::new(Pkcs11Ctx::new(Path::new(&config.lib_path))?);
        let slot_id = config.slot_id;
        let mut login_session = Pkcs11Session::new(ctx.clone(), slot_id)?;

        login_session.login(CKU_USER, Some(&config.user_pin))?;

        Ok(Pkcs11Signer {
            name,
            ctx,
            login_session,
            slot_id,
            key_lookup,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn open_session(&self) -> Result<Pkcs11Session, SignerError> {
        Pkcs11Session::new(self.ctx.clone(), self.slot_id)
    }

    fn get_public_key_from_handle(&self, pub_handle: u64) -> Result<PublicKey, SignerError> {
        let session = self.open_session()?;

        // Modern strategy for acquiring the SPKI:
        // =======================================
        // PKCS#11 2.40+ supports a public key attribute called CKA_PUBLIC_KEY_INFO which yields a byte array of the DER
        // encoded SubjectPublicKeyInfo so this is ideal. However, tokens that implement older PKCS#11 standard versions
        // don't support it, and even in compatible implementations the attribute is allowed to be empty (and in testing
        // with SoftHSMv2 it is empty for example). So, first, try to get this attribute and use it:

        // TODO: Factor out initial attribute length lookup and actual attribute value fetch to helper function
        // TODO: Add trace and debug level logging to indicate when the HSM is being queried and which logic path is
        // being followed.

        // Construct it from the modulus and exponent of the public key. These are available via CKA_ key attributes,
        // but again these might be empty. If we can't get the exponent we can assume that it is the value we requested
        // that it should be. There's no way we can work around not being able to get the modulus however.

        trace!("PKCS#11: Generating SubjectPublicKeyInfo using RSA modulus and public exponent key attributes");

        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT));
        let (_, res_vec) = self
            .ctx
            .get_attribute_value(*session, pub_handle, &mut pub_template)
            .map_err(|err| {
                SignerError::Pkcs11Error(format!("Failed to get modulus and/or public exponent lengths: {}", err))
            })?;

        let mut modulus = Vec::with_capacity(res_vec[0].ulValueLen as usize);
        let mut public_exp = Vec::with_capacity(res_vec[1].ulValueLen as usize);
        modulus.resize(res_vec[0].ulValueLen as usize, 0);
        public_exp.resize(res_vec[1].ulValueLen as usize, 0);
        pub_template.clear();
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS).with_bytes(modulus.as_mut_slice()));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(public_exp.as_mut_slice()));
        self.ctx
            .get_attribute_value(*session, pub_handle, &mut pub_template)
            .map_err(|err| {
                SignerError::Pkcs11Error(format!("Failed to get modulus and/or public exponent value: {}", err))
            })?;

        // TODO: use the input exponent value from the top of this function if we got a zero length exponent attribute
        // value back from the PKCS#11 interface.

        // TODO: work out how to encode the fetched values as a DER format SPKI for passing to PublicKey::decode().

        // From: https://tools.ietf.org/html/rfc5280#section-4.1 Internet X.509 Public Key Infrastructure
        //       Certificate and Certificate Revocation List (CRL) ProfileBasic Certificate Fields
        //
        //     SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //         algorithm              AlgorithmIdentifier,
        //         subjectPublicKey       BIT STRING  }
        //
        //     AlgorithmIdentifier   ::=  SEQUENCE  {
        //         algorithm              OBJECT IDENTIFIER,
        //         parameters             ANY DEFINED BY algorithm OPTIONAL  }
        //
        // The subjectPublicKey bit string is a DER encoding of the following ASN.1 definition:
        //
        //     RSAPublicKey          ::= SEQUENCE {
        //         modulus               INTEGER, -- n
        //         publicExponent        INTEGER -- e
        //     }
        //
        // We have the algorithm (aka PublicKeyFormat struct), modulus and publicExponent values but we have no way
        // to construct a PublicKey struct (aka SubjectPublicKeyInfo) from them. One way to do this is to transform
        // the PKCS#11 "Big Integer" modulus and publicExponent byte array values into a DER encoded ASN.1 sequence
        // hierarchy as described above, and use PublicKey::decode() to then create the PublicKey struct instance
        // that we need.
        //
        // From the PKCS#11 2.20 spec:
        //
        //   "Big integer a string of CK_BYTEs representing an unsigned integer of arbitrary size, most-significant
        //    byte first (e.g., the integer 32768 is represented as the 2-byte string 0x80 0x00)"
        //
        // We need to encode this as an ASN.1 INTEGER.

        let algorithm = PublicKeyFormat::Rsa;

        use crate::bcder::encode::PrimitiveContent; // for .encode()
        let modulus = bcder::Unsigned::from_be_bytes(modulus);
        let public_exp = bcder::Unsigned::from_be_bytes(public_exp);

        let rsa_public_key = bcder::encode::sequence((modulus.encode(), public_exp.encode()));

        use crate::bcder::encode::Values; // for .write_encoded()
        let mut rsa_public_key_bytes: Vec<u8> = Vec::new();
        rsa_public_key
            .write_encoded(bcder::Mode::Der, &mut rsa_public_key_bytes)
            .map_err(|err| {
                SignerError::Pkcs11Error(format!(
                    "Failed to create DER encoded RSAPublicKey from constituent parts: {}",
                    err
                ))
            })?;

        let subject_public_key = bcder::BitString::new(0, bytes::Bytes::from(rsa_public_key_bytes));

        let subject_public_key_info = bcder::encode::sequence((algorithm.encode(), subject_public_key.encode()));

        let mut subject_public_key_info_source: Vec<u8> = Vec::new();
        subject_public_key_info
            .write_encoded(bcder::Mode::Der, &mut subject_public_key_info_source)
            .map_err(|err| {
                SignerError::Pkcs11Error(format!(
                    "Failed to create DER encoded SubjectPublicKeyInfo from constituent parts: {}",
                    err
                ))
            })?;

        let public_key = PublicKey::decode(subject_public_key_info_source.as_slice()).map_err(|err| {
            SignerError::Pkcs11Error(format!(
                "Failed to create public key from the DER encoded SubjectPublicKeyInfo: {}",
                err
            ))
        })?;

        Ok(public_key)
    }

    fn find_key(
        &self,
        key_id: &KeyIdentifier,
        key_class: CK_OBJECT_CLASS,
    ) -> Result<CK_OBJECT_HANDLE, KeyError<SignerError>> {
        let session = self.open_session()?;

        let human_key_class = match key_class {
            CKO_PUBLIC_KEY => "public key",
            CKO_PRIVATE_KEY => "private key",
            _ => "key",
        };

        trace!(
            "PKCS#11: Finding key handle for {} with ID {}",
            &human_key_class,
            &key_id
        );

        let cka_id = self.key_lookup.get_key(&self.name, key_id)?;

        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        template.push(CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&key_class));
        template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(cka_id.as_slice()));

        self.ctx.find_objects_init(*session, &template).map_err(|err| {
            SignerError::Pkcs11Error(format!(
                "Failed to initialize find for {} with id {}: {}",
                &human_key_class, &key_id, err
            ))
        })?;

        let max_object_count = 2;
        let res = self.ctx.find_objects(*session, max_object_count).map_err(|err| {
            SignerError::Pkcs11Error(format!(
                "Failed to perform find for {} with id {}: {}",
                &human_key_class, &key_id, err
            ))
        });
        let res = match res {
            Err(err) => {
                self.ctx.find_objects_final(*session).map_err(|err2| {
                    KeyError::Signer(SignerError::Pkcs11Error(format!(
                        "Failed to finalize find for {} with id {}: {} (after find failed with error: {}",
                        &human_key_class, &key_id, err2, err
                    )))
                })?;
                Err(KeyError::Signer(err))
            }
            Ok(results) => match results.len() {
                0 => Err(KeyError::KeyNotFound),
                1 => Ok(results[0]),
                _ => Err(KeyError::Signer(SignerError::Pkcs11Error(format!(
                    "More than one {} found with id {}",
                    &human_key_class, &key_id
                )))),
            },
        };

        if let Err(err) = self.ctx.find_objects_final(*session).map_err(|err| {
            KeyError::Signer(SignerError::Pkcs11Error(format!(
                "Failed to finalize find for {} with id {}: {}",
                &human_key_class, &key_id, err
            )))
        }) {
            warn!("PKCS#11: {}", err);
        }

        trace!("PKCS#11: Found key with handle: {:?}", res);

        res
    }

    fn build_key(
        &self,
        algorithm: PublicKeyFormat,
    ) -> Result<(PublicKey, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, [u8; 20]), SignerError> {
        // https://tools.ietf.org/html/rfc6485#section-3: Asymmetric Key Pair Formats
        //   "The RSA key pairs used to compute the signatures MUST have a 2048-bit
        //    modulus and a public exponent (e) of 65,537."

        if !matches!(algorithm, PublicKeyFormat::Rsa) {
            return Err(SignerError::Pkcs11Error(format!(
                "Algorithm {:?} not supported while creating key",
                &algorithm
            )));
        }

        let mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        // A note about PKCS#11 public and private key handle lifetimes:
        //
        // From the PKCS#11 v2.20 specification section 9.4 Object types:
        //
        //   Cryptoki represents object information with the following types:
        //
        //   ♦ CK_OBJECT_HANDLE; CK_OBJECT_HANDLE_PTR
        //
        //   CK_OBJECT_HANDLE is a token-specific identifier for an object. It is defined as
        //   follows:
        //
        //     typedef CK_ULONG CK_OBJECT_HANDLE;
        //
        //   When an object is created or found on a token by an application, Cryptoki assigns it an
        //   object handle for that application’s sessions to use to access it. A particular object on a
        //   token does not necessarily have a handle which is fixed for the lifetime of the object;
        //   however, if a particular session can use a particular handle to access a particular object,
        //   then that session will continue to be able to use that handle to access that object as long
        //   as the session continues to exist, the object continues to exist, and the object continues to
        //   be accessible to the session.
        //
        // Thus WE CANNOT PERSIST THESE HANDLE VALUES in our key value storage and use them later to work with the keys.
        // Instead we must lookup the keys based on one or more attribute values. We might be able to cache handle
        // values for the lifetime of the Krill process. We also therefore have to ensure that there are attributes of
        // the keys that we know or can control the value of.
        //
        // One way to lookup the keys is using the CKA_MODULUS and CKA_PUBLIC_EXPONENT attributes as these can be
        // derived from the public key itself, and according to the PKCS#11 v2.20 specification section 12.1.2 "RSA
        // public key objects" and section 12.1.3 "RSA private key objects" are available for CKK_RSA keys as genearated
        // by the CKM_RSA_PKCS_KEY_PAIR_GEN mechanism which we use here. However, with KMIP it isn't possible to locate
        // a key by its modulus, it is however possible to locate a key by its Digest. This is also theoretically
        // possible with PKCS#11 via the CKA_HASH_OF_SUBJECT_PUBLIC_KEY attribute, but the PKCS#11 v2.20 specification
        // allows this attribute to be empty and indeed with SoftHSMv2 it is empty. It is unclear if "real" PKCS#11
        // implementations support this attribute, but at least the AWS CloudHSM does not appear to support it as
        // https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes.html doesn't include it under the
        // GetAttributeValue heading. So, there isn't a common approach we can use in both the PKCS#11 and KMIP cases.
        //
        // Thus, if we cannot rely on an attribute of the key that we can derive from the key itself such as its modulus
        // or hash, we must instead set an attribute on the key and we must do that at key creation time (as AWS
        // CloudHSM doesn't permit adding or modifying attributes once the key is created), and so it cannot be set to
        // the hash of the key bits as the key bits aren not yet known. We can just generate a random value and use that
        // as the attribute value that can be used to lookup the key in future. For PKCS#11 we can use the store this
        // value in the CKA_ID attribute. In KMIP we might be able to just use the Unique Identifier string attribute
        // that the server is required to generate and persist. From the KMIP 1.0 specification: "This attribute SHALL
        // be assigned by the key management system at creation or registration time, and then SHALL NOT be changed or
        // deleted before the object is destroyed". However, the public and private keys receive their own distinct
        // Unique Identifier values and we want a single identifier to refer to both at the same time. The CKA_ID
        // PKCS#11 permits CKA_ID values of public and private keys to be the same. It's unclear from the PKCS#11 spec
        // if CKA_ID should actually be the X.509 "Key Identifier", the spec has some advice on this matter but
        // acknowledges that the values could be anything. The alternative would be to use the CKA_LABEL field but it
        // might be desirable to set that to something descriptive, e.g. something about Krill and the CA a key relates
        // to, it is even conceivable that the label is something a HSM operator might feel they can edit to give the
        // keys names that they can easily keep track of. Similar concerns may be valid for the KMIP Name attribute, but
        // it's unclear what alternative can be used. There is a KMIP Application Specific Information attribute but the
        // server can reject setting this if the "Application Namespace" is not supported, whatever that means. KMIP has
        // a "Custom Attribute" that can be set by clients, the only requirement being that the name begin with "x-".
        // PyKMIP at least seems to support it but it's unknown if this is supported by real KMIP implementations.
        //
        // For now we will use CKA_ID for PKCS#11 and "Name" for KMIP as both have been seen to work on all platforms
        // tested so far.

        let mut pub_template: Vec<CK_ATTRIBUTE> = Vec::new();

        // As a quick test on AWS CloudHSM, store an in-memory only mapping of KeyIdentifier -> PKCS#11 CKA_ID, and
        // generate the CKA_ID here now for storing on the key at creation time.
        let mut cka_id: [u8; 20] = [0; 20];
        self.rand(&mut cka_id)?;
        pub_template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(&cka_id));

        pub_template.push(CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&CK_FALSE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));

        // AWS CloudHSM requires CKA_PRIVATE to be true for a public key
        // See: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes.html
        pub_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_TRUE));
        pub_template.push(CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(&2048));
        pub_template.push(CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_bytes(&[0x01, 0x00, 0x01]));
        pub_template.push(CK_ATTRIBUTE::new(CKA_LABEL).with_string("Krill"));

        let mut priv_template: Vec<CK_ATTRIBUTE> = Vec::new();

        // AWS CloudHSM quick test
        priv_template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(&cka_id));

        priv_template.push(CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE));

        // AWS CloudHSM requires CKA_PRIVATE to be true for a private key
        // See: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes.html
        priv_template.push(CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&CK_TRUE));

        priv_template.push(CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE));
        priv_template.push(CK_ATTRIBUTE::new(CKA_LABEL).with_string("Krill"));

        // Attempting to use CKA_ALLOWED_MECHANISMS with Kryptus causes error CKA_INVALID_MECHANISM_TYPE with:
        //   > command_line_client.py man get-knet-server-version
        //     Version:  1.25.0
        //
        //   > pkcs11-tool --module /path/to/libkNETPKCS11.so -I
        //     Cryptoki version 2.40
        //     Manufacturer     KRYPTUS
        //     Library          PKCS11 (ver 1.7)
        //     Using slot 0 with a present token (0x3e8)

        // let param = [CKM_SHA256_RSA_PKCS];
        // let mut allowed_mechanisms_attr = CK_ATTRIBUTE::new(CKA_ALLOWED_MECHANISMS);
        // allowed_mechanisms_attr.ulValueLen = ::std::mem::size_of::<CK_MECHANISM_TYPE>() as u64; // TODO: is 'as' safe?
        // allowed_mechanisms_attr.pValue = &param as *const CK_MECHANISM_TYPE as CK_VOID_PTR;

        // pub_template.push(allowed_mechanisms_attr);
        // priv_template.push(allowed_mechanisms_attr);

        trace!(
            "PKCS#11: Generating key pair with templates: public key={:?}, private key={:?}",
            &pub_template,
            &priv_template
        );

        let session = self.open_session()?;
        let (pub_handle, priv_handle) = self
            .ctx
            .generate_key_pair(*session, &mech, &pub_template, &priv_template)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to create key: {}", err)))?;

        // TODO: if we encounter an error from this point on should we delete the keys that we just created?

        let public_key = self.get_public_key_from_handle(pub_handle)?;
        let key_identifier = public_key.key_identifier();

        // TODO: C_SetAttributeValue is not supported by AWS CloudHSM.
        // Attempting to set an attribute causes error CKR_FUNCTION_NOT_SUPPORTED (0x54).
        // See: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-apis.html
        // let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        // template.push(CK_ATTRIBUTE::new(CKA_ID).with_bytes(key_identifier.as_slice()));
        // self.ctx
        //     .set_attribute_value(*session, pub_handle, &template)
        //     .map_err(|err| SignerError::Pkcs11Error(format!("Failed to set attributes on public key: {}", err)))?;
        // self.ctx
        //     .set_attribute_value(*session, priv_handle, &template)
        //     .map_err(|err| SignerError::Pkcs11Error(format!("Failed to set attributes on private key: {}", err)))?;

        debug!("PKCS#11: Generated key pair with ID {}", &key_identifier);

        Ok((public_key, pub_handle, priv_handle, cka_id))
    }

    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(
        &self,
        priv_handle: CK_OBJECT_HANDLE,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SignerError> {
        debug!("PKCS#11: Signing");

        if algorithm.public_key_format() != PublicKeyFormat::Rsa {
            return Err(SignerError::Pkcs11Error(format!(
                "Algorithm public key format not supported for signing: {:?}",
                algorithm.public_key_format()
            )));
        }

        // Note: The AWS CloudHSM Known Issues for the PKCS#11 Library states:
        // https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-pkcs11-sdk.html#ki-pkcs11-7
        //
        //   Issue: You could not hash more than 16KB of data
        //   For larger buffers, only the first 16KB will be hashed and returned. The excess data would have been
        //   silently ignored.
        //   Resolution status: Data less than 16KB in size continues to be sent to the HSM for hashing. We have added
        //   capability to hash locally, in software, data between 16KB and 64KB in size. The client and the SDKs will
        //   explicitly fail if the data buffer is larger than 64KB. You must update your client and SDK(s) to version
        //   1.1.1 or higher to benefit from the fix.
        //
        // TODO: if data is larger than 16KB we should hash locally and only use the HSM for signing, not for hashing.
        // Should we enable this behaviour based on detection of an AWS CloudHSM or a config flag or ??? As an example,
        // Oracle enables an AWS CloudHSM specific workaround by detecting a CLOUDHSM_IGNORE_CKA_MODIFIABLE_FALSE
        // environment variable.

        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_RSA_PKCS,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };

        let session = self.open_session()?;
        self.ctx
            .sign_init(*session, &mech, priv_handle)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to initialize sign: {}", err)))?;

        let signed = self
            .ctx
            .sign(*session, data.as_ref())
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to sign: {}", err)))?;

        let sig = Signature::new(SignatureAlgorithm::default(), Bytes::from(signed));

        // temporarily for testing purposes log some data we can use to verify that signing is working correctly:
        //   (plus we also log the key identifier in the caller fn sign())
        // error!("XIMON: data to sign: {}", hex::encode(data));
        // error!("XIMON: signed data : {}", hex::encode(&signed));
        // error!("XIMON: signature   : {}", hex::encode(sig.value()));
        // with these values we can copy paste the hex data into files and use this command to convert it back to
        // binary:
        //   $ xxd -r -p <input hex file> <output binary file>
        // then we can export the public key from SoftHSMv2 with this command:
        //   $ pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -p <USER_PIN> --read-object --type pubkey \
        //       --id <SIGNING KEY ID> -o /tmp/key.pub
        // then we can verify that the data was signed correctly with this command:
        //   $ openssl dgst -verify /tmp/key.pub -keyform DER -sha256 -signature /tmp/sig.bin -binary /tmp/in.bin
        //     Verified OK

        Ok(sig)
    }

    fn delete_key_pair(&self, key_id: &KeyIdentifier) -> Result<(), SignerError> {
        debug!("PKCS#11: Deleting key pair with ID {}", &key_id);

        let session = self.open_session()?;

        if let Ok(pub_handle) = self.find_key(key_id, CKO_PUBLIC_KEY) {
            self.ctx
                .destroy_object(*session, pub_handle)
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to delete public key: {}", err)))?;
        }

        if let Ok(priv_handle) = self.find_key(key_id, CKO_PRIVATE_KEY) {
            self.ctx
                .destroy_object(*session, priv_handle)
                .map_err(|err| SignerError::Pkcs11Error(format!("Failed to delete private key: {}", err)))?;
        }

        Ok(())
    }
}

impl Signer for Pkcs11Signer {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    // TODO: extend the fn signature to accept a context string, e.g. CA name, to label the key with?
    fn create_key(&mut self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let (key, _, _, cka_id) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.key_lookup.add_key(&self.name, key_id.clone(), &cka_id[..]);
        Ok(key_id)
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let pub_handle = self.find_key(key_id, CKO_PUBLIC_KEY)?;
        self.get_public_key_from_handle(pub_handle)
            .map_err(|err| KeyError::Signer(err))
    }

    fn destroy_key(&mut self, key_id: &Self::KeyId) -> Result<(), KeyError<Self::Error>> {
        self.delete_key_pair(key_id).map_err(|err| KeyError::Signer(err))
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &Self::KeyId,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SigningError<Self::Error>> {
        let priv_handle = self.find_key(key_id, CKO_PRIVATE_KEY).map_err(|err| match err {
            KeyError::KeyNotFound => SigningError::KeyNotFound,
            KeyError::Signer(err) => SigningError::Signer(err),
        })?;

        self.sign_with_key(priv_handle, algorithm, data)
            .map_err(|err| SigningError::Signer(err))
    }

    // TODO: As this requires creating a key, shouldn't this be &mut like create_key() ?
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        let (key, _, priv_handle, _) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature = self.sign_with_key(priv_handle, algorithm, data.as_ref())?;

        self.delete_key_pair(&key.key_identifier())?;

        Ok((signature, key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        // Should we seed the random number generator?
        let session = self.open_session()?;
        let random_value = self
            .ctx
            .generate_random(*session, target.len() as CK_ULONG)
            .map_err(|err| SignerError::Pkcs11Error(format!("Failed to generate random value: {}", err)))?;
        target.copy_from_slice(random_value.as_slice());
        Ok(())
    }
}
