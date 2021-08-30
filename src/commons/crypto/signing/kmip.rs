use std::{net::TcpStream, path::PathBuf, sync::Arc};

use bytes::Bytes;
use kmip::{
    types::{
        common::{
            KeyMaterial, ObjectType, Operation, TransparentRSAPrivateKey, TransparentRSAPublicKey, UniqueIdentifier,
        },
        request::{Attribute, RequestPayload},
        response::ManagedObject,
        response::{GetResponsePayload, KeyBlock, KeyValue, QueryResponsePayload, ResponsePayload},
    },
    Client, ClientBuilder,
};
use openssl::{
    error::ErrorStack,
    ssl::{SslConnector, SslFiletype, SslMethod, SslStream, SslVerifyMode},
};
use rpki::repository::crypto::{
    signer::KeyError, KeyIdentifier, PublicKey, PublicKeyFormat, Signature, SignatureAlgorithm, Signer, SigningError,
};

use super::{KeyMap, SignerError};

//------------ KmipSigner --------------------------------------------------

const TEMP_PUB_KEY_NAME: &'static str = "KrillKey-public";
const TEMP_PRIV_KEY_NAME: &'static str = "KrillKey-private";

fn default_kmip_port() -> u16 {
    // From: http://docs.oasis-open.org/kmip/profiles/v1.1/os/kmip-profiles-v1.1-os.html#_Toc332820682
    //   "KMIP servers using the Basic Authentication Suite SHOULD use TCP port number 5696, as assigned by IANA, to
    //    receive and send KMIP messages. KMIP clients using the Basic Authentication Suite MAY use the same 5696 TCP
    //    port number."
    5696
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConfigSignerKmip {
    pub host: String,

    #[serde(default = "default_kmip_port")]
    pub port: u16,

    #[serde(default)]
    pub insecure: bool,

    #[serde(default)]
    pub server_ca_cert_path: Option<PathBuf>,

    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,

    #[serde(default)]
    pub client_cert_private_key_path: Option<PathBuf>,

    #[serde(default)]
    pub username: Option<String>,

    #[serde(default)]
    pub password: Option<String>,
}

type KmipClient = Client<SslStream<TcpStream>>;

fn make_conn(config: &ConfigSignerKmip) -> Result<KmipClient, SignerError> {
    fn create_tls_client(config: &ConfigSignerKmip) -> Result<SslConnector, ErrorStack> {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        if config.insecure {
            connector.set_verify(SslVerifyMode::NONE);
        } else if let Some(path) = &config.server_ca_cert_path {
            connector.set_ca_file(path)?;
        }
        if let Some(path) = &config.client_cert_path {
            connector.set_certificate_file(path, SslFiletype::PEM)?;
        }
        if let Some(path) = &config.client_cert_private_key_path {
            connector.set_private_key_file(path, SslFiletype::PEM)?;
        }
        Ok(connector.build())
    }

    fn create_kmip_client(tls_stream: SslStream<TcpStream>, config: &ConfigSignerKmip) -> KmipClient {
        let mut client = ClientBuilder::new(tls_stream);
        if let Some(username) = &config.username {
            client = client.with_credentials(username.clone(), config.password.clone());
        }
        client.build()
    }

    let tls_client = create_tls_client(&config)
        .map_err(|err| SignerError::KmipError(format!("Failed to create TLS client: {}", err)))?;

    let tcp_stream = TcpStream::connect(format!("{}:{}", config.host, config.port))
        .map_err(|err| SignerError::KmipError(format!("Failed to connect: {}", err)))?;

    let tls_stream = tls_client
        .connect(&config.host, tcp_stream)
        .map_err(|err| SignerError::KmipError(format!("TLS handshake failed: {}", err)))?;

    Ok(create_kmip_client(tls_stream, config))
}

/// A KMIP based signer.
#[derive(Clone, Debug)]
pub struct KmipSigner {
    name: String,
    config: ConfigSignerKmip,
    supports_rng_retrieve: bool,
    key_lookup: Arc<KeyMap>,
}

impl KmipSigner {
    fn conn(&self) -> Result<KmipClient, SignerError> {
        make_conn(&self.config)
    }

    pub fn build(name: &str, config: &ConfigSignerKmip, key_lookup: Arc<KeyMap>) -> Result<Self, SignerError> {
        let name = name.to_string();

        let mut conn = make_conn(&config)?;

        // TODO: Is it okay to fail to start Krill if the KMIP server is unreachable?
        // info!("KMIP: Discovering provider details using {}", &conn);
        let res: QueryResponsePayload = conn
            .query()
            .map_err(|err| SignerError::KmipError(format!("Unable to query KMIP server info: {:?}", err)))?;

        info!("KMIP: Provider details: {:?}", res.vendor_identification);

        let operations = res.operations.unwrap_or(Vec::new());
        // We don't check every possible operation that we might need, only the major ones
        for op in &[Operation::CreateKeyPair, Operation::Sign] {
            if !operations.contains(&op) {
                return Err(SignerError::KmipError(format!(
                    "KMIP server cannot be used as it lacks support for the {:?} operation",
                    op
                )));
            }
        }

        let supports_rng_retrieve = operations.contains(&Operation::RNGRetrieve);

        if !supports_rng_retrieve {
            warn!(
                "KMIP server does not support the Rng Retrieve operation. Random numbers will be generated by Krill."
            );
        }

        Ok(KmipSigner {
            name,
            config: config.clone(),
            supports_rng_retrieve,
            key_lookup,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn get_public_key_from_id(&self, pub_id: &str) -> Result<PublicKey, SignerError> {
        let algorithm = PublicKeyFormat::Rsa;

        let res = self
            .conn()?
            .do_request(RequestPayload::Get(
                Some(UniqueIdentifier(pub_id.to_string())),
                None,
                None,
                None,
            ))
            .map_err(|err| SignerError::KmipError(format!("Failed to get key material: {:?}", err)))?;

        fn rsa_public_key_from_parts(modulus: &[u8], public_exponent: &[u8]) -> Result<bytes::Bytes, SignerError> {
            let modulus = bcder::Unsigned::from_slice(modulus).map_err(|_| SignerError::DecodeError)?;
            let public_exp = bcder::Unsigned::from_slice(public_exponent).map_err(|_| SignerError::DecodeError)?;
            let rsa_public_key = bcder::encode::sequence((modulus.encode(), public_exp.encode()));

            let mut bytes: Vec<u8> = Vec::new();
            rsa_public_key
                .write_encoded(bcder::Mode::Der, &mut bytes)
                .map_err(|err| {
                    SignerError::KmipError(format!(
                        "Failed to create DER encoded RSAPublicKey from constituent parts: {}",
                        err
                    ))
                })?;

            Ok(bytes::Bytes::from(bytes))
        }

        let rsa_public_key_bytes = if let ResponsePayload::Get(GetResponsePayload {
            object_type: ObjectType::PublicKey,
            cryptographic_object:
                ManagedObject::PublicKey(kmip::types::response::PublicKey {
                    key_block:
                        KeyBlock {
                            key_value: KeyValue { key_material: km, .. },
                            ..
                        },
                }),
            ..
        }) = res
        {
            match km {
                KeyMaterial::Bytes(bytes) => bytes::Bytes::from(bytes),
                KeyMaterial::TransparentRSAPublicKey(TransparentRSAPublicKey {
                    modulus: m,
                    public_exponent: p,
                }) => rsa_public_key_from_parts(&m, &p)?,
                KeyMaterial::TransparentRSAPrivateKey(TransparentRSAPrivateKey {
                    modulus: m,
                    public_exponent: Some(p),
                    ..
                }) => rsa_public_key_from_parts(&m, &p)?,
                _ => {
                    return Err(SignerError::KmipError(format!(
                        "Failed to get key material: key material type {:?} is not yet supported",
                        km
                    )));
                }
            }
        } else {
            return Err(SignerError::KmipError(
                "Failed to get key material: unsupported response payload from Get operation".to_string(),
            ));
        };

        let subject_public_key = bcder::BitString::new(0, rsa_public_key_bytes);

        use crate::bcder::encode::PrimitiveContent; // for .encode()
        let subject_public_key_info = bcder::encode::sequence((algorithm.encode(), subject_public_key.encode()));

        use crate::bcder::encode::Values; // for .write_encoded()
        let mut subject_public_key_info_source: Vec<u8> = Vec::new();
        subject_public_key_info
            .write_encoded(bcder::Mode::Der, &mut subject_public_key_info_source)
            .map_err(|err| {
                SignerError::KmipError(format!(
                    "Failed to create DER encoded SubjectPublicKeyInfo from constituent parts: {}",
                    err
                ))
            })?;

        // This public key format can be loaded with openssl dgst -keyform PEM if verifying manually that
        // signing is working. See below.
        // error!("XIMON: public key in PEM format:");
        // error!("-----BEGIN PUBLIC KEY-----");
        // error!(base64::encode(&subject_public_key_info_source)));
        // error!("-----END PUBLIC KEY-----");

        let public_key = PublicKey::decode(subject_public_key_info_source.as_slice()).map_err(|err| {
            SignerError::KmipError(format!(
                "Failed to create public key from the DER encoded SubjectPublicKeyInfo: {}",
                err
            ))
        })?;

        Ok(public_key)
    }

    fn find_key(&self, key_id: &KeyIdentifier, is_private: bool) -> Result<String, KeyError<SignerError>> {
        let key_name_prefix_vec = self.key_lookup.get_key(&self.name, key_id)?;
        let key_name_prefix = String::from_utf8(key_name_prefix_vec).map_err(|err| {
            KeyError::Signer(SignerError::KmipError(format!(
                "Failed to convert lookeded up key name prefix bytes to String: {}",
                err
            )))
        })?;

        let (key_type, key_name, human_key_class) = match is_private {
            false => (
                ObjectType::PublicKey,
                format!("{}-public", key_name_prefix),
                "public key",
            ),
            true => (
                ObjectType::PrivateKey,
                format!("{}-private", key_name_prefix),
                "private key",
            ),
        };

        trace!("KMIP: Finding key id for {} with ID {}", &human_key_class, &key_id);

        let res = self
            .conn()?
            .do_request(RequestPayload::Locate(vec![
                Attribute::Name(key_name),
                Attribute::ObjectType(key_type),
            ]))
            .map_err(|err| {
                KeyError::Signer(SignerError::KmipError(format!(
                    "Failed to perform find for {} with id {}: {:?}",
                    &human_key_class, &key_id, err
                )))
            })?;

        if let ResponsePayload::Locate(res) = res {
            match res.unique_identifiers.len() {
                0 => Err(KeyError::KeyNotFound),
                1 => Ok(res.unique_identifiers[0].to_string()),
                _ => Err(KeyError::Signer(SignerError::KmipError(format!(
                    "More than one {} found with id {}",
                    &human_key_class, &key_id
                )))),
            }
        } else {
            Err(KeyError::Signer(SignerError::KmipError(
                "Internal error: mismatched locate response payload type".to_string(),
            )))
        }
    }

    fn prepare_keys_for_use(&self, priv_id: &str, pub_id: &str) -> Result<(PublicKey, String), SignerError> {
        let public_key = self.get_public_key_from_id(&pub_id)?;
        let key_identifier = public_key.key_identifier();
        let key_name_prefix = hex::encode(key_identifier);
        let pub_key_name = format!("{}-public", key_name_prefix);
        let priv_key_name = format!("{}-private", key_name_prefix);

        let mut conn = self.conn()?;

        conn.do_request(RequestPayload::ModifyAttribute(
            Some(UniqueIdentifier(pub_id.to_string())),
            Attribute::Name(pub_key_name),
        ))
        .map_err(|err| SignerError::KmipError(format!("Failed to set name on new public key: {:?}", err)))?;
        conn.do_request(RequestPayload::ModifyAttribute(
            Some(UniqueIdentifier(priv_id.to_string())),
            Attribute::Name(priv_key_name),
        ))
        .map_err(|err| SignerError::KmipError(format!("Failed to set name on new private key: {:?}", err)))?;

        debug!(
            "KMIP: Generated pub/priv key pair with HSM IDs {} and {} and named {}-(public|private)",
            pub_id, priv_id, key_name_prefix
        );

        // It might be possible to combine this with the key creation step by setting an activation date attribute in
        // the past. At least one KMIP specification test case does this when registering (importing) a key, not sure if
        // it is possible when creating a key pair or if HSMs support it.
        conn.activate_key(&priv_id)
            .map_err(|err| SignerError::KmipError(format!("Failed to activate new private key: {:?}", err)))?;

        Ok((public_key, key_name_prefix))
    }

    fn build_key(&self, algorithm: PublicKeyFormat) -> Result<(PublicKey, String, String, String), SignerError> {
        if !matches!(algorithm, PublicKeyFormat::Rsa) {
            return Err(SignerError::KmipError(format!(
                "Algorithm {:?} not supported while creating key",
                &algorithm
            )));
        }

        trace!("KMIP: Generating key pair");

        let (priv_id, pub_id) = self
            .conn()?
            .create_rsa_key_pair(2048, TEMP_PRIV_KEY_NAME.into(), TEMP_PUB_KEY_NAME.into())
            .map_err(|err| SignerError::KmipError(format!("Failed to create key: {:?}", err)))?;

        let (public_key, key_name_prefix) = self.prepare_keys_for_use(&priv_id, &pub_id).or_else(|err| {
            // cleanup
            if let Err(err) = self.conn()?.destroy_key(&priv_id) {
                warn!("Failed to destroy KMIP private key with ID '{}: {:?}'", priv_id, err);
            }
            if let Err(err) = self.conn()?.destroy_key(&pub_id) {
                warn!("Failed to destroy KMIP public key with ID '{}: {:?}'", pub_id, err);
            }

            // propagate the original error
            Err(err)
        })?;

        Ok((public_key, pub_id, priv_id, key_name_prefix))
    }

    fn sign_with_key<D: AsRef<[u8]> + ?Sized>(
        &self,
        priv_id: &str,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<Signature, SignerError> {
        debug!("KMIP: Signing");

        if algorithm.public_key_format() != PublicKeyFormat::Rsa {
            return Err(SignerError::KmipError(format!(
                "Algorithm public key format not supported for signing: {:?}",
                algorithm.public_key_format()
            )));
        }

        let signed = self
            .conn()?
            .sign(priv_id, data.as_ref())
            .map_err(|err| SignerError::KmipError(format!("Failed to sign: {:?}", err)))?;

        let sig = Signature::new(SignatureAlgorithm::default(), Bytes::from(signed.signature_data));

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
        //
        // if you can't get the key out of the HSM using pkcs11-tool you can instead use the error! statements
        // above in get_public_key_from_id() which print out the public key in PEM format, and then use
        // -keyform PEM with the openssl dgst command instead of -keyform DER.

        Ok(sig)
    }

    fn delete_key_pair(&self, key_id: &KeyIdentifier) -> Result<(), SignerError> {
        if let Ok(id) = self.find_key(key_id, false) {
            self.conn()?
                .destroy_key(&id)
                .map_err(|err| SignerError::KmipError(format!("Failed to destroy public key: {:?}", err)))?;
        }
        if let Ok(id) = self.find_key(key_id, true) {
            // We have to revoke (deactivate) the activated private key before we are allowed to destroy it.
            self.conn()?
                .revoke_key(&id)
                .map_err(|err| SignerError::KmipError(format!("Failed to revoke private key: {:?}", err)))?;

            self.conn()?
                .revoke_key(&id)
                .map_err(|err| SignerError::KmipError(format!("Failed to destroy private key: {:?}", err)))?;
        }
        Ok(())
    }
}

impl Signer for KmipSigner {
    type KeyId = KeyIdentifier;
    type Error = SignerError;

    // TODO: extend the fn signature to accept a context string, e.g. CA name, to label the key with?
    fn create_key(&mut self, algorithm: PublicKeyFormat) -> Result<Self::KeyId, Self::Error> {
        let (key, _, _, key_name_prefix) = self.build_key(algorithm)?;
        let key_id = key.key_identifier();
        self.key_lookup
            .add_key(&self.name, key_id.clone(), key_name_prefix.as_bytes());
        Ok(key_id)
    }

    fn get_key_info(&self, key_id: &Self::KeyId) -> Result<PublicKey, KeyError<Self::Error>> {
        let pub_id = self.find_key(key_id, false)?;
        self.get_public_key_from_id(&pub_id)
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
        let priv_id = self.find_key(key_id, true).map_err(|err| match err {
            KeyError::KeyNotFound => SigningError::KeyNotFound,
            KeyError::Signer(err) => SigningError::Signer(err),
        })?;

        // error!("XIMON: sign: key name prefix: {}", hex::encode(key_id));

        self.sign_with_key(&priv_id, algorithm, data)
            .map_err(|err| SigningError::Signer(err))
    }

    // TODO: As this requires creating a key, shouldn't this be &mut like create_key() ?
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: SignatureAlgorithm,
        data: &D,
    ) -> Result<(Signature, PublicKey), SignerError> {
        let (key, _, priv_id, _) = self.build_key(PublicKeyFormat::Rsa)?;

        let signature = self.sign_with_key(&priv_id, algorithm, data.as_ref())?;

        self.delete_key_pair(&key.key_identifier())?;

        Ok((signature, key))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), SignerError> {
        if self.supports_rng_retrieve {
            // Should we seed the random number generator?
            let random_value = self
                .conn()?
                .rng_retrieve(target.len() as i32)
                .map_err(|err| SignerError::KmipError(format!("Failed to generate random value: {:?}", err)))?;
            target.copy_from_slice(random_value.data.as_slice());
            Ok(())
        } else {
            openssl::rand::rand_bytes(target)
                .map_err(|err| SignerError::KmipError(format!("Failed to generate ramdom value in s/w: {:?}", err)))
        }
    }
}
