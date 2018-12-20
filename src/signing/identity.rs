use ext_serde;
use rpki::remote::idcert::IdCert;
use rpki::signing::signer::KeyId;


//------------ MyIdentity ----------------------------------------------------

/// This type stores identity details for a client or server involved in RPKI
/// provisioning (up-down) or publication.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MyIdentity {
    name: String,

    #[serde(
    deserialize_with = "ext_serde::de_id_cert",
    serialize_with = "ext_serde::ser_id_cert")]
    id_cert: IdCert,

    #[serde(
    deserialize_with = "ext_serde::de_key_id",
    serialize_with = "ext_serde::ser_key_id")]
    key_id: KeyId
}

impl MyIdentity {
    pub fn new(name: &str, id_cert: IdCert, key_id: KeyId) -> Self {
        MyIdentity {
            name: name.to_string(),
            id_cert,
            key_id
        }
    }

    /// The name for this actor.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The identity certificate for this actor.
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    /// The identifier that the Signer needs to use the key for the identity
    /// certificate.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

impl PartialEq for MyIdentity {
    fn eq(&self, other: &MyIdentity) -> bool {
        self.name == other.name &&
            self.id_cert.to_bytes() == other.id_cert.to_bytes() &&
            self.key_id == other.key_id
    }
}

impl Eq for MyIdentity {}