use std::collections::HashMap;

use rpki::repository::crypto::KeyIdentifier;

/// KMIP key identifiers needed to use keys stored in the HSM.
#[derive(Clone, Debug)]
pub struct KmipKeyPairIds {
    pub public_key_id: String,
    pub private_key_id: String,
}

/// An in-memory mapping of Krill [KeyIdentifier] to KMIP server internal key pair identifiers.
pub type KeyMap = HashMap<KeyIdentifier, KmipKeyPairIds>;
