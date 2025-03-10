use std::collections::HashMap;

use rpki::{
    ca::provisioning::ResourceClassName,
    crypto::KeyIdentifier,
    repository::{
        resources::ResourceSet, x509::Validity,
    },
};
use serde::{Deserialize, Serialize};

use crate::commons::{
    api::ca::{Revocation, RtaList, RtaName},
    error::Error,
    KrillResult,
};
use crate::commons::api::rta::ResourceTaggedAttestation; 

//------------ Rtas ---------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rtas {
    map: HashMap<RtaName, RtaState>,
}

impl Rtas {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn list(&self) -> RtaList {
        RtaList::new(self.map.keys().cloned().collect())
    }

    pub fn has(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    pub fn signed_rta(
        &self,
        name: &str,
    ) -> KrillResult<ResourceTaggedAttestation> {
        let state = self
            .map
            .get(name)
            .ok_or_else(|| Error::custom("Unknown RTA"))?;
        match state {
            RtaState::Signed(signed) => Ok(signed.rta.clone()),
            RtaState::Prepared(_) => {
                Err(Error::custom("RTA is not signed yet"))
            }
        }
    }

    pub fn prepared_rta(&self, name: &str) -> KrillResult<&PreparedRta> {
        let state = self
            .map
            .get(name)
            .ok_or_else(|| Error::custom("Unknown RTA"))?;
        match state {
            RtaState::Signed(_) => {
                Err(Error::custom("RTA was already signed"))
            }
            RtaState::Prepared(prepped) => Ok(prepped),
        }
    }

    pub fn add_prepared(&mut self, name: RtaName, prepared: PreparedRta) {
        self.map.insert(name, RtaState::Prepared(prepared));
    }

    pub fn add_signed(&mut self, name: RtaName, signed: SignedRta) {
        self.map.insert(name, RtaState::Signed(signed));
    }
}

//------------ RtaState -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RtaState {
    Prepared(PreparedRta),
    Signed(SignedRta),
}

//------------ PreparedRta --------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedRta {
    resources: ResourceSet,
    validity: Validity,
    keys: HashMap<ResourceClassName, KeyIdentifier>,
}

impl PreparedRta {
    pub fn new(
        resources: ResourceSet,
        validity: Validity,
        keys: HashMap<ResourceClassName, KeyIdentifier>,
    ) -> Self {
        PreparedRta {
            resources,
            validity,
            keys,
        }
    }

    pub fn validity(&self) -> Validity {
        self.validity
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    pub fn keys(&self) -> Vec<KeyIdentifier> {
        self.keys.values().cloned().collect()
    }

    pub fn key_map(&self) -> &HashMap<ResourceClassName, KeyIdentifier> {
        &self.keys
    }
}

//------------ SignedRta -----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedRta {
    resources: ResourceSet,
    revocation_info: HashMap<ResourceClassName, Revocation>,
    rta: ResourceTaggedAttestation,
}

impl SignedRta {
    pub fn new(
        resources: ResourceSet,
        revocation_info: HashMap<ResourceClassName, Revocation>,
        rta: ResourceTaggedAttestation,
    ) -> Self {
        SignedRta {
            resources,
            revocation_info,
            rta,
        }
    }

    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }
}

