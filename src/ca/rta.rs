//! Resource Tagged Attestations.

use std::collections::HashMap;
use rpki::ca::provisioning::ResourceClassName;
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::ResourceSet;
use rpki::repository::x509::Validity;
use serde::{Deserialize, Serialize};
use crate::commons::KrillResult;
use crate::commons::api::ca::{Revocation, RtaList, RtaName};
use crate::commons::api::rta::ResourceTaggedAttestation; 
use crate::commons::error::Error;


//------------ Rtas ---------------------------------------------------------

/// The set of RTAs held by a CA.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rtas {
    /// The RTAs keyed by their name.
    map: HashMap<RtaName, RtaState>,
}

impl Rtas {
    /// Returns whether the set of RTAs is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns a list of all current RTAs.
    pub fn list(&self) -> RtaList {
        RtaList::new(self.map.keys().cloned().collect())
    }

    /// Returns whether the set has an RTA with the given name.
    pub fn has(&self, name: &str) -> bool {
        self.map.contains_key(name)
    }

    /// Returns the RTA with the given name if it is already signed.
    ///
    /// Returns an error if there is no such RTA or if it is currently in
    /// prepared state.
    pub fn signed_rta(
        &self, name: &str,
    ) -> KrillResult<ResourceTaggedAttestation> {
        let state = self.map.get(name).ok_or_else(|| {
            Error::custom("Unknown RTA")
        })?;
        match state {
            RtaState::Signed(signed) => Ok(signed.rta.clone()),
            RtaState::Prepared(_) => {
                Err(Error::custom("RTA is not signed yet"))
            }
        }
    }

    /// Returns the prepare RTA with the given name.
    ///
    /// Returns an error if there is no such RTA or if it is already signed.
    pub fn prepared_rta(&self, name: &str) -> KrillResult<&PreparedRta> {
        let state = self.map.get(name).ok_or_else(|| {
            Error::custom("Unknown RTA")
        })?;
        match state {
            RtaState::Signed(_) => {
                Err(Error::custom("RTA was already signed"))
            }
            RtaState::Prepared(prepped) => Ok(prepped),
        }
    }

    /// Adds a prepared RTA with the given name.
    pub fn add_prepared(&mut self, name: RtaName, prepared: PreparedRta) {
        self.map.insert(name, RtaState::Prepared(prepared));
    }

    /// Adds a signed RTA with the given name.
    pub fn add_signed(&mut self, name: RtaName, signed: SignedRta) {
        self.map.insert(name, RtaState::Signed(signed));
    }
}


//------------ RtaState -----------------------------------------------------

/// The state of an RTA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RtaState {
    /// The RTA is currently being prepared.
    Prepared(PreparedRta),

    /// The RTA is signed and ready to go.
    Signed(SignedRta),
}


//------------ PreparedRta --------------------------------------------------

/// An RTA currently being prepared.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedRta {
    /// The resources contained in the RTA.
    resources: ResourceSet,

    /// The validity of the RTA.
    validity: Validity,

    /// The keys used to sign the RTA from the various resource classes.
    keys: HashMap<ResourceClassName, KeyIdentifier>,
}

impl PreparedRta {
    /// Creates a new prepared RTA.
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

    /// Returns the validity of the RTA.
    pub fn validity(&self) -> Validity {
        self.validity
    }

    /// Returns the resources of the RTA.
    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }

    /// Returns an iterator over the keys of the RTA.
    pub fn keys(&self) -> impl Iterator<Item = KeyIdentifier> + '_ {
        self.keys.values().copied()
    }

    /// Returns an iterator over the keys and their resource classes.
    pub fn rcn_keys(
        &self
    ) -> impl Iterator<Item = (&ResourceClassName, KeyIdentifier)> + '_ {
        self.keys.iter().map(|(rcn, key)| (rcn, *key))
    }
}


//------------ SignedRta -----------------------------------------------------

/// An RTA having been signed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedRta {
    /// The resources of the RTA.
    resources: ResourceSet,

    /// Revocation information for the various resource classes.
    revocation_info: HashMap<ResourceClassName, Revocation>,

    /// The actual RTA.
    rta: ResourceTaggedAttestation,
}

impl SignedRta {
    /// Creats a new signed RTA.
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

    /// Returns the resources of the RTA.
    pub fn resources(&self) -> &ResourceSet {
        &self.resources
    }
}

