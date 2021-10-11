//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/
//!

use std::{collections::HashMap, fmt::Debug};

use rpki::repository::{aspa::Aspa, x509::Time};

use crate::commons::api::{AsProviderAttestation, AspaCustomer};

//------------ AspaDefinitions ---------------------------------------------

/// This type contains the ASPA definitions for a CA. Generally speaking
/// the [`AspaCustomer`] ASN will be held in a single [`ResourceClass`] only,
/// but at least in theory the CA could issue ASPA objects in each RC that
/// holds the ASN.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitions {
    attestations: HashMap<AspaCustomer, AsProviderAttestation>,
}

impl AspaDefinitions {}

/// # Set operations
///
impl AspaDefinitions {
    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

impl Default for AspaDefinitions {
    fn default() -> AspaDefinitions {
        AspaDefinitions {
            attestations: HashMap::new(),
        }
    }
}

//------------ AspaObjects -------------------------------------------------

/// ASPA objects held by a resource class in a CA.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaObjects {
    v4: HashMap<AspaCustomer, AspaInfo>,
    v6: HashMap<AspaCustomer, AspaInfo>,
}

//------------ AspaInfo ----------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AspaInfo {
    aspa: Aspa,
    since: Time, // Creation time
}

impl AspaInfo {
    pub fn new(aspa: Aspa, since: Time) -> Self {
        AspaInfo { aspa, since }
    }
    pub fn new_aspa(aspa: Aspa) -> Self {
        AspaInfo::new(aspa, Time::now())
    }

    pub fn aspa(&self) -> &Aspa {
        &self.aspa
    }

    pub fn since(&self) -> Time {
        self.since
    }
}

impl PartialEq for AspaInfo {
    fn eq(&self, other: &Self) -> bool {
        self.aspa.to_captured().as_slice() == other.aspa.to_captured().as_slice()
    }
}

impl Eq for AspaInfo {}
