//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::fmt;

use rpki::repository::aspa::*;
use rpki::repository::resources::AsId;

pub type AspaCustomer = AsId;

//------------ ProviderAsFamilyLimit -----------------------------------

//------------ AspaConfiguration -----------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaConfiguration {
    customer: AspaCustomer,
    providers: Vec<ProviderAs>,
}

impl AspaConfiguration {
    pub fn new(customer: AspaCustomer, providers: Vec<ProviderAs>) -> Self {
        AspaConfiguration { customer, providers }
    }

    pub fn unpack(self) -> (AspaCustomer, Vec<ProviderAs>) {
        (self.customer, self.providers)
    }

    pub fn customer(&self) -> AspaCustomer {
        self.customer
    }

    pub fn providers(&self) -> &Vec<ProviderAs> {
        &self.providers
    }

    pub fn verify_update(&self, updates: &ProviderAsUpdates) -> Result<(), ProviderAsUpdateConflict> {
        let mut error = ProviderAsUpdateConflict::default();
        for provider in updates.removed() {
            if !self.providers.contains(provider) {
                error.add_unknown(*provider)
            }
        }
        for provider in updates.added() {
            if self.providers.contains(provider) {
                error.add_duplicate(*provider)
            }
        }

        if error.is_empty() {
            Ok(())
        } else {
            Err(error)
        }
    }
}

impl fmt::Display for AspaConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ASPA config for customer ASN: {} ", self.customer)?;
        write!(f, "with providers:")?;
        for provider in &self.providers {
            write!(f, " {}", provider)?;
        }
        Ok(())
    }
}

//------------ ProviderAsUpdates -----------------------------------------

/// This type defines a delta of ProviderAss intended for an
/// AspaCustomer. I.e. additions and removals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderAsUpdates {
    customer: AspaCustomer,
    added: Vec<ProviderAs>,
    removed: Vec<ProviderAs>,
}

impl ProviderAsUpdates {
    pub fn empty(customer: AspaCustomer) -> Self {
        ProviderAsUpdates {
            customer,
            added: vec![],
            removed: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    // Add a provider for both v4 and v6
    pub fn add(&mut self, provider: ProviderAs) {
        self.added.push(provider);
    }

    pub fn remove(&mut self, provider: ProviderAs) {
        self.removed.push(provider);
    }

    pub fn customer(&self) -> AspaCustomer {
        self.customer
    }

    pub fn added(&self) -> &Vec<ProviderAs> {
        &self.added
    }

    pub fn removed(&self) -> &Vec<ProviderAs> {
        &self.removed
    }
}

impl fmt::Display for ProviderAsUpdates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "updated ASPA config for customer ASN: {}", self.customer)?;
        if !self.added.is_empty() {
            write!(f, " adding providers:")?;
            for added in &self.added {
                write!(f, " {}", added)?;
            }
        }
        if !self.removed.is_empty() {
            write!(f, " removing providers:")?;
            for removed in &self.removed {
                write!(f, " {}", removed)?;
            }
        }
        writeln!(f)
    }
}

//------------ ProviderAsUpdateConflict ----------------------------------

/// This type contains a detailed error report for an ASPA
/// that could not be applied.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderAsUpdateConflict {
    duplicates: Vec<ProviderAs>,
    unknowns: Vec<ProviderAs>,
}

impl ProviderAsUpdateConflict {
    pub fn add_duplicate(&mut self, provider: ProviderAs) {
        self.duplicates.push(provider);
    }

    pub fn add_unknown(&mut self, provider: ProviderAs) {
        self.unknowns.push(provider);
    }

    pub fn is_empty(&self) -> bool {
        self.duplicates.is_empty() && self.unknowns.is_empty()
    }
}

impl Default for ProviderAsUpdateConflict {
    fn default() -> Self {
        Self {
            duplicates: vec![],
            unknowns: vec![],
        }
    }
}

impl fmt::Display for ProviderAsUpdateConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.duplicates.is_empty() {
            writeln!(f, "Cannot add the following duplicate provider(s): ")?;
            for dup in &self.duplicates {
                writeln!(f, "  {}", dup)?;
            }
        }

        if !self.unknowns.is_empty() {
            writeln!(f, "Cannot remove the following unknown provider(s): ")?;
            for unk in &self.unknowns {
                writeln!(f, "  {}", unk)?;
            }
        }

        Ok(())
    }
}
