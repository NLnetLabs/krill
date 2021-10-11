//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::fmt;

use rpki::repository::resources::AsId;

pub type AspaCustomer = AsId;
pub type AspaProvider = AsId;

//------------ AsProviderAttestation -------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AsProviderAttestation {
    customer: AspaCustomer,
    v4_providers: Vec<AspaProvider>,
    v6_providers: Vec<AspaProvider>,
}

//------------ AspaProviderUpdates -----------------------------------------

/// This type defines a delta of AspaProviders intended for an
/// AspaCustomer. I.e. additions and removals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaProviderUpdates {
    customer: AspaCustomer,
    v4_added: Vec<AspaProvider>,
    v4_removed: Vec<AspaProvider>,
    v6_added: Vec<AspaProvider>,
    v6_removed: Vec<AspaProvider>,
}

impl AspaProviderUpdates {
    pub fn empty(customer: AspaCustomer) -> Self {
        AspaProviderUpdates {
            customer,
            v4_added: vec![],
            v4_removed: vec![],
            v6_added: vec![],
            v6_removed: vec![],
        }
    }

    // Add a provider for both v4 and v6
    pub fn add(&mut self, provider: AspaProvider) {
        self.v4_added.push(provider);
        self.v6_added.push(provider);
    }

    pub fn add_v4_only(&mut self, provider: AspaProvider) {
        self.v4_added.push(provider);
    }

    pub fn add_v6_only(&mut self, provider: AspaProvider) {
        self.v6_added.push(provider);
    }

    pub fn remove(&mut self, provider: AspaProvider) {
        self.v4_removed.push(provider);
        self.v6_removed.push(provider);
    }

    pub fn remove_v4_only(&mut self, provider: AspaProvider) {
        self.v4_removed.push(provider);
    }

    pub fn remove_v6_only(&mut self, provider: AspaProvider) {
        self.v6_removed.push(provider);
    }

    pub fn customer(&self) -> AspaCustomer {
        self.customer
    }

    pub fn v4_added(&self) -> &Vec<AspaProvider> {
        &self.v4_added
    }

    pub fn v6_added(&self) -> &Vec<AspaProvider> {
        &self.v6_added
    }

    pub fn v4_removed(&self) -> &Vec<AspaProvider> {
        &self.v4_removed
    }

    pub fn v6_removed(&self) -> &Vec<AspaProvider> {
        &self.v6_removed
    }
}

impl fmt::Display for AspaProviderUpdates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Updating ASPA for customer ASN: {}", self.customer)?;
        if !self.v4_added.is_empty() {
            write!(f, "  adding IPv4 providers:")?;
            for added in &self.v4_added {
                write!(f, " {}", added)?;
            }
            writeln!(f)?;
        }
        if !self.v6_added.is_empty() {
            write!(f, "  adding IPv6 providers:")?;
            for added in &self.v6_added {
                write!(f, " {}", added)?;
            }
            writeln!(f)?;
        }
        if !self.v4_removed.is_empty() {
            write!(f, "  removing IPv4 providers:")?;
            for added in &self.v4_removed {
                write!(f, " {}", added)?;
            }
            writeln!(f)?;
        }
        if !self.v6_removed.is_empty() {
            write!(f, "  removing IPv6 providers:")?;
            for added in &self.v6_removed {
                write!(f, " {}", added)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
