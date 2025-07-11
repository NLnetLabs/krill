//! Autonomous System Provider Authorizations.
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the drafts
//! <https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/> and
//! <https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/>

use std::{error, fmt};
use std::str::FromStr;
use rpki::repository::resources::Asn;
use serde::{Deserialize, Serialize};


//------------- Type Aliases -------------------------------------------------

/// The type of a customer ASN.
//
//  *Warning:* This type is used in stored state.
pub type CustomerAsn = Asn;

/// The type of a provider ASN.
//
//  *Warning:* This type is used in stored state.
pub type ProviderAsn = Asn;


//------------ AspaDefinitionUpdates -----------------------------------------

/// Information for an ASPA definition update.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitionUpdates {
    /// Definitions to add or replace.
    ///
    /// Definitions in this list will be added if their customer ASN doesn’t
    /// exist yet or will be updated if they do.
    pub add_or_replace: Vec<AspaDefinition>,

    /// Definitions to remove.
    ///
    /// Definitions with these customer ASNs will be removed.
    pub remove: Vec<CustomerAsn>,
}

impl fmt::Display for AspaDefinitionUpdates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Update ASPA definitions: ")?;
        if !self.add_or_replace.is_empty() {
            write!(f, " add or replace:")?;
            for definition in &self.add_or_replace {
                write!(f, " {definition}")?;
            }
        }
        if !self.remove.is_empty() {
            write!(f, " remove where customer ASN is:")?;
            for as_id in &self.remove {
                write!(f, " {as_id}")?;
            }
        }

        Ok(())
    }
}


//------------ AspaDefinitionList ----------------------------------------

/// A list of ASPA definitions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitionList(Vec<AspaDefinition>);

impl AspaDefinitionList {
    pub fn new(definitions: Vec<AspaDefinition>) -> Self {
        AspaDefinitionList(definitions)
    }

    pub fn as_slice(&self) -> &[AspaDefinition] {
        self.0.as_slice()
    }
}

impl fmt::Display for AspaDefinitionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for def in self.0.iter() {
            writeln!(f, "{def}")?;
        }
        Ok(())
    }
}


//------------ AspaDefinition ------------------------------------------------

/// The definition of an ASPA record.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinition {
    /// The customer ASN.
    pub customer: CustomerAsn,

    /// The list of provider ASNs.
    ///
    /// This is not necessarily an acceptable list yet, i.e., it may be
    /// unordered, contain duplicates, or contain the customer ASN.
    pub providers: Vec<ProviderAsn>,
}

impl AspaDefinition {
    /// Returns true if the customer is used in the provider list.
    ///
    /// This is not allowed by spec, and these definitions should
    /// be rejected by Krill.
    pub fn customer_used_as_provider(&self) -> bool {
        self.providers.contains(&self.customer)
    }

    /// Returns true if there are duplicate provider ASNs.
    ///
    /// This is not allowed by spec and these definitions should be
    /// rejected by Krill.
    pub fn contains_duplicate_providers(&self) -> bool {
        let mut providers: Vec<Asn> = self.providers.clone();

        let len_before_duplicates = providers.len();

        providers.sort();
        providers.dedup();

        len_before_duplicates > providers.len()
    }

    /// Applies an update to the definition.
    ///
    /// The update is lenient, i.e., adding exsting ASNs and removing
    /// non-existing ASNs is fine. After the update, the provider ASNs are
    /// sorted.
    pub fn apply_update(&mut self, update: &AspaProvidersUpdate) {
        for removed in &update.removed {
            self.providers.retain(|provider| provider != removed);
        }

        for added in &update.added {
            if !self.providers.contains(added) {
                self.providers.push(*added);
            }
        }
        self.providers.sort();
    }
}

impl fmt::Display for AspaDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // example: 65000 => 65001, 65002, 65003
        write!(f, "{} => ", self.customer)?;
        if self.providers.is_empty() {
            write!(f, "<none>")?;
        } else {
            for i in 0..self.providers.len() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", self.providers[i])?;
            }
        }
        Ok(())
    }
}

impl FromStr for AspaDefinition {
    type Err = AspaDefinitionFormatError;

    // example: 65000 => 65001, 65002(v4), 65003(v6)
    // example: 65000 => <none>
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split("=>");

        let customer = {
            let customer_str = parts
                .next()
                .ok_or(AspaDefinitionFormatError::CustomerAsMissing)?;
            CustomerAsn::from_str(customer_str.trim()).map_err(|_| {
                AspaDefinitionFormatError::CustomerAsInvalid(
                    customer_str.trim().to_string(),
                )
            })?
        };

        let mut providers = {
            let mut providers = vec![];
            let providers_str = parts.next().unwrap_or("<none>");

            if providers_str.trim() != "<none>" {
                let provider_parts = providers_str.split(',');
                for provider_part in provider_parts {
                    let provider = ProviderAsn::from_str(
                        provider_part.trim(),
                    )
                    .map_err(|_| {
                        AspaDefinitionFormatError::ProviderAsInvalid(
                            provider_part.trim().to_string(),
                        )
                    })?;
                    providers.push(provider);
                }
            }

            providers
        };

        // unexpected extra bits are not acceptable
        if parts.next().is_some() {
            Err(AspaDefinitionFormatError::ExtraParts)
        } else {
            // Ensure that the providers are sorted,  and there are no
            // duplicates
            providers.sort();

            match providers.windows(2).find(|pair| pair[0] == pair[1]) {
                Some(dup) => {
                    Err(AspaDefinitionFormatError::ProviderAsDuplicate(
                        dup[0], dup[1],
                    ))
                }
                None => Ok(AspaDefinition { customer, providers }),
            }
        }
    }
}


//------------ AspaProvidersUpdate -------------------------------------------

/// An update to the provider ASN list of an ASPA definition.
//
//  *Warning:* This type is used in stored state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaProvidersUpdate {
    /// A list of ASNs to be added to the provider ASNs.
    pub added: Vec<ProviderAsn>,

    /// A list of ASNs to be removed from the provider ASNs.
    pub removed: Vec<ProviderAsn>,
}

impl AspaProvidersUpdate {
    /// Returns whether the update is empty.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

impl fmt::Display for AspaProvidersUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.added.is_empty() {
            write!(f, "adding providers:")?;
            for added in &self.added {
                write!(f, " {added}")?;
            }
            write!(f, " ")?;
        }
        if !self.removed.is_empty() {
            write!(f, "removing providers:")?;
            for removed in &self.removed {
                write!(f, " {removed}")?;
            }
        }
        Ok(())
    }
}


//============ Error Types ===================================================

//------------ AspaDefinitionFormatError -------------------------------------

/// An error happened while parsing an ASPA definition.
#[derive(Clone, Debug)]
pub enum AspaDefinitionFormatError {
    /// The customer ASN was missing.
    CustomerAsMissing,

    /// The customer ASN was invalid.
    CustomerAsInvalid(String),

    /// The given provider ASN definition was invalid.
    ProviderAsInvalid(String),

    /// The given two provider ASNs are duplicates.
    ProviderAsDuplicate(ProviderAsn, ProviderAsn),

    /// There was trailing text in the definition.
    ExtraParts,
}

impl fmt::Display for AspaDefinitionFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ASPA configuration format invalid: ")?;
        match self {
            AspaDefinitionFormatError::CustomerAsMissing => {
                write!(f, "customer AS missing")
            }
            AspaDefinitionFormatError::CustomerAsInvalid(s) => {
                write!(f, "cannot parse customer AS: {s}")
            }
            AspaDefinitionFormatError::ProviderAsInvalid(s) => {
                write!(f, "cannot parse provider AS: {s}")
            }
            AspaDefinitionFormatError::ProviderAsDuplicate(l, r) => {
                write!(
                    f,
                    "duplicate AS in provider list. Found {l} and {r}"
                )
            }
            AspaDefinitionFormatError::ExtraParts => {
                write!(f, "found more than one '=>'")
            }
        }
    }
}

impl error::Error for AspaDefinitionFormatError {}


//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn customer(s: &str) -> Asn {
        Asn::from_str(s).unwrap()
    }

    fn provider(s: &str) -> ProviderAsn {
        ProviderAsn::from_str(s).unwrap()
    }

    #[test]
    fn aspa_configuration_to_from_str() {
        let config = AspaDefinition {
            customer: customer("AS65000"),
            providers: vec![
                provider("AS65001"),
                provider("AS65002"),
                provider("AS65003"),
            ],
        };
        let config_str = "AS65000 => AS65001, AS65002, AS65003";

        let to_str = config.to_string();
        assert_eq!(config_str, to_str.as_str());

        let from_str = AspaDefinition::from_str(config_str).unwrap();
        assert_eq!(config, from_str);
    }

    #[test]
    fn aspa_configuration_empty_providers_from_str() {
        let config = AspaDefinition {
            customer: customer("AS65000"),
            providers: vec![]
        };
        let config_str = "AS65000 => <none>";

        let to_str = config.to_string();
        assert_eq!(config_str, to_str.as_str());

        let from_str = AspaDefinition::from_str(config_str).unwrap();
        assert_eq!(config, from_str);
    }
}

