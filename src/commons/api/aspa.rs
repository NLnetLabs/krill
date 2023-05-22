//! Autonomous System Provider Authorization
//!
//! This is still being discussed in the IETF. No RFC just yet.
//! See the following drafts:
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-profile/
//! https://datatracker.ietf.org/doc/draft-ietf-sidrops-aspa-verification/

use std::fmt;
use std::str::FromStr;

use rpki::repository::aspa::*;
use rpki::repository::resources::{AddressFamily, Asn};

pub type AspaCustomer = Asn;

//------------ AspaDefinitionUpdates -------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitionUpdates {
    add_or_replace: Vec<AspaDefinition>,
    remove: Vec<AspaCustomer>,
}

impl AspaDefinitionUpdates {
    pub fn new(add_or_replace: Vec<AspaDefinition>, remove: Vec<AspaCustomer>) -> Self {
        AspaDefinitionUpdates { add_or_replace, remove }
    }
    pub fn unpack(self) -> (Vec<AspaDefinition>, Vec<AspaCustomer>) {
        (self.add_or_replace, self.remove)
    }
}

impl fmt::Display for AspaDefinitionUpdates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Update ASPA definitions: ")?;
        if !self.add_or_replace.is_empty() {
            write!(f, " add or replace:")?;
            for definition in &self.add_or_replace {
                write!(f, " {}", definition)?;
            }
        }
        if !self.remove.is_empty() {
            write!(f, " remove where customer ASN is:")?;
            for as_id in &self.remove {
                write!(f, " {}", as_id)?;
            }
        }

        Ok(())
    }
}

//------------ AspaDefinitionList ----------------------------------------
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinitionList(Vec<AspaDefinition>);

impl AspaDefinitionList {
    pub fn new(definitions: Vec<AspaDefinition>) -> Self {
        AspaDefinitionList(definitions)
    }
}

impl fmt::Display for AspaDefinitionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for def in self.0.iter() {
            writeln!(f, "{}", def)?;
        }
        Ok(())
    }
}

//------------ AspaDefinition --------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaDefinition {
    customer: AspaCustomer,
    providers: Vec<ProviderAs>,
}

impl AspaDefinition {
    pub fn new(customer: AspaCustomer, providers: Vec<ProviderAs>) -> Self {
        AspaDefinition { customer, providers }
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

    /// Returns true if the customer is used in the provider list.
    /// This is not allowed by spec, and these definitions should
    /// be rejected by Krill.
    pub fn customer_used_as_provider(&self) -> bool {
        self.providers.iter().any(|p| p.provider() == self.customer)
    }

    /// Returns true if this is a single AFI AspaDefinition. Technically,
    /// it is allowed to omit one address family entirely, but this will
    /// be interpreted as thought the user specified an AS0 provider for
    /// the omitted AFI. This may be counterintuitive, so we'd better
    /// force people to make an explicit choice.
    pub fn providers_has_both_afis(&self) -> bool {
        let mut v4 = false;
        let mut v6 = false;
        for p in &self.providers {
            if !v4 {
                v4 = p.includes_v4();
            }
            if !v6 {
                v6 = p.includes_v6();
            }

            if v4 && v6 {
                break;
            }
        }

        v4 && v6
    }

    /// Applies an update. This is a no-op in case there is no
    /// actual change needed (i.e. this is idempotent).
    pub fn apply_update(&mut self, update: &AspaProvidersUpdate) {
        for removed in update.removed() {
            // If the operators tries to remove a provider for a specific AFI limit
            // only, and we have an existing provider without limit, then we should
            // keep the provider with the remaining limit.
            if let Some(limit) = removed.afi_limit() {
                if let Some(existing) = self
                    .providers
                    .iter()
                    .find(|existing| existing.provider() == removed.provider())
                {
                    match existing.afi_limit() {
                        None => {
                            let remaining = match limit {
                                AddressFamily::Ipv4 => ProviderAs::new_v6(existing.provider()),
                                AddressFamily::Ipv6 => ProviderAs::new_v4(existing.provider()),
                            };

                            self.providers.retain(|p| p.provider() != remaining.provider());
                            self.providers.push(remaining);
                        }
                        Some(_) => {
                            // retain all other ProviderAS, this will retain
                            // a possible ProviderAS for the removed ASN if
                            // its afiLimit was different.
                            self.providers.retain(|p| p != removed);
                        }
                    }
                }
            } else {
                // there is no limit in the removal, we should remove any existing
                // ProviderAS for the removed provider ASN regardless of limit.
                self.providers
                    .retain(|provider| provider.provider() != removed.provider());
            }
        }

        for added in update.added() {
            if let Some(existing) = self
                .providers
                .iter()
                .find(|e| e.provider() == added.provider())
                .copied()
            {
                // If there is any existing provider for the added, and if
                // that was using an afiLimit which was different, then we
                // need to merge this into an entry without a limit.
                //
                // In other words, if we hade provider listed for IPv4 and
                // the operator now adds the same provider for IPv6, then
                // we need to have this provider without afiLimit.
                //
                // And, if we hade provider listed for IPv4 and the operator
                // now adds the same provider without afiLimit, then we need
                // to have this provider without afiLimit.
                if existing.afi_limit().is_some() && existing.afi_limit() != added.afi_limit() {
                    // remove the existing entry, then add a new entry without limit
                    self.providers.retain(|p| p != &existing);
                    self.providers.push(ProviderAs::new(added.provider()));
                }
            } else {
                // no entry for this new provider ASN, add it as-is
                self.providers.push(*added);
            }
        }
        self.providers.sort_by_key(|p| p.provider());
    }
}

impl fmt::Display for AspaDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // example: 65000 => 65001, 65002(v4), 65003(v6)
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
            let customer_str = parts.next().ok_or(AspaDefinitionFormatError::CustomerAsMissing)?;
            AspaCustomer::from_str(customer_str.trim())
                .map_err(|_| AspaDefinitionFormatError::CustomerAsInvalid(customer_str.trim().to_string()))?
        };

        let mut providers = {
            let mut providers = vec![];
            let providers_str = parts.next().unwrap_or("<none>");

            if providers_str.trim() != "<none>" {
                let provider_parts = providers_str.split(',');
                for provider_part in provider_parts {
                    let provider = ProviderAs::from_str(provider_part.trim())
                        .map_err(|_| AspaDefinitionFormatError::ProviderAsInvalid(provider_part.trim().to_string()))?;
                    providers.push(provider);
                }
            }

            providers
        };

        // unexpected extra bits are not acceptable
        if parts.next().is_some() {
            Err(AspaDefinitionFormatError::ExtraParts)
        } else {
            // Ensure that the providers are sorted,  and there are no duplicates
            providers.sort_by_key(|p| p.provider());

            match providers
                .windows(2)
                .find(|pair| pair[0].provider() == pair[1].provider())
            {
                Some(dup) => Err(AspaDefinitionFormatError::ProviderAsDuplicate(dup[0], dup[1])),
                None => Ok(AspaDefinition::new(customer, providers)),
            }
        }
    }
}

//------------ AspaDefinitionFormatError ---------------------------------

#[derive(Clone, Debug)]
pub enum AspaDefinitionFormatError {
    CustomerAsMissing,
    CustomerAsInvalid(String),
    ProviderAsInvalid(String),
    ProviderAsDuplicate(ProviderAs, ProviderAs),
    ExtraParts,
}

impl fmt::Display for AspaDefinitionFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ASPA configuration format invalid: ")?;
        match self {
            AspaDefinitionFormatError::CustomerAsMissing => write!(f, "customer AS missing"),
            AspaDefinitionFormatError::CustomerAsInvalid(s) => write!(f, "cannot parse customer AS: {}", s),
            AspaDefinitionFormatError::ProviderAsInvalid(s) => write!(f, "cannot parse provider AS: {}", s),
            AspaDefinitionFormatError::ProviderAsDuplicate(l, r) => {
                write!(f, "duplicate AS in provider list. Found {} and {}", l, r)
            }
            AspaDefinitionFormatError::ExtraParts => write!(f, "found more than one '=>'"),
        }
    }
}

impl std::error::Error for AspaDefinitionFormatError {}

//------------ AspaProvidersUpdate ---------------------------------------

/// This type defines an update of ProviderAs entries for an existing
/// AspaDefinition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AspaProvidersUpdate {
    added: Vec<ProviderAs>,
    removed: Vec<ProviderAs>,
}

impl AspaProvidersUpdate {
    pub fn new(added: Vec<ProviderAs>, removed: Vec<ProviderAs>) -> Self {
        AspaProvidersUpdate { added, removed }
    }
    pub fn empty() -> Self {
        AspaProvidersUpdate {
            added: vec![],
            removed: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    pub fn contains_changes(&self) -> bool {
        !self.is_empty()
    }

    // Add a provider for both v4 and v6
    pub fn add(&mut self, provider: ProviderAs) {
        self.added.push(provider);
    }

    pub fn remove(&mut self, provider: ProviderAs) {
        self.removed.push(provider);
    }

    pub fn added(&self) -> &Vec<ProviderAs> {
        &self.added
    }

    pub fn removed(&self) -> &Vec<ProviderAs> {
        &self.removed
    }
}

impl fmt::Display for AspaProvidersUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.added.is_empty() {
            write!(f, "adding providers:")?;
            for added in &self.added {
                write!(f, " {}", added)?;
            }
            write!(f, " ")?;
        }
        if !self.removed.is_empty() {
            write!(f, "removing providers:")?;
            for removed in &self.removed {
                write!(f, " {}", removed)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn customer(s: &str) -> Asn {
        Asn::from_str(s).unwrap()
    }

    fn provider(s: &str) -> ProviderAs {
        ProviderAs::from_str(s).unwrap()
    }

    #[test]
    fn aspa_configuration_to_from_str() {
        let config = AspaDefinition::new(
            customer("AS65000"),
            vec![provider("AS65001"), provider("AS65002(v4)"), provider("AS65003(v6)")],
        );
        let config_str = "AS65000 => AS65001, AS65002(v4), AS65003(v6)";

        let to_str = config.to_string();
        assert_eq!(config_str, to_str.as_str());

        let from_str = AspaDefinition::from_str(config_str).unwrap();
        assert_eq!(config, from_str);
    }

    #[test]
    fn aspa_configuration_empty_providers_from_str() {
        let config = AspaDefinition::new(customer("AS65000"), vec![]);
        let config_str = "AS65000 => <none>";

        let to_str = config.to_string();
        assert_eq!(config_str, to_str.as_str());

        let from_str = AspaDefinition::from_str(config_str).unwrap();
        assert_eq!(config, from_str);
    }
}
