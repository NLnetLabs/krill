use std::collections::HashSet;
use std::fmt;

use crate::{constants::ACTOR_KRILL, commons::api::{RoaDefinition, RoaDefinitionUpdates}};
use crate::commons::bgp::make_roa_tree;
use crate::daemon::krillserver::KrillServer;

pub async fn roa_cleanup(server: &KrillServer) -> Result<(), RoaCleanupError> {
    for ca in server.ca_list(ACTOR_KRILL)?.cas() {
        info!("Will check ROAs for CA: {}", ca.handle());

        let roas = server.ca_routes_show(ca.handle()).await?;

        if roas.is_empty() {
            info!("No ROAs found for CA: {}", ca.handle());
        } else {
            info!("ROAs found for CA: {}", ca.handle());
            for def in roas.iter() {
                info!("{}", def);
            }
        }

        if let Some(updates) = clean(roas) {
            info!("Will clean up ROAs as follows:\n{}", updates);
            server.ca_routes_update(ca.handle().clone(), updates, ACTOR_KRILL).await?;
        } else {
            info!("No clean up needed");
        }
    }

    Ok(())
}

fn clean(roas: Vec<RoaDefinition>) -> Option<RoaDefinitionUpdates> {
    let tree = make_roa_tree(roas.as_slice());

    let mut added = HashSet::new();
    let mut removed = HashSet::new();

    for roa in roas.into_iter() {
        // if this ROA is covered by any other ROA

        let prefix = roa.prefix();
        let asn = roa.asn();

        let mut should_remove = false;

        for covering in tree.matching_or_less_specific(&prefix) {
            if covering == &roa || covering.asn() != asn {
                continue;
            }

            if covering.prefix() == prefix && roa.max_length().is_none() {
                should_remove = true;
                break;
            }

            if covering.effective_max_length() > roa.effective_max_length() {
                // covering prefix is bigger and allows this
                should_remove = true;
                break;
            }
        }

        if should_remove {
            removed.insert(roa);
        } else if roa.max_length().is_none() {
            // If this does not have a max length then remove
            // this one and add the equivalent with max length.
            // Note: if that equivalent would have existed this
            // roa would have been marked for removal
            let with_length = RoaDefinition::new(asn, prefix, Some(roa.effective_max_length()));
            removed.insert(roa);
            added.insert(with_length);
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        Some(RoaDefinitionUpdates::new(added, removed))
    } else {
        None
    }
}

#[derive(Debug)]
pub struct RoaCleanupError(String);

impl fmt::Display for RoaCleanupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<crate::commons::error::Error> for RoaCleanupError {
    fn from(e: crate::commons::error::Error) -> Self {
        RoaCleanupError(e.to_string())
    }
}

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test::definition;
    use std::collections::HashSet;

    #[test]
    fn upgrade_roa_cleanup() {
        let roas = vec![
            definition("192.0.0.0/8-8 => 64496"),       // keep
            definition("192.168.0.0/16 => 64496"),      // remove there is a longer ml
            definition("192.168.0.0/16-16 => 64496"),   // remove there is a longer ml
            definition("192.168.0.0/16-20 => 64496"),   // keep
            definition("192.168.0.0/16-18 => 64496"),   // remove there is a longer ml
            definition("192.168.0.0/18-20 => 64496"),   // remove covering has longer ml
            definition("192.168.0.0/18-24 => 64496"),   // keep, this is more permissive for specific bit
            definition("192.168.127.0/24-24 => 64496"), // keep, this is more specific
            definition("192.168.0.0/16-20 => 64497"),   // different asn -> keep
            definition("10.0.0.0/8 => 64496"),          // replace with one with max length
            definition("10.0.1.0/24 => 64498"),         // remove, there is one with explicit ml
            definition("10.0.1.0/24-24 => 64498"),      // keep
        ];

        let update = clean(roas).unwrap();

        let mut expected_added = HashSet::new();
        expected_added.insert(definition("10.0.0.0/8-8 => 64496"));

        let mut expected_removed = HashSet::new();
        expected_removed.insert(definition("10.0.0.0/8 => 64496"));
        expected_removed.insert(definition("10.0.1.0/24 => 64498"));
        expected_removed.insert(definition("192.168.0.0/16 => 64496"));
        expected_removed.insert(definition("192.168.0.0/16-16 => 64496"));
        expected_removed.insert(definition("192.168.0.0/16-18 => 64496"));
        expected_removed.insert(definition("192.168.0.0/18-20 => 64496"));

        let expected = RoaDefinitionUpdates::new(expected_added, expected_removed);

        assert_eq!(update, expected);
    }
}
