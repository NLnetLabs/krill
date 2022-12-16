//! Data types used to support importing a CA structure for testing or automated set ups.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer};

use rpki::{
    ca::idexchange::{CaHandle, ParentHandle},
    repository::resources::ResourceSet,
    uri,
};

use crate::{
    commons::api::PublicationServerUris,
    daemon::{config, ta::ta_handle},
};

use super::RoaConfiguration;

/// This type contains the full structure of CAs and signed objects etc that is
/// set up when the import API is used.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Structure {
    pub ta_aia: uri::Rsync,
    pub ta_uri: uri::Https,
    pub publication_server_uris: PublicationServerUris,
    pub cas: Vec<ImportCa>,
}

impl Structure {
    pub fn new(
        ta_aia: uri::Rsync,
        ta_uri: uri::Https,
        publication_server_uris: PublicationServerUris,
        cas: Vec<ImportCa>,
    ) -> Self {
        Structure {
            ta_aia,
            ta_uri,
            publication_server_uris,
            cas,
        }
    }

    /// Check that all parents are valid for the CAs in this structure
    /// in the order in which they appear, and that the parent CAs have
    /// the resources for each child CA.
    pub fn validate_ca_hierarchy(&self) -> Result<(), String> {
        // Note we define the parent child relationship in the child only.
        // So, the child refers to one or more parents that should have already
        // been seen in the import structure.
        //
        // Furthermore, the child defines which resources it will get from
        // the named parent. So we *also* expect that the parent claimed
        // all those resources itself.
        //
        // We will always have a TA, with ALL resources in this setup. This
        // TA is not mentioned in the CAs part of this structure. So, we
        // will mark it as implicitly seen.
        let mut seen: HashMap<ParentHandle, ResourceSet> = HashMap::new();
        let ta_handle = ta_handle();
        seen.insert(ta_handle.convert(), ResourceSet::all());
        for ca in &self.cas {
            if ca.handle == ta_handle {
                return Err(format!("CA name {} is reserved.", ta_handle));
            }
            let mut ca_resources = ResourceSet::empty();
            for ca_parent in &ca.parents {
                if let Some(seen_parent_resources) = seen.get(ca_parent.handle()) {
                    if seen_parent_resources.contains(&ca_parent.resources) {
                        ca_resources = ca_resources.union(&ca_parent.resources);
                    } else {
                        return Err(format!(
                            "CA '{}' under parent '{}' claims resources not held by parent.",
                            ca.handle,
                            ca_parent.handle()
                        ));
                    }
                } else {
                    return Err(format!(
                        "CA '{}' wants parent '{}', but this parent CA does not appear before this CA.",
                        ca.handle,
                        ca_parent.handle()
                    ));
                }
            }
            seen.insert(ca.handle.convert(), ca_resources);
        }
        Ok(())
    }

    pub fn into_cas(self) -> Vec<ImportCa> {
        self.cas
    }
}

fn deserialize_parent<'de, D>(deserializer: D) -> Result<Vec<ImportParent>, D::Error>
where
    D: Deserializer<'de>,
{
    config::OneOrMany::<ImportParent>::deserialize(deserializer).map(|oom| oom.into())
}

/// This type describes a CaStructure that needs to be imported. I.e. it describes
/// a CA at the top of a branch and recursively includes 0 or more children of this
/// same type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportCa {
    handle: CaHandle,

    // In the majority of cases there will only be one parent, so use that for json
    // but allow one or more parents to be configured.
    #[serde(rename = "parent", deserialize_with = "deserialize_parent")]
    parents: Vec<ImportParent>,

    #[serde(default = "Vec::new")]
    roas: Vec<RoaConfiguration>,
}

impl ImportCa {
    pub fn new(handle: CaHandle, parents: Vec<ImportParent>, roas: Vec<RoaConfiguration>) -> Self {
        ImportCa { handle, parents, roas }
    }

    pub fn unpack(self) -> (CaHandle, Vec<ImportParent>, Vec<RoaConfiguration>) {
        (self.handle, self.parents, self.roas)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportParent {
    handle: ParentHandle,
    resources: ResourceSet,
}

impl ImportParent {
    pub fn new(handle: ParentHandle, resources: ResourceSet) -> Self {
        ImportParent { handle, resources }
    }

    pub fn handle(&self) -> &ParentHandle {
        &self.handle
    }

    pub fn unpack(self) -> (ParentHandle, ResourceSet) {
        (self.handle, self.resources)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_cas_only() {
        let json = include_str!("../../../test-resources/bulk-ca-import/structure.json");

        let structure: Structure = serde_json::from_str(json).unwrap();
        assert!(structure.validate_ca_hierarchy().is_ok());
    }
}
