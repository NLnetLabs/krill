//! Data types used to support importing a CA structure for testing or automated set ups.

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Deserializer};

use rpki::{
    ca::{
        idcert::IdCert,
        idexchange::{CaHandle, ChildHandle, ParentHandle},
        provisioning::ResourceClassName,
    },
    repository::resources::ResourceSet,
    uri,
};

use crate::{
    commons::{api::PublicationServerUris, crypto::CsrInfo, error::Error, KrillResult},
    daemon::config,
    ta::ta_handle,
};

use super::RoaConfiguration;

//------------ Structure -----------------------------------------------------

/// This type contains the full structure of CAs and signed objects etc that is
/// set up when the import API is used.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Structure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ta: Option<ImportTa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publication_server: Option<PublicationServerUris>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub cas: Vec<ImportCa>,
}

impl Structure {
    pub fn new(
        ta_aia: uri::Rsync,
        ta_uri: uri::Https,
        ta_key_pem: Option<String>,
        publication_server_uris: PublicationServerUris,
        cas: Vec<ImportCa>,
    ) -> Self {
        Structure {
            ta: Some(ImportTa {
                ta_aia,
                ta_uri,
                ta_key_pem,
            }),
            publication_server: Some(publication_server_uris),
            cas,
        }
    }

    /// Check that all parents are valid for the CAs in this structure
    /// in the order in which they appear, and that the parent CAs have
    /// the resources for each child CA.
    pub fn validate_ca_hierarchy(&self, mut existing_cas: HashMap<ParentHandle, ResourceSet>) -> KrillResult<()> {
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
        let ta_handle = ta_handle();
        existing_cas.insert(ta_handle.convert(), ResourceSet::all());

        for ca in &self.cas {
            if ca.handle == ta_handle {
                return Err(Error::Custom(format!("CA name {} is reserved.", ta_handle)));
            }

            if existing_cas.contains_key(&ca.handle.convert()) {
                return Err(Error::Custom(format!(
                    "CA with name {} already exists. Check import and server state!",
                    ca.handle
                )));
            }

            let mut ca_resources = ResourceSet::empty();
            for ca_parent in &ca.parents {
                if let Some(seen_parent_resources) = existing_cas.get(ca_parent.handle()) {
                    if seen_parent_resources.contains(&ca_parent.resources) {
                        ca_resources = ca_resources.union(&ca_parent.resources);
                    } else {
                        return Err(Error::Custom(format!(
                            "CA '{}' under parent '{}' claims resources not held by parent.",
                            ca.handle,
                            ca_parent.handle()
                        )));
                    }
                } else {
                    return Err(Error::Custom(format!(
                        "CA '{}' wants parent '{}', but this parent CA does not appear before this CA.",
                        ca.handle,
                        ca_parent.handle()
                    )));
                }
            }
            existing_cas.insert(ca.handle.convert(), ca_resources);
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

//------------ ImportTa ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportTa {
    pub ta_aia: uri::Rsync,
    pub ta_uri: uri::Https,
    pub ta_key_pem: Option<String>,
}

impl ImportTa {
    pub fn unpack(self) -> (uri::Rsync, Vec<uri::Https>, Option<String>) {
        (self.ta_aia, vec![self.ta_uri], self.ta_key_pem)
    }
}

//------------ ImportCa ------------------------------------------------------

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

//------------ ImportParent --------------------------------------------------

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

//------------ ImportChild ---------------------------------------------------

pub type ExportChild = ImportChild;

/// Describes a child CA that can be imported from, or exported to,
/// another parent CA instance.
///
/// Only supports the simplest scenario where the child has only
/// one certificate, in only one resource class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportChild {
    pub name: ChildHandle,
    pub id_cert: IdCert,
    pub resources: ResourceSet,
    pub issued_cert: ImportChildCertificate,
}

pub type ChildResourceClassName = ResourceClassName;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportChildCertificate {
    #[serde(flatten)]
    pub csr: CsrInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<ChildResourceClassName>,
}

impl fmt::Display for ImportChild {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Name:         {}", self.name)?;
        writeln!(
            f,
            "Id Key:       {}",
            self.id_cert.public_key().key_identifier().to_string()
        )?;
        writeln!(f, "Resources:    {}", self.resources)?;
        if let Some(class_name) = &self.issued_cert.class_name {
            writeln!(f, "Classname:    {}", class_name)?;
        }
        let (ca_repository, rpki_manifest, rpki_notify, key) = self.issued_cert.csr.clone().unpack();

        writeln!(f, "Issued Certificate:")?;
        writeln!(f, "  Key Id:       {}", key.key_identifier())?;
        writeln!(f, "  CA repo:      {}", ca_repository)?;
        writeln!(f, "  CA mft:       {}", rpki_manifest)?;
        if let Some(rrdp) = rpki_notify {
            writeln!(f, "  RRDP:         {}", rrdp)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_cas_only() {
        let json = include_str!("../../../test-resources/bulk-ca-import/structure.json");

        let structure: Structure = serde_json::from_str(json).unwrap();
        assert!(structure.validate_ca_hierarchy(HashMap::new()).is_ok());
    }

    #[test]
    fn parse_import_delegated_child() {
        let json = include_str!("../../../test-resources/bulk-ca-import/import-nicbr.json");

        let _child: ImportChild = serde_json::from_str(json).unwrap();
    }
}
