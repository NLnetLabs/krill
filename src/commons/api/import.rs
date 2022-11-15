//! Data types used to support importing a CA structure for testing or automated set ups.

use rpki::{ca::idexchange::CaHandle, repository::resources::ResourceSet};

/// This type contains the full structure of CAs and signed objects etc that is
/// set up when the import API is used.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Structure {
    online_ta_children: Vec<CaStructure>,
}

/// This type describes a CaStructure that needs to be imported. I.e. it describes
/// a CA at the top of a branch and recursively includes 0 or more children of this
/// same type.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaStructure {
    handle: CaHandle,
    resources: ResourceSet,
    children: Vec<CaStructure>,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse_cas_only() {
        let json = include_str!("../../../test-resources/bulk-ca-import/cas-only.json");

        let _ca: Structure = serde_json::from_str(json).unwrap();
    }
}
