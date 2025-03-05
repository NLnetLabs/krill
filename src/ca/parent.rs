use serde::{Deserialize, Serialize};
use crate::commons::api::ca::IdCertInfo;
use crate::commons::crypto::KrillSigner;
use crate::commons::error::KrillError;


//------------ Rfc8183Id ---------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rfc8183Id {
    cert: IdCertInfo,
}

impl Rfc8183Id {
    pub fn new(cert: IdCertInfo) -> Self {
        Rfc8183Id { cert }
    }

    pub fn generate(signer: &KrillSigner) -> Result<Self, KrillError> {
        let cert = signer.create_self_signed_id_cert()?;
        let cert = IdCertInfo::from(&cert);
        Ok(Rfc8183Id { cert })
    }

    pub fn cert(&self) -> &IdCertInfo {
        &self.cert
    }
}

impl From<Rfc8183Id> for IdCertInfo {
    fn from(id: Rfc8183Id) -> Self {
        id.cert
    }
}

