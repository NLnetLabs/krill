//! Provides wrappers for RPKI Objects (Certififcates, MFTs, CRLs, ROAs,..?) for CAs

use bytes::Bytes;
use krill_commons::util::ext_serde;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Cert {
    #[serde(
        deserialize_with = "ext_serde::de_bytes",
        serialize_with = "ext_serde::ser_bytes")]
    content: Bytes
}