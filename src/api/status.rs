//! Error reporting.

use std::fmt;
use std::collections::HashMap;
use rpki::ca::csr::BgpsecCsr;
use rpki::ca::idexchange::{
    CaHandle, ChildHandle, ParentHandle, PublisherHandle
};
use rpki::ca::provisioning::ResourceClassName;
use rpki::ca::publication::Base64;
use rpki::crypto::KeyIdentifier;
use rpki::repository::resources::Asn;
use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeStruct;
use crate::commons::error::RoaDeltaError;
use super::roa::RoaPayload;


//------------ Success -------------------------------------------------------

/// An empty, successful API response.
///
/// This type needs to be used instead of `()` to make conversion into
/// [`Report`][crate::cli::report::Report] work.
#[derive(Clone, Copy, Debug)]
pub struct Success;

impl fmt::Display for Success {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Ok")
    }
}

impl Serialize for Success {
    fn serialize<S: Serializer>(
        &self, serializer: S
    ) -> Result<S::Ok, S::Error> {
        let mut serializer = serializer.serialize_struct("Success", 1)?;
        serializer.serialize_field("status", "Ok")?;
        serializer.end()
    }
}


//------------ ErrorResponse -------------------------------------------------

/// An API error response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorResponse {
    /// The error label.
    pub label: String,

    /// The error message.
    pub msg: String,

    /// Arguments with details about the error.
    pub args: HashMap<String, String>,

    /// Optional ROA delta error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_error: Option<RoaDeltaError>,
}

impl ErrorResponse {
    pub fn new(label: &str, msg: impl fmt::Display) -> Self {
        ErrorResponse {
            label: label.to_string(),
            msg: msg.to_string(),
            args: HashMap::new(),
            delta_error: None,
        }
    }

    pub fn with_arg(mut self, key: &str, value: impl fmt::Display) -> Self {
        self.args.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_cause(self, cause: impl fmt::Display) -> Self {
        self.with_arg("cause", cause)
    }

    pub fn with_publisher(self, publisher: &PublisherHandle) -> Self {
        self.with_arg("publisher", publisher)
    }

    pub fn with_uri(self, uri: impl fmt::Display) -> Self {
        self.with_arg("uri", uri)
    }

    pub fn with_base_uri(self, base_uri: impl fmt::Display) -> Self {
        self.with_arg("base_uri", base_uri)
    }

    pub fn with_ca(self, ca: &CaHandle) -> Self {
        self.with_arg("ca", ca)
    }

    pub fn with_parent(self, parent: &ParentHandle) -> Self {
        self.with_arg("parent", parent)
    }

    pub fn with_child(self, child: &ChildHandle) -> Self {
        self.with_arg("child", child)
    }

    pub fn with_auth(self, auth: impl Into<RoaPayload>) -> Self {
        let auth = auth.into();
        let mut res = self
            .with_arg("prefix", auth.prefix)
            .with_arg("asn", auth.asn);

        if let Some(max) = auth.max_length {
            res = res.with_arg("max_length", max)
        }

        res
    }

    pub fn with_asn(self, asn: Asn) -> Self {
        self.with_arg("asn", asn)
    }

    pub fn with_bgpsec_csr(self, csr: &BgpsecCsr) -> Self {
        let base64 = Base64::from_content(csr.to_captured().as_slice());
        self.with_arg("bgpsec_csr", base64)
    }

    pub fn with_roa_delta_error(
        mut self,
        roa_delta_error: &RoaDeltaError,
    ) -> Self {
        self.delta_error = Some(roa_delta_error.clone());
        self
    }

    pub fn with_key_identifier(self, ki: &KeyIdentifier) -> Self {
        self.with_arg("key_id", ki)
    }

    pub fn with_resource_class(self, class_name: &ResourceClassName) -> Self {
        self.with_arg("class_name", class_name)
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &serde_json::to_string(&self).unwrap())
    }
}

