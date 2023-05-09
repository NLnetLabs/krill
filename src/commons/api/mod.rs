//! Data structures for the API, shared between client and server.

mod admin;
pub use self::admin::*;

mod aspa;
pub use self::aspa::*;

mod bgpsec;
pub use self::bgpsec::*;

mod ca;
pub use self::ca::*;

mod history;
pub use self::history::*;

pub mod import;

mod roas;
pub use self::roas::*;

pub mod rrdp;

use std::{collections::HashMap, fmt};

use rpki::ca::csr::BgpsecCsr;
use rpki::ca::provisioning::ResourceClassName;
use rpki::ca::publication::Base64;
use serde::{Deserialize, Serialize};

use rpki::{
    ca::idexchange::{CaHandle, ChildHandle, ParentHandle, PublisherHandle},
    crypto::KeyIdentifier,
    repository::resources::Asn,
};

use crate::{commons::error::RoaDeltaError, daemon::ca::RoaPayloadJsonMapKey};

// Some syntactic sugar to help this old coder's brain deal with the mess of Strings
pub type Message = String;
pub type Label = String;
pub type ArgKey = String;
pub type ArgVal = String;

//------------ ErrorResponse --------------------------------------------------

/// Defines an error response. Codes are unique and documented here:
/// https://rpki.readthedocs.io/en/latest/krill/pub/api.html#error-responses
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorResponse {
    label: String,
    msg: String,
    args: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delta_error: Option<RoaDeltaError>,
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

    pub fn delta_error(&self) -> Option<&RoaDeltaError> {
        self.delta_error.as_ref()
    }

    fn with_arg(mut self, key: &str, value: impl fmt::Display) -> Self {
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

    pub fn with_auth(self, auth: &RoaPayloadJsonMapKey) -> Self {
        let mut res = self.with_arg("prefix", auth.prefix()).with_arg("asn", auth.asn());

        if let Some(max) = auth.max_length() {
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

    pub fn with_roa_delta_error(mut self, roa_delta_error: &RoaDeltaError) -> Self {
        self.delta_error = Some(roa_delta_error.clone());
        self
    }

    pub fn with_key_identifier(self, ki: &KeyIdentifier) -> Self {
        self.with_arg("key_id", ki)
    }

    pub fn with_resource_class(self, class_name: &ResourceClassName) -> Self {
        self.with_arg("class_name", class_name)
    }

    pub fn label(&self) -> &str {
        &self.label
    }
    pub fn msg(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &serde_json::to_string(&self).unwrap())
    }
}
