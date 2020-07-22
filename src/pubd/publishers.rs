use rpki::uri;

use crate::commons::api::rrdp::{CurrentObjects, DeltaElements};
use crate::commons::api::{ListReply, PublisherDetails, PublisherHandle};
use crate::commons::error::Error;
use crate::commons::remote::crypto::IdCert;
use crate::commons::KrillResult;

//------------ Publisher -----------------------------------------------------

/// This type defines Publisher CAs that are allowed to publish.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Publisher {
    /// Used by remote RFC8181 publishers
    id_cert: IdCert,

    /// Publication jail for this publisher
    base_uri: uri::Rsync,

    /// All objects currently published by this publisher, by hash
    current_objects: CurrentObjects,
}

/// # Accessors
impl Publisher {
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
    pub fn base_uri(&self) -> &uri::Rsync {
        &self.base_uri
    }
    pub fn current_objects(&self) -> &CurrentObjects {
        &self.current_objects
    }

    pub fn as_api_details(&self, handle: &PublisherHandle) -> PublisherDetails {
        let objects = self
            .current_objects
            .elements()
            .into_iter()
            .cloned()
            .collect();

        PublisherDetails::new(handle, self.id_cert.clone(), &self.base_uri(), objects)
    }
}

/// # Life cycle
///
impl Publisher {
    pub fn new(id_cert: IdCert, base_uri: uri::Rsync, current_objects: CurrentObjects) -> Self {
        Publisher {
            id_cert,
            base_uri,
            current_objects,
        }
    }
}

/// # Publication protocol
///
impl Publisher {
    /// Gets an owned list reply containing all objects for this publisher.
    /// Note that cloning the uris and hashes is relatively cheap because of
    /// the use of Bytes as the underlying structure. Still, it may be good
    /// to change this implementation in future to return a structure that
    /// takes references, and only lives long enough to compose a response.
    pub fn list_current(&self) -> ListReply {
        self.current_objects.to_list_reply()
    }

    /// Verifies a delta command and returns an event containing the delta,
    /// provided that it's legitimate.
    pub fn verify_delta(&self, delta_elements: &DeltaElements) -> KrillResult<()> {
        self.current_objects
            .verify_delta(delta_elements, &self.base_uri)
            .map_err(Error::Rfc8181Delta)
    }

    pub fn apply_delta(&mut self, delta: DeltaElements) {
        self.current_objects.apply_delta(delta);
    }
}
