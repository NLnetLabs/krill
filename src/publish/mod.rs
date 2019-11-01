//! Support CAs publishing at a local, or remote, repository

use std::collections::HashMap;
use std::sync::Arc;

use crate::commons::api::Handle;
use crate::commons::api::{PubServerContact, Publish, PublishDelta, Update, Withdraw};
use crate::commons::util::softsigner::OpenSslSigner;
use crate::daemon::ca;
use crate::daemon::ca::CaServer;
use crate::pubd;
use crate::pubd::PubServer;

//------------ CaPublisher ---------------------------------------------------

/// A helper which orchestrates publishing by CAs at either local, or
/// remote, repositories.
pub struct CaPublisher {
    caserver: Arc<CaServer<OpenSslSigner>>,
    pubserver: Arc<PubServer>,
}

/// # Construct
///
impl CaPublisher {
    pub fn new(caserver: Arc<CaServer<OpenSslSigner>>, pubserver: Arc<PubServer>) -> Self {
        CaPublisher {
            caserver,
            pubserver,
        }
    }
}

impl CaPublisher {
    pub fn publish(&self, ca_handle: &Handle) -> Result<(), Error> {
        let ca = self.caserver.get_ca(ca_handle)?;

        let list_reply = match ca.pub_server_contact() {
            PubServerContact::Embedded(_) => self.pubserver.list(ca_handle)?,
            PubServerContact::Rfc8181(_) => self.caserver.send_rfc8181_list(ca_handle)?,
        };

        let delta = {
            let elements: HashMap<_, _> = list_reply
                .into_elements()
                .into_iter()
                .map(|el| el.unpack())
                .collect();

            let mut all_objects: HashMap<_, _> =
                ca.all_objects().into_iter().map(|el| el.unpack()).collect();

            let mut withdraws = vec![];
            let mut updates = vec![];
            for (uri, hash) in elements.into_iter() {
                match all_objects.remove(&uri) {
                    Some(base64) => {
                        if base64.to_encoded_hash() != hash {
                            updates.push(Update::new(None, uri, base64, hash))
                        }
                    }
                    None => withdraws.push(Withdraw::new(None, uri, hash)),
                }
            }
            let publishes = all_objects
                .into_iter()
                .map(|(uri, base64)| Publish::new(None, uri, base64))
                .collect();

            PublishDelta::new(publishes, updates, withdraws)
        };

        match ca.pub_server_contact() {
            PubServerContact::Embedded(_) => self.pubserver.publish(ca_handle.clone(), delta)?,
            PubServerContact::Rfc8181(_) => self.caserver.send_rfc8181_delta(ca_handle, delta)?,
        };

        Ok(())
    }
}

//------------ Error ---------------------------------------------------------

#[derive(Debug, Display)]
pub enum Error {
    #[display(fmt = "{}", _0)]
    CaServer(ca::ServerError),

    #[display(fmt = "{}", _0)]
    PubServer(pubd::Error),
}

impl From<ca::ServerError> for Error {
    fn from(e: ca::ServerError) -> Self {
        Error::CaServer(e)
    }
}

impl From<pubd::Error> for Error {
    fn from(e: pubd::Error) -> Self {
        Error::PubServer(e)
    }
}
