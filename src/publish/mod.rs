//! Support CAs publishing at a local, or remote, repository
use std::collections::HashMap;
use std::sync::Arc;

use crate::commons::api::Handle;
use crate::commons::api::{Publish, PublishDelta, RepositoryContact, Update, Withdraw};
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

        // Since this is called by the schedular, this should act as a no-op for
        // new CAs which do not yet have any repository configured.
        let repo_contact = match ca.repository_contact() {
            Some(repo) => repo,
            None => return Ok(()),
        };

        let list_reply = match &repo_contact {
            RepositoryContact::Embedded(_) => self.pubserver.list(ca_handle)?,
            RepositoryContact::Rfc8181(repo) => self.caserver.send_rfc8181_list(ca_handle, repo)?,
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

        match &repo_contact {
            RepositoryContact::Embedded(_) => self.pubserver.publish(ca_handle.clone(), delta)?,
            RepositoryContact::Rfc8181(repo) => {
                self.caserver.send_rfc8181_delta(ca_handle, repo, delta)?
            }
        };

        Ok(())
    }

    pub fn clean_up(&self, ca_handle: &Handle) -> Result<(), Error> {
        let ca = self.caserver.get_ca(ca_handle)?;

        let repo = match ca.old_repository_contact() {
            None => return Ok(()),
            Some(contact) => contact,
        };

        info!(
            "Will perform best effort clean up of old repository: {}",
            repo
        );

        let list_reply = match repo {
            RepositoryContact::Embedded(_) => self.pubserver.list(ca_handle)?,
            RepositoryContact::Rfc8181(repo) => self.caserver.send_rfc8181_list(ca_handle, repo)?,
        };

        let delta = list_reply.into_withdraw_delta();

        match repo {
            RepositoryContact::Embedded(_) => self.pubserver.publish(ca_handle.clone(), delta)?,
            RepositoryContact::Rfc8181(res) => {
                self.caserver.send_rfc8181_delta(ca_handle, res, delta)?
            }
        }

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
