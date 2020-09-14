//! Support CAs publishing at a local, or remote, repository
use std::collections::HashMap;
use std::sync::Arc;

use crate::commons::api::Handle;
use crate::commons::api::{Publish, PublishDelta, RepositoryContact, Update, Withdraw};
use crate::commons::error::Error;
use crate::daemon::ca::CaServer;
use crate::pubd::PubServer;

//------------ CaPublisher ---------------------------------------------------

/// A helper which orchestrates publishing by CAs at either local, or
/// remote, repositories.
pub struct CaPublisher {
    caserver: Arc<CaServer>,
    pubserver: Option<Arc<PubServer>>,
}

/// # Construct
///
impl CaPublisher {
    pub fn new(caserver: Arc<CaServer>, pubserver: Option<Arc<PubServer>>) -> Self {
        CaPublisher { caserver, pubserver }
    }
}

impl CaPublisher {
    fn get_embedded(&self) -> Result<&Arc<PubServer>, Error> {
        self.pubserver.as_ref().ok_or_else(|| Error::PublisherNoEmbeddedRepo)
    }

    pub async fn publish(&self, ca_handle: &Handle) -> Result<(), Error> {
        let ca = self.caserver.get_ca(ca_handle).await?;

        // Since this is called by the scheduler, this should act as a no-op for
        // new CAs which do not yet have any repository configured.
        let repo_contact = match ca.get_repository_contact() {
            Ok(repo) => repo,
            Err(_) => return Ok(()),
        };

        let list_reply = match &repo_contact {
            RepositoryContact::Embedded(_) => self.get_embedded()?.list(ca_handle).await?,
            RepositoryContact::Rfc8181(repo) => self.caserver.send_rfc8181_list(ca_handle, repo, false).await?,
        };

        #[allow(clippy::mutable_key_type)]
        let delta = {
            let elements: HashMap<_, _> = list_reply.into_elements().into_iter().map(|el| el.unpack()).collect();

            let mut all_objects: HashMap<_, _> = ca.all_objects().into_iter().map(|el| el.unpack()).collect();

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
            RepositoryContact::Embedded(_) => self.get_embedded()?.publish(ca_handle.clone(), delta).await?,
            RepositoryContact::Rfc8181(repo) => self.caserver.send_rfc8181_delta(ca_handle, repo, delta, false).await?,
        };

        Ok(())
    }

    pub async fn clean_up(&self, ca_handle: &Handle) -> Result<(), Error> {
        let ca = self.caserver.get_ca(ca_handle).await?;

        let repo = match ca.old_repository_contact() {
            None => return Ok(()),
            Some(contact) => contact,
        };

        info!("Will perform best effort clean up of old repository: {}", repo);

        let list_reply = match repo {
            RepositoryContact::Embedded(_) => self.get_embedded()?.list(ca_handle).await?,
            RepositoryContact::Rfc8181(repo) => self.caserver.send_rfc8181_list(ca_handle, repo, true).await?,
        };

        let delta = list_reply.into_withdraw_delta();

        match repo {
            RepositoryContact::Embedded(_) => self.get_embedded()?.publish(ca_handle.clone(), delta).await?,
            RepositoryContact::Rfc8181(res) => self.caserver.send_rfc8181_delta(ca_handle, res, delta, true).await?,
        }

        Ok(())
    }
}
