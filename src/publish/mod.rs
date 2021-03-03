//! Support CAs publishing at a local, or remote, repository
use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    commons::{
        api::rrdp::PublishElement,
        api::{Handle, Publish, PublishDelta, RepositoryContact, Update, Withdraw},
        error::Error,
    },
    daemon::ca::CaServer,
    pubd::RepositoryManager,
};

//------------ CaPublisher ---------------------------------------------------

/// A helper which orchestrates publishing by CAs at either local, or
/// remote, repositories.
pub struct CaPublisher {
    caserver: Arc<CaServer>,
    pubserver: Option<Arc<RepositoryManager>>,
}

/// # Construct
///
impl CaPublisher {
    pub fn new(caserver: Arc<CaServer>, pubserver: Option<Arc<RepositoryManager>>) -> Self {
        CaPublisher { caserver, pubserver }
    }
}

impl CaPublisher {
    fn get_embedded(&self) -> Result<&Arc<RepositoryManager>, Error> {
        self.pubserver.as_ref().ok_or(Error::RepositoryServerNotEnabled)
    }

    pub async fn publish(&self, ca_handle: &Handle) -> Result<(), Error> {
        // Since this is called by the scheduler, this acts as a no-op for new CAs which do not yet have any repository configured.
        for (contact, elements) in self.caserver.ca_repo_elements(ca_handle).await? {
            self.sync_repo(ca_handle, contact, elements).await?;
        }

        // Best effort clean-up of old repos
        for deprecated in self.caserver.ca_take_deprecated_repos(ca_handle)? {
            info!(
                "Will try to clean up deprecated repository '{}' for CA '{}'",
                deprecated, ca_handle
            );
            if self.sync_repo(ca_handle, deprecated, vec![]).await.is_err() {
                info!(
                    "Could not clean up deprecated repository. This is fine - objects there are no longer referenced."
                );
            }
        }

        Ok(())
    }

    async fn sync_repo(
        &self,
        ca_handle: &Handle,
        repo_contact: RepositoryContact,
        ca_elements: Vec<PublishElement>,
    ) -> Result<(), Error> {
        let list_reply = match &repo_contact {
            RepositoryContact::Embedded { .. } => self.get_embedded()?.list(ca_handle)?,
            RepositoryContact::Rfc8181 { server_response } => {
                self.caserver
                    .send_rfc8181_list(ca_handle, server_response, false)
                    .await?
            }
        };

        #[allow(clippy::mutable_key_type)]
        let delta = {
            let elements: HashMap<_, _> = list_reply.into_elements().into_iter().map(|el| el.unpack()).collect();

            let mut all_objects: HashMap<_, _> = ca_elements.into_iter().map(|el| el.unpack()).collect();

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
            RepositoryContact::Embedded { .. } => self.get_embedded()?.publish(ca_handle.clone(), delta)?,
            RepositoryContact::Rfc8181 { server_response } => {
                self.caserver
                    .send_rfc8181_delta(ca_handle, server_response, delta, false)
                    .await?
            }
        };

        Ok(())
    }

    pub async fn clean_all_repos(&self, ca_handle: &Handle) -> Result<(), Error> {
        let mut repos: Vec<RepositoryContact> = self
            .caserver
            .ca_repo_elements(ca_handle)
            .await?
            .into_iter()
            .map(|(contact, _)| contact)
            .collect();
        repos.append(&mut self.caserver.ca_take_deprecated_repos(ca_handle)?);

        info!(
            "Will try to clean up all repositories for CA '{}' before removing it.",
            ca_handle
        );
        for repo in repos {
            if self.sync_repo(ca_handle, repo, vec![]).await.is_err() {
                info!(
                    "Could not clean up deprecated repository. This is fine - objects there are no longer referenced."
                );
            }
        }

        Ok(())
    }
}
