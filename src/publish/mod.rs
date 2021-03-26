//! Support CAs publishing at a local, or remote, repository
use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    commons::{
        api::rrdp::PublishElement,
        api::{Handle, Publish, PublishDelta, RepositoryContact, Update, Withdraw},
        error::Error,
    },
    daemon::ca::CaManager,
    pubd::RepositoryManager,
};

//------------ CaPublisher ---------------------------------------------------

/// A helper which orchestrates publishing by CAs at either local, or
/// remote, repositories.
pub struct CaPublisher {
    ca_manager: Arc<CaManager>,
    repo_manager_opt: Option<Arc<RepositoryManager>>,
}

/// # Construct
///
impl CaPublisher {
    pub fn new(ca_manager: Arc<CaManager>, repo_manager_opt: Option<Arc<RepositoryManager>>) -> Self {
        CaPublisher {
            ca_manager,
            repo_manager_opt,
        }
    }
}

impl CaPublisher {
    fn get_embedded(&self) -> Result<&Arc<RepositoryManager>, Error> {
        self.repo_manager_opt.as_ref().ok_or(Error::RepositoryServerNotEnabled)
    }

    pub async fn publish(&self, ca_handle: &Handle) -> Result<(), Error> {
        // Since this is called by the scheduler, this acts as a no-op for new CAs which do not yet have any repository configured.
        for (contact, elements) in self.ca_manager.ca_repo_elements(ca_handle).await? {
            self.sync_repo(ca_handle, &contact, elements).await?;
        }

        // Best effort clean-up of old repos
        for deprecated in self.ca_manager.ca_deprecated_repos(ca_handle)? {
            info!(
                "Will try to clean up deprecated repository '{}' for CA '{}'",
                deprecated.contact(),
                ca_handle
            );

            if let Err(e) = self.sync_repo(ca_handle, &deprecated.contact(), vec![]).await {
                warn!("Could not clean up deprecated repository: {}", e);

                if deprecated.clean_attempts() < 5 {
                    self.ca_manager
                        .ca_deprecated_repo_inc_clean_attempts(ca_handle, deprecated.contact())?;
                    return Err(e);
                }
            }

            self.ca_manager
                .ca_deprecated_repo_remove(ca_handle, deprecated.contact())?;
        }

        Ok(())
    }

    async fn sync_repo(
        &self,
        ca_handle: &Handle,
        repo_contact: &RepositoryContact,
        ca_elements: Vec<PublishElement>,
    ) -> Result<(), Error> {
        let list_reply = match repo_contact {
            RepositoryContact::Embedded { .. } => self.get_embedded()?.list(ca_handle)?,
            RepositoryContact::Rfc8181 { server_response } => {
                self.ca_manager
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

        match repo_contact {
            RepositoryContact::Embedded { .. } => {
                self.get_embedded()?.publish(ca_handle.clone(), delta)?;
                self.ca_manager.ca_repo_status_set_elements(ca_handle).await?;
            }
            RepositoryContact::Rfc8181 { server_response } => {
                self.ca_manager
                    .send_rfc8181_delta(ca_handle, server_response, delta)
                    .await?
            }
        };

        Ok(())
    }

    pub async fn clean_all_repos(&self, ca_handle: &Handle) -> Result<(), Error> {
        let repos: Vec<RepositoryContact> = self
            .ca_manager
            .ca_repo_elements(ca_handle)
            .await?
            .into_iter()
            .map(|(contact, _)| contact)
            .collect();

        info!(
            "Will try to clean up all repositories for CA '{}' before removing it.",
            ca_handle
        );
        for repo in repos {
            if let Err(e) = self.sync_repo(ca_handle, &repo, vec![]).await {
                warn!(
                    "Could not remove objects for CA '{}' at repository {}. Error was: {}",
                    ca_handle, repo, e
                );
            }
        }

        Ok(())
    }
}
