//! Support CAs publishing at a local, or remote, repository
use std::collections::HashMap;
use std::sync::Arc;

use crate::commons::api::{Publish, PublishDelta, RepositoryContact, Update, Withdraw};
use crate::commons::error::Error;
use crate::commons::{actor::Actor, api::Handle};
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
        self.pubserver.as_ref().ok_or(Error::RepositoryServerNotEnabled)
    }

    pub async fn publish(&self, ca_handle: &Handle, actor: &Actor) -> Result<(), Error> {
        // Since this is called by the scheduler, this acts as a no-op for new CAs which do not yet have any repository configured.
        for (repo_contact, ca_elements) in self.caserver.ca_repo_elements(ca_handle).await? {
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
                RepositoryContact::Embedded { .. } => self.get_embedded()?.publish(ca_handle.clone(), delta, actor)?,
                RepositoryContact::Rfc8181 { server_response } => {
                    self.caserver
                        .send_rfc8181_delta(ca_handle, server_response, delta, false)
                        .await?
                }
            };
        }

        Ok(())
    }

    pub async fn clean_old_repo(&self, ca_handle: &Handle, actor: &Actor) -> Result<(), Error> {
        let ca = self.caserver.get_ca(ca_handle).await?;

        let repo = match ca.old_repository_contact() {
            None => return Ok(()),
            Some(contact) => contact,
        };

        self.clean_repo(ca_handle, repo, actor).await
    }

    pub async fn clean_current_repo(&self, ca_handle: &Handle, actor: &Actor) -> Result<(), Error> {
        let ca = self.caserver.get_ca(ca_handle).await?;

        let repo = match ca.repository_contact() {
            Ok(contact) => contact,
            Err(_) => return Ok(()),
        };

        self.clean_repo(ca_handle, repo, actor).await
    }

    async fn clean_repo(&self, ca_handle: &Handle, repo: &RepositoryContact, actor: &Actor) -> Result<(), Error> {
        info!("Will perform best effort clean up of repository: {}", repo);

        let list_reply = match repo {
            RepositoryContact::Embedded { info } => self.get_embedded()?.list(ca_handle)?,
            RepositoryContact::Rfc8181 { server_response } => {
                self.caserver
                    .send_rfc8181_list(ca_handle, server_response, true)
                    .await?
            }
        };

        let delta = list_reply.into_withdraw_delta();

        match repo {
            RepositoryContact::Embedded { info } => self.get_embedded()?.publish(ca_handle.clone(), delta, actor)?,
            RepositoryContact::Rfc8181 { server_response } => {
                self.caserver
                    .send_rfc8181_delta(ca_handle, server_response, delta, true)
                    .await?
            }
        }

        Ok(())
    }
}
