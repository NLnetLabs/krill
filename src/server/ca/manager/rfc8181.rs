//! Publication protocol exchanges.

use std::collections::HashMap;
use log::{debug, error};
use rpki::ca::publication;
use rpki::ca::idexchange::CaHandle;
use rpki::ca::publication::{
    ListReply, Publish, PublishDelta, Update, Withdraw
};
use rpki::crypto::KeyIdentifier;
use crate::api::admin::{
    PublicationServerInfo, PublishedFile, RepositoryContact
};
use crate::api::ca::IdCertInfo;
use crate::commons::KrillResult;
use crate::commons::cmslogger::CmsLogger;
use crate::commons::error::Error;
use crate::server::pubd::RepositoryManager;
use super::CaManager;


//------------ super::CaManager ----------------------------------------------

impl CaManager {
    /// Synchronizes with the repository.
    pub fn ca_repo_sync(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        id_cert: &IdCertInfo,
        repo_contact: &RepositoryContact,
        publish_elements: Vec<PublishedFile>,
    ) -> KrillResult<()> {
        debug!("CA '{ca_handle}' sends list query to repo");
        let list_reply = self.send_rfc8181_list(
            repo_manager,
            ca_handle,
            id_cert,
            &repo_contact.server_info,
        )?;

        // XXX Do we really need hash maps here? In particular, this will
        //     quietly overwrite double URLs which we should probably catch?
        let elements: HashMap<_, _> = list_reply
            .into_elements()
            .into_iter()
            .map(|el| el.unpack())
            .collect();

        let mut all_objects: HashMap<_, _> =
            publish_elements.into_iter()
                .map(|el| (el.uri, el.base64)).collect();

        let mut delta = PublishDelta::empty();

        for (uri, hash) in elements {
            match all_objects.remove(&uri) {
                Some(base64) => {
                    if base64.to_hash() != hash {
                        delta.add_update(Update::new(None, uri, base64, hash))
                    }
                }
                None => delta.add_withdraw(Withdraw::new(None, uri, hash)),
            }
        }

        for (uri, base64) in all_objects {
            delta.add_publish(Publish::new(None, uri, base64));
        }

        if !delta.is_empty() {
            debug!("CA '{ca_handle}' sends delta");
            self.send_rfc8181_delta(
                repo_manager,
                ca_handle,
                id_cert,
                &repo_contact.server_info,
                delta,
            )?;
            debug!("CA '{ca_handle}' sent delta");
        }
        else {
            debug!("CA '{ca_handle}' has nothing to publish");
        }

        Ok(())
    }

    /// Sends a publication protocol list request and returns the reply.
    pub fn send_rfc8181_list(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        id_cert: &IdCertInfo,
        server_info: &PublicationServerInfo,
    ) -> KrillResult<ListReply> {
        let signing_key = id_cert.public_key.key_identifier();

        let message = publication::Message::list_query();

        let reply = self.send_rfc8181_and_validate_response(
            repo_manager,
            message,
            server_info,
            &ca_handle,
            signing_key,
        );

        let reply = match reply {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &e,
                )?;
                return Err(e);
            }
        };

        match reply {
            publication::Reply::List(list_reply) => {
                self.status_store.set_status_repo_success(
                    ca_handle, server_info.service_uri.clone()
                )?;
                Ok(list_reply)
            }
            publication::Reply::Success => {
                let err = Error::custom(
                    "Got success reply to list query?!"
                );
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
            publication::Reply::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {e}"));
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
        }
    }

    /// Sends a publication protocol delta request.
    fn send_rfc8181_delta(
        &self,
        repo_manager: &RepositoryManager,
        ca_handle: &CaHandle,
        id_cert: &IdCertInfo,
        server_info: &PublicationServerInfo,
        delta: PublishDelta,
    ) -> KrillResult<()> {
        let signing_key = id_cert.public_key.key_identifier();

        let message = publication::Message::delta(delta.clone());

        let reply = self.send_rfc8181_and_validate_response(
            repo_manager,
            message,
            server_info,
            ca_handle,
            signing_key,
        );

        let reply = match reply {
            Ok(reply) => reply,
            Err(e) => {
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &e,
                )?;
                return Err(e);
            }
        };

        match reply {
            publication::Reply::Success => {
                self.status_store.set_status_repo_published(
                    ca_handle,
                    server_info.service_uri.clone(),
                    delta,
                )?;
                Ok(())
            }
            publication::Reply::ErrorReply(e) => {
                let err = Error::Custom(format!("Got error reply: {e}"));
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
            publication::Reply::List(_) => {
                let err = Error::custom("Got list reply to delta query?!");
                self.status_store.set_status_repo_failure(
                    ca_handle,
                    server_info.service_uri.clone(),
                    &err,
                )?;
                Err(err)
            }
        }
    }

    fn send_rfc8181_and_validate_response(
        &self,
        repo_manager: &RepositoryManager,
        message: publication::Message,
        server_info: &PublicationServerInfo,
        ca_handle: &CaHandle,
        signing_key: KeyIdentifier,
    ) -> KrillResult<publication::Reply> {
        if server_info.service_uri.as_str().starts_with(
            self.config.service_uri().as_str()
        ) {
            // this maps back to *this* Krill instance
            let query = message.as_query()?;
            let publisher_handle = ca_handle.convert();
            let response = repo_manager.rfc8181_message(
                &publisher_handle, query
            )?;
            response.as_reply().map_err(Error::Rfc8181)
        }
        else {
            // Set up a logger for CMS exchanges.
            let cms_logger = CmsLogger::for_rfc8181_sent(
                self.config.rfc8181_log_dir.as_ref(),
                ca_handle,
            );

            let cms = match self.signer.create_rfc8181_cms(
                message, &signing_key
            ) {
                Ok(cms) => cms.to_bytes(),
                Err(err) => {
                    return Err(err.into())
                }
            };

            let ca_handle = ca_handle.clone();
            let (res, cms_logger) = self.post_protocol_cms_binary(
                cms,
                &server_info.service_uri,
                publication::CONTENT_TYPE,
                cms_logger
            ).block().map_err(|_| Error::custom("publication post failed"))?;

            match publication::PublicationCms::decode(
                &res?
            ) {
                Err(err) => {
                    error!(
                        "Could not decode response from publication \
                         server at: {}, for ca: {}. Error: {}",
                         server_info.service_uri, ca_handle, err
                    );
                    cms_logger.err(
                        format!("Could not decode CMS: {err}"
                    ))?;
                    Err(Error::Rfc8181(err))
                }
                Ok(cms) => match cms.validate(&server_info.public_key) {
                    Err(err) => {
                        error!(
                            "Could not validate response from \
                            publication server at: {}, \
                            for ca: {}. Error: {}",
                            server_info.service_uri, ca_handle, err

                        );
                        cms_logger.err(
                            format!("Response invalid: {err}")
                        )?;
                        Err(Error::Rfc8181(err))
                    }
                    Ok(()) => {
                        cms.into_message().as_reply().map_err(
                            Error::Rfc8181
                        )
                    }
                },
            }
        }
    }
}

