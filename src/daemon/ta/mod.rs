//! Trust Anchor Support
//!
use rpki::ca::idexchange::CaHandle;

mod common;
pub use self::common::*;

mod proxy;
pub use self::proxy::*;

mod signer;
pub use self::signer::*;

pub const TA_NAME: &str = "ta"; // reserved for TA

//------------ TrustAnchor Handle Types ------------------------------------

pub type TrustAnchorHandle = CaHandle;

pub fn ta_handle() -> CaHandle {
    use std::str::FromStr;
    CaHandle::from_str(TA_NAME).unwrap()
}

fn ta_resource_class_name() -> rpki::ca::provisioning::ResourceClassName {
    "default".into()
}

//----------------- TESTS --------------------------------------------------------------
#[cfg(test)]
mod tests {
    use rpki::ca::idexchange::{RepoInfo, ServiceUri};

    use super::*;

    use std::{sync::Arc, time::Duration};

    use crate::{
        commons::{
            api::{PublicationServerInfo, RepositoryContact},
            crypto::KrillSignerBuilder,
            eventsourcing::{segment, AggregateStore, Segment},
        },
        daemon::config::ConfigDefaults,
        test,
    };

    #[test]
    fn init_ta() {
        test::test_in_memory(|storage_uri| {
            let cleanup = test::init_logging();

            let ta_signer_store: AggregateStore<TrustAnchorSigner> =
                AggregateStore::create(storage_uri, segment!("ta_signer"), false).unwrap();
            let ta_proxy_store: AggregateStore<TrustAnchorProxy> =
                AggregateStore::create(storage_uri, segment!("ta_proxy"), false).unwrap();

            // We will import a TA key - this is only (supposed to be) supported for the openssl signer
            let signers = ConfigDefaults::openssl_signer_only();
            let signer = Arc::new(
                KrillSignerBuilder::new(storage_uri, Duration::from_secs(1), &signers)
                    .build()
                    .unwrap(),
            );

            let actor = test::test_actor();

            let proxy_handle = TrustAnchorHandle::new("proxy".into());

            let init = TrustAnchorProxy::create_init(proxy_handle.clone(), &signer).unwrap();

            ta_proxy_store.add(init).unwrap();

            let repository = {
                let repo_info = RepoInfo::new(
                    test::rsync("rsync://example.krill.cloud/repo/"),
                    Some(test::https("https://exmple.krill.cloud/repo/notification.xml")),
                );
                let repo_key_id = signer.create_key().unwrap();
                let repo_key = signer.get_key_info(&repo_key_id).unwrap();

                let service_uri = ServiceUri::Https(test::https("https://example.krill.cloud/rfc8181/ta"));
                let server_info = PublicationServerInfo::new(repo_key, service_uri);

                RepositoryContact::new(repo_info, server_info)
            };

            let add_repo_cmd = TrustAnchorProxyCommand::add_repo(&proxy_handle, repository, &actor);
            let mut proxy = ta_proxy_store.command(add_repo_cmd).unwrap();

            let signer_handle = TrustAnchorHandle::new("signer".into());
            let tal_https = vec![test::https("https://example.krill.cloud/ta/ta.cer")];
            let tal_rsync = test::rsync("rsync://example.krill.cloud/ta/ta.cer");

            let import_key_pem = include_str!("../../../test-resources/ta/example-pkcs1.pem");

            let signer_init_cmd = TrustAnchorSignerInitCommand {
                handle: signer_handle.clone(),
                proxy_id: proxy.id().clone(),
                repo_info: proxy.repository().unwrap().repo_info().clone(),
                tal_https: tal_https.clone(),
                tal_rsync: tal_rsync.clone(),
                private_key_pem: Some(import_key_pem.to_string()),
                signer: signer.clone(),
            };

            let signer_init = TrustAnchorSigner::create_init(signer_init_cmd).unwrap();

            let mut ta_signer = ta_signer_store.add(signer_init).unwrap();
            let signer_info = ta_signer.get_signer_info();
            let add_signer_cmd = TrustAnchorProxyCommand::add_signer(&proxy_handle, signer_info, &actor);

            proxy = ta_proxy_store.command(add_signer_cmd).unwrap();

            // The initial signer starts off with a TA certificate
            // and a CRL and manifest with revision number 1.
            let ta_objects = proxy.get_trust_anchor_objects().unwrap();
            assert_eq!(ta_objects.revision().number(), 1);

            let ta_cert_details = proxy.get_ta_details().unwrap();
            assert_eq!(ta_cert_details.tal().uris(), &tal_https);
            assert_eq!(ta_cert_details.tal().rsync_uri(), &tal_rsync);

            // We can make a new signer request to make a new manifest and CRL
            // even if we do not yet have any issued certificates to publish.
            let make_publish_request_cmd = TrustAnchorProxyCommand::make_signer_request(&proxy_handle, &actor);
            proxy = ta_proxy_store.command(make_publish_request_cmd).unwrap();

            let signed_request = proxy.get_signer_request(&signer).unwrap();
            let request_nonce = signed_request.content().nonce.clone();

            let ta_signer_process_request_command =
                TrustAnchorSignerCommand::make_process_request_command(&signer_handle, signed_request, signer, &actor);
            ta_signer = ta_signer_store.command(ta_signer_process_request_command).unwrap();

            let exchange = ta_signer.get_exchange(&request_nonce).unwrap();
            let ta_proxy_process_signer_response_command =
                TrustAnchorProxyCommand::process_signer_response(&proxy_handle, exchange.response.clone(), &actor);

            proxy = ta_proxy_store
                .command(ta_proxy_process_signer_response_command)
                .unwrap();

            // The TA should have published again, the revision used for manifest and crl will
            // have been updated.
            let ta_objects = proxy.get_trust_anchor_objects().unwrap();
            assert_eq!(ta_objects.revision().number(), 2);

            // We still need to test some higher order functions:
            // - add child
            // - let the child request a certificate
            // - let the child perform a key rollover
            // - let the TA publish
            //
            // This is hard to test at this level. So, will test this as part of the higher
            // order functional tests found under /tests. I.e. we will start a full krill
            // server with testbed support, which will use the TrustAnchorProxy and Signer.

            cleanup();
        })
    }
}
