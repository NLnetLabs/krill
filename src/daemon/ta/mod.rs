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
            eventsourcing::AggregateStore,
        },
        daemon::config::ConfigDefaults,
        test::*,
    };

    #[test]
    fn init_ta() {
        test_under_tmp(|d| {
            init_logging();

            let ta_signer_store: AggregateStore<TrustAnchorSigner> = AggregateStore::disk(&d, "ta_signer").unwrap();
            let ta_proxy_store: AggregateStore<TrustAnchorProxy> = AggregateStore::disk(&d, "ta_proxy").unwrap();

            let signers = ConfigDefaults::signers();
            let signer = Arc::new(
                KrillSignerBuilder::new(&d, Duration::from_secs(1), &signers)
                    .build()
                    .unwrap(),
            );

            let actor = test_actor();

            let proxy_handle = TrustAnchorHandle::new("proxy".into());

            let init = TrustAnchorProxy::create_init(proxy_handle.clone(), &signer).unwrap();

            let mut proxy = ta_proxy_store.add(init).unwrap();

            let repository = {
                let repo_info = RepoInfo::new(
                    rsync("rsync://example.krill.cloud/repo/"),
                    Some(https("https://exmple.krill.cloud/repo/notification.xml")),
                );
                let repo_key_id = signer.create_key().unwrap();
                let repo_key = signer.get_key_info(&repo_key_id).unwrap();

                let service_uri = ServiceUri::Https(https("https://example.krill.cloud/rfc8181/ta"));
                let server_info = PublicationServerInfo::new(repo_key, service_uri);

                RepositoryContact::new(repo_info, server_info)
            };

            let add_repo_cmd = TrustAnchorProxyCommand::add_repo(&proxy_handle, repository, &actor);
            proxy = ta_proxy_store.command(add_repo_cmd).unwrap();

            let signer_handle = TrustAnchorHandle::new("signer".into());
            let tal_https = vec![https("https://example.krill.cloud/ta/ta.cer")];
            let tal_rsync = rsync("rsync://example.krill.cloud/ta/ta.cer");

            let signer_init_cmd = proxy
                .create_signer_init_cmd(signer_handle.clone(), tal_https, tal_rsync, signer.clone())
                .unwrap();

            let signer_init = TrustAnchorSigner::create_init(signer_init_cmd).unwrap();

            let mut ta_signer = ta_signer_store.add(signer_init).unwrap();
            let signer_info = ta_signer.get_signer_info();
            let add_signer_cmd = TrustAnchorProxyCommand::add_signer(&proxy_handle, signer_info, &actor);

            ta_proxy_store.command(add_signer_cmd).unwrap();

            let make_publish_request_cmd = TrustAnchorProxyCommand::make_signer_request(&proxy_handle, &actor);
            proxy = ta_proxy_store.command(make_publish_request_cmd).unwrap();

            let signer_request = proxy.get_signer_request().unwrap();

            let request_nonce = signer_request.nonce.clone();

            let ta_signer_process_request_command = TrustAnchorSignerCommand::make_process_request_command(
                &signer_handle,
                signer_request,
                signer.clone(),
                &actor,
            );
            ta_signer = ta_signer_store.command(ta_signer_process_request_command).unwrap();

            let exchange = ta_signer.get_exchange(&request_nonce).unwrap();
            let ta_proxy_process_signer_response_command =
                TrustAnchorProxyCommand::process_signer_response(&proxy_handle, exchange.response.clone(), &actor);

            proxy = ta_proxy_store
                .command(ta_proxy_process_signer_response_command)
                .unwrap();

            // // First we need to set up the online TA
            // // The offline TA can only be set up when its online counterpart
            // // is initialised.
            // let online_cmd_init = OnlineTrustAnchorInitCommand {
            //     handle: OnlineTrustAnchorHandle::new("sub-ta".into()),
            //     signer: signer.clone(),
            // };
            // let online_ta = online_store
            //     .add(OnlineTrustAnchor::init(online_cmd_init).unwrap())
            //     .unwrap();

            // let repo_info = RepoInfo::new(
            //     rsync("rsync://example.krill.cloud/repo/"),
            //     Some(https("https://example.krill.cloud/repo/notification.xml")),
            // );

            // let tal_https = vec![https("https://example.krill.cloud/ta/ta.cer")];
            // let tal_rsync = rsync("rsync://example.krill.cloud/ta/ta.cer");

            // // todo: create online ta first
            // let counterpart = online_ta.as_counterpart();

            // let init_cmd = OfflineTrustAnchorInitCommand {
            //     handle: OfflineTrustAnchorHandle::new("ta".into()),
            //     repo_info,
            //     tal_https,
            //     tal_rsync,
            //     counterpart,
            //     signer,
            // };

            // let init_event = OfflineTrustAnchor::init(init_cmd).unwrap();

            // offline_store.add(init_event).unwrap();
        })
    }
}
