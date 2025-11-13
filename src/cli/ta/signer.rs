//! Managing the Trust Anchor Signer.

use std::sync::Arc;
use rpki::ca::idexchange;
use rpki::ca::idexchange::CaHandle;
use rpki::uri;
use crate::tasigner;
use crate::api::status::Success;
use crate::api::ca::IdCertInfo;
use crate::api::ta::{
    TrustAnchorSignedRequest, TrustAnchorSignedResponse,
    TrustAnchorSignerInfo,
};
use crate::commons::crypto::KrillSigner;
use crate::commons::actor::Actor;
use crate::commons::error::Error as KrillError;
use crate::commons::eventsourcing::{AggregateStore, AggregateStoreError};
use crate::commons::storage::Ident;
use crate::commons::httpclient;
use crate::tasigner::{
    Config, TrustAnchorProxySignerExchanges,
    TrustAnchorSigner, TrustAnchorSignerCommand, TrustAnchorSignerInitCommand,
    TrustAnchorSignerInitCommandDetails,
};


//------------ Client Error --------------------------------------------------

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SignerClientError {
    DataDirMissing,
    UnrecognizedMatch,
    HttpClientError(httpclient::Error),
    KrillError(KrillError),
    StorageError(AggregateStoreError),
    ConfigError(tasigner::ConfigError),
    Other(String),
}

impl SignerClientError {
    fn other(msg: impl std::fmt::Display) -> Self {
        Self::Other(msg.to_string())
    }
}

impl std::fmt::Display for SignerClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SignerClientError::DataDirMissing => {
                write!(f, "Cannot find data dir")
            }
            SignerClientError::UnrecognizedMatch => {
                write!(f, "Unrecognised argument. Use 'help'")
            }
            SignerClientError::HttpClientError(e) => {
                write!(f, "HTTP client error: {e}")
            }
            SignerClientError::KrillError(e) => write!(f, "{e}"),
            SignerClientError::StorageError(e) => {
                write!(f, "Issue with persistence layer: {e}")
            }
            SignerClientError::ConfigError(e) => {
                write!(f, "Issue with configuration file: {e}")
            }
            SignerClientError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<tasigner::ConfigError> for SignerClientError {
    fn from(e: tasigner::ConfigError) -> Self {
        Self::ConfigError(e)
    }
}

impl From<KrillError> for SignerClientError {
    fn from(e: KrillError) -> Self {
        Self::KrillError(e)
    }
}

impl From<AggregateStoreError> for SignerClientError {
    fn from(e: AggregateStoreError) -> Self {
        Self::StorageError(e)
    }
}


//------------ SignerInitInfo ------------------------------------------------

#[derive(Debug)]
pub struct SignerInitInfo {
    pub proxy_id: IdCertInfo,
    pub repo_info: idexchange::RepoInfo,
    pub tal_https: Vec<uri::Https>,
    pub tal_rsync: uri::Rsync,
    pub private_key_pem: Option<String>,
    pub ta_mft_nr_override: Option<u64>,
}


//------------ SignerReissueInfo ----------------------------------------------
#[derive(Debug)]
pub struct SignerReissueInfo {
    pub proxy_id: IdCertInfo,
    pub repo_info: idexchange::RepoInfo,
    pub tal_https: Vec<uri::Https>,
    pub tal_rsync: uri::Rsync,
}


//------------ TrustAnchorSignerManager --------------------------------------

pub struct TrustAnchorSignerManager {
    store: AggregateStore<TrustAnchorSigner>,
    ta_handle: CaHandle,
    config: Config,
    signer: Arc<KrillSigner>,
    actor: Actor,
}

impl TrustAnchorSignerManager {
    pub fn create(config: Config) -> Result<Self, SignerClientError> {
        let store = AggregateStore::create(
            &config.storage_uri,
            const { Ident::make("signer") },
            config.use_history_cache,
        ).map_err(SignerClientError::other)?;
        let ta_handle = CaHandle::new("ta".into());
        let signer = config.signer()?;
        let actor = crate::constants::ACTOR_DEF_KRILLTA;

        Ok(TrustAnchorSignerManager {
            store,
            ta_handle,
            config,
            signer,
            actor,
        })
    }

    pub fn init(
        &self,
        info: SignerInitInfo,
    ) -> Result<Success, SignerClientError> {
        if self.store.has(&self.ta_handle)? {
            Err(SignerClientError::other(
                "Trust Anchor Signer was already initialised.",
            ))
        } else {
            let cmd = TrustAnchorSignerInitCommand::new(
                self.ta_handle.clone(),
                TrustAnchorSignerInitCommandDetails {
                    proxy_id: info.proxy_id,
                    repo_info: info.repo_info,
                    tal_https: info.tal_https,
                    tal_rsync: info.tal_rsync,
                    private_key_pem: info.private_key_pem,
                    ta_mft_nr_override: info.ta_mft_nr_override,
                    timing: self.config.ta_timing,
                    signer: self.signer.clone(),
                },
                &self.actor,
            );

            self.store.add(cmd)?;

            Ok(Success)
        }
    }

    pub fn reissue(
        &self,
        info: SignerReissueInfo,
    ) -> Result<Success, SignerClientError> {
        let _ = self.get_signer()?;

        let cmd = TrustAnchorSignerCommand::make_reissue_command(
        &self.ta_handle,
            info.repo_info,
            info.tal_https,
            info.tal_rsync,
            self.config.ta_timing,
            self.signer.clone(),
            &self.actor,
        );

        self.store.command(cmd)?;

        Ok(Success)
    }

    pub fn show(&self) -> Result<TrustAnchorSignerInfo, SignerClientError> {
        let ta_signer = self.get_signer()?;
        Ok(ta_signer.get_signer_info())
    }

    pub fn process(
        &self,
        signed_request: TrustAnchorSignedRequest,
        ta_mft_number_override: Option<u64>,
    ) -> Result<TrustAnchorSignedResponse, SignerClientError> {
        let cmd = TrustAnchorSignerCommand::make_process_request_command(
            &self.ta_handle,
            signed_request,
            self.config.ta_timing,
            ta_mft_number_override,
            self.signer.clone(),
            &self.actor,
        );
        self.store.command(cmd)?;

        self.show_last_response()
    }

    pub fn show_last_response(
        &self,
    ) -> Result<TrustAnchorSignedResponse, SignerClientError> {
        self.get_signer()?
            .get_latest_exchange()
            .map(|exchange| exchange.response.clone())
            .ok_or_else(|| SignerClientError::other("No response found."))
    }

    pub fn show_exchanges(
        &self,
    ) -> Result<TrustAnchorProxySignerExchanges, SignerClientError> {
        let signer = self.get_signer()?;
        // In this context it's okay to clone the exchanges.
        // If we are afraid that this would become too expensive, then we will
        // need to rethink the model where we return data in the enum that we
        // use. We can't have references and lifetimes because the signer will
        // be gone..
        //
        // But, again, in this context this should never be huge with
        // exchanges happening every couple of months. So, it should
        // all be fine.
        Ok(signer.get_exchanges().clone())
    }

    fn get_signer(
        &self
    ) -> Result<Arc<TrustAnchorSigner>, SignerClientError> {
        if self.store.has(&self.ta_handle)? {
            self.store
                .get_latest(&self.ta_handle)
                .map_err(SignerClientError::KrillError)
        } else {
            Err(SignerClientError::other(
                "Trust Anchor Signer is not initialised.",
            ))
        }
    }
}

