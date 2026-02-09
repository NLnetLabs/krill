//! The server’s runtime.
//!
//! The Krill server contains both sync and async code. This module provides
//! the means to manage control flow through all these parts.
//!
//! Most processing in Krill happens in sync code because that is easier to
//! reason about. However, certain things – most prominently the HTTP
//! requests made to talk to remote repositories and parent CAs – have the
//! potential to block threads for an unduly long time. So these are best
//! performed as tasks on an async runtime.
//!
//! A consequence of this is that processing needs to be able to go from
//! sync to async and then back to sync. This module provides a mechanism to
//! do this in a safe and ergonomic way.
//!
//! > Side note: The terminology we are using is a bit creative. All the
//! > obvious terms are already used elsewhere and we don’t want ambiguity,
//! > so we had to resort to scroll quite a bit down in a thesaurus.
//!


use std::mem::drop;
use std::sync::Arc;
use std::time::Duration;
use log::info;
use rpki::uri;
use tokio::runtime;
use crate::commons::actor::Actor;
use crate::commons::crypto::{KrillSigner, KrillSignerBuilder};
use crate::commons::error::KrillError;
use crate::config::Config;
use crate::constants::{ACTOR_DEF_KRILL, KRILL_SERVER_APP};
use super::bgp::BgpAnalyser;
use super::ca::CaManager;
use super::mq::TaskQueue;
use super::pubd::RepositoryManager;


//------------ KrillRuntime --------------------------------------------------

#[derive(Clone)]
pub struct KrillRuntime(Arc<Components>);

impl KrillRuntime {
    pub fn new(
        config: Config,
        tokio: runtime::Handle,
    ) -> Result<Self, KrillError> {
        let service_uri = config.service_uri();

        info!("{KRILL_SERVER_APP} uses service uri: {service_uri}");

        // Assumes that Config::verify() has already ensured that the signer
        // configuration is valid and that Config::resolve() has been
        // used to update signer name references to resolve to the
        // corresponding signer configurations.
        let signer = KrillSignerBuilder::new(
            &config.storage_uri,
            Duration::from_secs(config.signer_probe_retry_seconds),
            &config.signers,
        ).with_default_signer(
            config.default_signer()
        ).with_one_off_signer(
            config.one_off_signer()
        ).build()?;

        let tasks = TaskQueue::new(&config.storage_uri)?;
        let repo_manager = RepositoryManager::new(&config)?;
        let ca_manager = CaManager::new(&config)?;
        let bgp_analyser = BgpAnalyser::new(&config);

        Ok(Self(Arc::new(Components {
            config,
            service_uri,
            repo_manager,
            ca_manager,
            tasks,
            signer,
            bgp_analyser,
            system_actor: ACTOR_DEF_KRILL,
            tokio,
        })))
    }

    pub fn config(&self) -> &Config {
        &self.0.config
    }

    pub fn service_uri(&self) -> &uri::Https {
        &self.0.service_uri
    }

    pub fn repo_manager(&self) -> &RepositoryManager {
        &self.0.repo_manager
    }

    pub fn ca_manager(&self) -> &CaManager {
        &self.0.ca_manager
    }

    pub fn tasks(&self) -> &TaskQueue {
        &self.0.tasks
    }

    pub fn signer(&self) -> &KrillSigner {
        &self.0.signer
    }

    pub fn bgp_analyser(&self) -> &BgpAnalyser {
        &self.0.bgp_analyser
    }

    pub fn system_actor(&self) -> &Actor {
        &self.0.system_actor
    }

    /// Returns whether testbed mode is enabled.
    pub fn is_testbed_enabled(&self) -> bool {
        self.config().testbed().is_some()
    }

    /// Spawns a future onto the async runtime.
    pub fn spawn_async(
        &self, future: impl Future<Output = ()> + Send + 'static
    ) {
        // Explicitely drop the join handle so Clippy doesn’t complain. The
        // task will continue running.
        drop(self.0.tokio.spawn(future));
    }
}


//------------ Components ----------------------------------------------------

struct Components {
    /// The server configuration.
    ///
    /// This has to be an arc for now since some components keep a copy.
    config: Config,

    /// The base URI for communicating with this server.
    ///
    /// We keep it separately because the config only keeps the configured
    /// value which may be missing.
    service_uri: uri::Https,

    /// Publication server with configured publishers
    repo_manager: RepositoryManager,

    /// The manager for all our CAs.
    ca_manager: CaManager,

    /// The task queue.
    tasks: TaskQueue,

    /// The signer.
    signer: KrillSigner,

    /// The BGP analyser.
    bgp_analyser: BgpAnalyser,

    /// The actor used for actions initiated by the server itself.
    system_actor: Actor,

    /// The Tokio runtime to spawn tasks onto.
    ///
    /// We currently use it for both async and sync tasks (via
    /// `spawn_blocking`).
    tokio: runtime::Handle,
}

