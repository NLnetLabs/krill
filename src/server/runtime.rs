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


use std::sync::Arc;
//use std::time::Duration;
//use log::info;
use rpki::uri;
use tokio::runtime;
use tokio::sync::oneshot;
use crate::commons::actor::Actor;
use crate::commons::crypto::{KrillSigner/*, KrillSignerBuilder*/};
//use crate::commons::error::KrillError;
use crate::config::Config;
//use crate::constants::{ACTOR_DEF_KRILL, KRILL_SERVER_APP};
use super::bgp::BgpAnalyser;
use super::ca::CaManager;
use super::mq::TaskQueue;
use super::pubd::RepositoryManager;


//------------ KrillRuntime --------------------------------------------------

#[derive(Clone)]
pub struct KrillRuntime(Arc<Components>);

impl KrillRuntime {
    /*
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
        let repo_manager = RepositoryManager::build(&config)?;
        let ca_manager = CaManager::build(&config)?;
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
    */

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

    pub fn bpg_analyseer(&self) -> &BgpAnalyser {
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
        let _ = self.0.tokio.spawn(future);
    }

    /// Spawns a closure onto the sync runtime.
    pub fn spawn_blocking(
        &self, op: impl FnOnce() + Send + 'static
    ) {
        let _ = self.0.tokio.spawn_blocking(op);
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
    bgp_analyser: Arc<BgpAnalyser>,

    /// The actor used for actions initiated by the server itself.
    system_actor: Actor,

    /// The Tokio runtime to spawn tasks onto.
    ///
    /// We currently use it for both async and sync tasks (via
    /// `spawn_blocking`).
    tokio: runtime::Handle,
}


//------------ Init ----------------------------------------------------------

pub struct Init<Cap, Fut: Future> {
    /// The capture value passed along during execution.
    capture: Cap,

    /// The initial calculation of the errand.
    value: MaybeFuture<Fut>,

    /// The Krill runtime to use and pass along.
    krill: KrillRuntime,
}

impl<Cap, Fut: Future> Init<Cap, Fut> {
    pub fn then<Op>(self, op: Op) -> Then<Self, Op> {
        Then {
            before: self,
            op: op
        }
    }
}

impl<Cap, Fut> Errand for Init<Cap, Fut>
where
    Cap: Send + 'static,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    type Capture = Cap;
    type Output = Fut::Output;

    fn run<Then>(self, then: Then)
    where
        Then: 
            FnOnce(Cap, Self::Output, KrillRuntime)
            + Send + 'static
    {
        match self.value {
            MaybeFuture::Ready(res) => (then)(self.capture, res, self.krill),
            MaybeFuture::Future(fut) => {
                self.krill.clone().spawn_async(async move {
                    let res = fut.await;
                    self.krill.clone().spawn_blocking(move || {
                        (then)(self.capture, res, self.krill);
                    })
                })
            }
        }
    }

    fn finish(self, tx: oneshot::Sender<Fut::Output>) {
        match self.value {
            MaybeFuture::Ready(res) => {
                let _ = tx.send(res);
            }
            MaybeFuture::Future(fut) => {
                self.krill.spawn_async(async {
                    let _ = tx.send(fut.await);
                })
            }
        }
    }
}


//------------ Then ----------------------------------------------------------

/// An errand with an additional stage chained to it.
pub struct Then<Before, Op> {
    // the errand that produces the output we are processing
    before: Before,

    // a function that is run sync and returns a future.
    //
    // this needs to be spawned blocking when outer resolves.
    op: Op,
}

impl<Before, Op> Then<Before, Op> {
    pub fn then<OOp>(self, op: OOp) -> Then<Self, OOp>{
        Then {
            before: self,
            op,
        }
    }
}

impl<Before, Op> Errand for Then<Before, Op>
where
    Before: Errand,
    Op: IntoMaybeFuture<Capture = Before::Capture, Input = Before::Output>,
{
    type Capture = Op::Capture;
    type Output = Op::Output;

    fn run<Then>(self, then: Then)
    where
        Then: 
            FnOnce(Op::Capture, Self::Output, KrillRuntime)
            + Send + 'static
    {
        self.before.run(|mut capture, input, krill| {
            match self.op.eval(&mut capture, input, &krill) {
                MaybeFuture::Ready(res) => (then)(capture, res, krill),
                MaybeFuture::Future(fut) => {
                    krill.clone().spawn_async(async {
                        let res = fut.await;
                        krill.clone().spawn_blocking(|| {
                            (then)(capture, res, krill);
                        })
                    })
                }
            }
        })
    }

    fn finish(self, tx: oneshot::Sender<Op::Output>) {
        self.before.run(|mut capture, input, krill| {
            match self.op.eval(&mut capture, input, &krill) {
                MaybeFuture::Ready(res) => {
                    let _ = tx.send(res);
                }
                MaybeFuture::Future(fut) => {
                    krill.spawn_async(async {
                        let _ = tx.send(fut.await);
                    })
                }
            }
        });
    }
}


//------------ MaybeFuture ---------------------------------------------------

/// A value that is either already present or the result of a future.
pub enum MaybeFuture<Fut: Future> {
    /// The value is already present.
    Ready(Fut::Output),

    /// The value needs to be calculated by resolving the future.
    Future(Fut),
}


//------------ IntoMaybeFuture -----------------------------------------------

/// An operation that will result in a `MaybeFuture`.
pub trait IntoMaybeFuture: Send + 'static {
    type Capture: Send + 'static;
    type Input: Send + 'static;
    type Output: Send + 'static;
    type Future: Future<Output = Self::Output> + Send + 'static;

    fn eval(
        self,
        capture: &mut Self::Capture,
        input: Self::Input,
        krill: &KrillRuntime,
    ) -> MaybeFuture<Self::Future>;
}


//------------ Errand --------------------------------------------------------

/// A single step in running an errand.
pub trait Errand: Sized {
    type Capture: Send + 'static;
    type Output: Send + 'static;

    fn run<Then>(self, then: Then)
    where
        Then: 
            FnOnce(Self::Capture, Self::Output, KrillRuntime)
            + Send + 'static
    ;

    fn finish(self, tx: oneshot::Sender<Self::Output>);
}

