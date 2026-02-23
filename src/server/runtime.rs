//! The Krill server runtime.
//!
//! The runtime contains all the components of a Krill server in one central
//! place and allows access to them. A reference to it is being passed around
//! when performing actions that may require access to other compontents.

use std::{cmp, error, fmt, thread};
use std::mem::drop;
use std::sync::{mpsc as std_mpsc};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use log::{error, info};
use rpki::uri;
use tokio::runtime;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
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

/// The Krill runtime.
///
/// The runtime contains all the components of the Krill server and provides
/// access to them. It is keeps them behind an arc, so it can be cloned and
/// passed around cheaply.
///
/// Many methods of the various components expect a refernce to the runtime
/// so they can initiate follow-up operations on other Krill components.
#[derive(Clone)]
pub struct KrillRuntime(Arc<Components>);

impl KrillRuntime {
    /// Creates a new Krill runtime.
    ///
    /// The runtime and all the components will be configured using `config`.
    /// The `tokio` runtime handle will be used by the
    /// [`spawn_async`][Self::spawn_async] method as the runtime to spawn
    /// async tasks onto.
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

    /// Returns the config used to create the runtime.
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// Returns the service URI of this Krill server instance.
    pub fn service_uri(&self) -> &uri::Https {
        &self.0.service_uri
    }

    /// Returns the repository manager.
    pub fn repo_manager(&self) -> &RepositoryManager {
        &self.0.repo_manager
    }

    /// Returns the CA manager.
    pub fn ca_manager(&self) -> &CaManager {
        &self.0.ca_manager
    }

    /// Returns the task queue.
    pub fn tasks(&self) -> &TaskQueue {
        &self.0.tasks
    }

    /// Returns the signer.
    pub fn signer(&self) -> &KrillSigner {
        &self.0.signer
    }

    /// Returns the BGP analyser.
    pub fn bgp_analyser(&self) -> &BgpAnalyser {
        &self.0.bgp_analyser
    }

    /// Returns the actor to be used for sytem tasks.
    pub fn system_actor(&self) -> &Actor {
        &self.0.system_actor
    }

    /// Returns whether testbed mode is enabled.
    pub fn is_testbed_enabled(&self) -> bool {
        self.config().testbed().is_some()
    }

    /// Runs a future on a Tokio runtime and blocks until it resolves.
    ///
    /// This method blocks the current thread.
    pub fn exec_async<F>(
        &self, future: F
    ) -> Result<F::Output, ExecAsyncError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let join = self.0.tokio.spawn(async move {
            let _ = tx.send(future.await);
        });
        drop(join); // explicitly drop to avoid warning
        rx.blocking_recv().map_err(|_| ExecAsyncError(()))
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

    /// The Tokio runtime to spawn async tasks onto.
    tokio: runtime::Handle,
}


//------------ ThreadPool ----------------------------------------------------

pub struct ThreadPool {
    /// The sending end of the job queue.
    worker_tx: tokio_mpsc::Sender<ThreadPoolMessage>,

    /// The sending ends of all shutdown queues for regular threads.
    thread_tx: Vec<std_mpsc::SyncSender<()>>,

    /// The join handles of all child threads.
    join: Vec<thread::JoinHandle<()>>,
}

impl ThreadPool {
    pub fn new(
        config: &Config
    ) -> Result<Self, KrillError> {
        let (worker_tx, rx) = tokio_mpsc::channel(1);
        let rx = Arc::new(Mutex::new(rx));

        let thread_count = match config.num_threads {
            Some(num) => num,
            None => {
                match thread::available_parallelism() {
                    Ok(num) => num.into(),
                    Err(err) => {
                        return Err(KrillError::internal(
                            format_args!(
                                "failed to determine thread number. Please \
                                 specify `num_threads` in config. \
                                 ({err})"
                            )
                        ));
                    }
                }
            }
        };
        let thread_count = cmp::min(thread_count, 1);

        let mut join = Vec::new();
        for _ in 0..thread_count {
            let rx = rx.clone();
            join.push(thread::spawn(move || {
                Self::worker_thread(rx)
            }));
        }

        Ok(Self {
            worker_tx,
            thread_tx: Vec::new(),
            join
        })
    }

    fn worker_thread(
        rx: Arc<Mutex<tokio_mpsc::Receiver<ThreadPoolMessage>>>,
    ) {
        loop {
            let job = {
                let mut queue = match rx.lock() {
                    Ok(queue) => queue,
                    Err(err) => {
                        error!(
                            "Fatal: worker thread failed to aquire lock: {err}"
                        );
                        return;
                    }
                };
                let Some(job) = queue.blocking_recv() else {
                    // None is returned when the queue is closed or when
                    // all the senders are gone.
                    return;
                };
                match job {
                    ThreadPoolMessage::Job(job) => job,
                    ThreadPoolMessage::Shutdown => {
                        // Close the queue. If there are any tasks left,
                        // we want to still process those, so continue here.
                        queue.close();
                        continue;
                    }
                }
            };
            (job)();
        }
    }

    pub fn handle(&self) -> ThreadPoolHandle {
        ThreadPoolHandle { tx: self.worker_tx.clone() }
    }

    pub fn spawn(
        &mut self, f: impl FnOnce(std_mpsc::Receiver<()>) + Send + 'static
    ) {
        let (tx, rx) = std_mpsc::sync_channel(1);
        self.thread_tx.push(tx);
        self.join.push(thread::spawn(|| f(rx)));
    }

    pub fn terminate(self) {
        let _ = self.worker_tx.blocking_send(ThreadPoolMessage::Shutdown);
        for tx in self.thread_tx {
            let _ = tx.send(());
        }
        for join in self.join {
            // `join` returns an error if the thread panicked. We can
            // consider it done in this case.
            eprintln!("Joining thread {:?}.", join.thread().id());
            let _ = join.join();
        }
    }
}


//------------ ThreadPoolHandle ----------------------------------------------

#[derive(Clone)]
pub struct ThreadPoolHandle {
    /// The sending end of the job queue.
    tx: tokio_mpsc::Sender<ThreadPoolMessage>,
}

impl ThreadPoolHandle {
    pub async fn spawn(
        &self, job: impl FnOnce() + Send + 'static
    ) -> Result<(), SpawnError> {
        self.tx.send(
            ThreadPoolMessage::Job(Box::new(job))
        ).await.map_err(|_| SpawnError(()))
    }
}


//------------ ThreadPoolMessage ---------------------------------------------

/// The message sent to the queue of the thread pool.
enum ThreadPoolMessage {
    /// A job to run.
    Job(Box<dyn FnOnce() + Send + 'static>),

    /// The thread pool is shutting down.
    Shutdown,
}


//============ SpawnError ====================================================

//------------ SpawnError ----------------------------------------------------

/// An error happened while trying to spawn a job.
///
/// This error means that all worker threads have disappeared.
#[derive(Clone, Debug)]
pub struct SpawnError(());

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("all worker threads disappeared")
    }
}

impl error::Error for SpawnError { }


//------------ ExecAsyncError ------------------------------------------------

/// An error happened while waiting for a future to resolve.
///
/// This error means that the executed future was dropped before being
/// resolved.
#[derive(Clone, Debug)]
pub struct ExecAsyncError(());

impl fmt::Display for ExecAsyncError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("the future was dropped before resolving")
    }
}

impl error::Error for ExecAsyncError { }

