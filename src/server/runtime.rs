//! The Krill server runtime.
//!
//! The runtime contains all the components of a Krill server in one central
//! place and allows access to them. A reference to it is being passed around
//! when performing actions that may require access to other compontents.
//!
//! In addition, this module also provides the [`ThreadPool`] that is used
//! by the daemon to run its jobs on.

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
/// Many methods of the various components expect a reference to the runtime
/// so they can initiate follow-up operations on other Krill components.
#[derive(Clone)]
pub struct KrillRuntime(Arc<Components>);

impl KrillRuntime {
    /// Creates a new Krill runtime.
    ///
    /// The runtime and all the components will be configured using `config`.
    /// The `tokio` runtime handle will be used by the
    /// [`exec_async`][Self::exec_async] method as the runtime to spawn
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

/// All the components of a Krill server.
///
/// A value of this type is kept by [`KrillRuntime`] behind an arc.
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

/// A thread pool to run jobs on.
///
/// This type represents the thread pool itself and should be kept around
/// during the entire lifetime of the pool.
///
/// Jobs are spawned onto the pool through a
/// [`ThreadPoolHandle`] which can be obtained via the
/// [`handle`][Self::handle] method.
///
/// Additional, non-worker threads can be created using the
/// [`spawn`][Self::spawn] method. This feature is used for the
/// scheduler thread. Spawning a thread via the thread pool differs regular
/// threads in that it provides a means to signal that the thread should
/// exit.
///
/// This becomes relevant when it is time to shut down the application. In
/// this case, the [`terminate`][Self::terminate] method is called. The
/// imminent shutdown is signalled to all the worker threads and the
/// additional threads and then the method blocks and waits for all threads
/// to exit.
///
/// During shutdown, the thread pool will not accept new jobs but the
/// worker threads will process all already queued jobs. This is slightly
/// theoretical as the queue capacity is 1, so there should be at most one
/// queued job.
pub struct ThreadPool {
    /// The sending end of the job queue.
    ///
    /// The receiving end of this queue is shared between all worker threads.
    worker_tx: tokio_mpsc::Sender<ThreadPoolMessage>,

    /// The sending ends of all shutdown queues for regular threads.
    ///
    /// Each thread spawned via the `spawn` method gets the receiving end
    /// of one of these. During shutdown, a `()` is sent to each of them.
    thread_tx: Vec<std_mpsc::SyncSender<()>>,

    /// The join handles of all child threads.
    ///
    /// We will wait for all of them during shutdown.
    join: Vec<thread::JoinHandle<()>>,
}

impl ThreadPool {
    /// Creates a new thread pool based on the config.
    ///
    /// Currently, we only use [`config.num_threads`][Config::num_threads]
    /// to allow users to configure the number of worker threads. By default,
    /// the number is the available parallelism as reported by the standard
    /// library.
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

        info!("Created thread pool with {thread_count} threads");

        Ok(Self {
            worker_tx,
            thread_tx: Vec::new(),
            join
        })
    }

    /// The thread function of each worker thread.
    ///
    /// The function receives a copy of the receiving end of the job queue
    /// behind a mutex which allows the thread to acquire new work.
    ///
    /// The work distribution mechanism is extremely simple: When it is out
    /// of work, a thread will try to acquire the lock on the receiver. When
    /// it acquires the lock, it will the perform a blocking read on the 
    /// queue.
    ///
    /// If the received message is a new job, it will drop the lock and
    /// perform the job. If the message signals a shutdown, it will call
    /// `close` on the queue – which will switch the queue into shutdown
    /// mode, drop the lock and start again at the top.
    ///
    /// When the queue is in shutdown mode, trying to receive a message will
    /// return `None` once the queue has been exhausted. This is the signal
    /// for the thread to exit.
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

    /// Creates a new handle to the thread pool
    pub fn handle(&self) -> ThreadPoolHandle {
        ThreadPoolHandle { tx: self.worker_tx.clone() }
    }

    /// Spawns a new additional thread on the thread pool.
    ///
    /// The method expects a closure which will receive the receiver for a 
    /// standard library MPSC queue. When the thread pool is being shut down,
    /// a single `()` is sent to this queue.
    ///
    /// Additional threads are waited upon when the thread pool is terminated
    /// and there currently is no timeout for that, so make sure your thread
    /// actually listens to the shutdown signal and terminates eventually.
    pub fn spawn(
        &mut self, f: impl FnOnce(std_mpsc::Receiver<()>) + Send + 'static
    ) {
        let (tx, rx) = std_mpsc::sync_channel(1);
        self.thread_tx.push(tx);
        self.join.push(thread::spawn(|| f(rx)));
    }

    /// Terminates the thread pool.
    ///
    /// The method sends signals to all threads to initiate their own shutdown
    /// and then blocks until all threads have terminated.
    pub fn terminate(self) {
        let _ = self.worker_tx.blocking_send(ThreadPoolMessage::Shutdown);
        for tx in self.thread_tx {
            let _ = tx.send(());
        }
        for join in self.join {
            // `join` returns an error if the thread panicked. We can
            // consider it done in this case.
            let _ = join.join();
        }
    }
}


//------------ ThreadPoolHandle ----------------------------------------------

/// A handle to a thread pool, allowing to spawn jobs onto it.
///
/// The sole purpose of this type is to allow spawning jobs onto the thread
/// pool it is connected to via the [`spawn`][Self::spawn] method.
///
/// Handles can be cloned relatively cheaply.
#[derive(Clone)]
pub struct ThreadPoolHandle {
    /// The sending end of the job queue.
    tx: tokio_mpsc::Sender<ThreadPoolMessage>,
}

impl ThreadPoolHandle {
    /// Spawns a job onto the thread pool.
    ///
    /// The job is represented by the closure. As this closure will be run
    /// on a different thread, it needs to be `Send + 'static`.
    ///
    /// Returns an error if the thread pool does not accept new jobs any more.
    ///
    /// This is an async function that will only return once the job has been
    /// dipatched of.
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
/// This error means that the thread pool does not accept new jobs any more.
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

