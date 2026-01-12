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


use std::{error, fmt};
use std::sync::Arc;
use hyper::StatusCode;
use rpki::ca::publication;
use tokio::runtime;
use tokio::sync::oneshot;
use crate::commons::error::KrillError;
use crate::api::status::ErrorResponse;


//------------ KrillRuntime --------------------------------------------------

pub struct KrillRuntime(Arc<Components>);

impl KrillRuntime {
    pub async fn run<F, T, E>(
        &self, op: F
    ) -> Result<T, RunError>
    where
        F: FnOnce() -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: Into<RunError> + Send + 'static
    {
        let (tx, rx) = oneshot::channel();
        self.0.tokio.spawn_blocking(|| {
            let _ = tx.send(op());
        });
        rx.await?.map_err(Into::into)
    }

    pub async fn run_errand<F, P, T, E>(
        &self, op: F
    ) -> Result<T, RunError>
    where
        F: FnOnce() -> P + Send + 'static,
        P: Phase<Output = Result<T, E>>,
        T: Send + 'static,
        E: Into<RunError> + Send + 'static
    {
        let (tx, rx) = oneshot::channel();
        self.0.tokio.spawn_blocking(|| {
            op().finish(tx);
        });
        rx.await?.map_err(Into::into)
    }
}


//------------ ErrandRuntime -------------------------------------------------

#[derive(Clone)]
pub struct ErrandRuntime(Arc<Components>);

impl ErrandRuntime {
    fn spawn_async(&self, future: impl Future<Output = ()> + Send + 'static) {
        let _ = self.0.tokio.spawn(future);
    }

    fn spawn_blocking(&self, op: impl FnOnce() + Send + 'static) {
        let _ = self.0.tokio.spawn_blocking(op);
    }
}


//------------ Components ----------------------------------------------------

struct Components {
    /*
    /// The server configuration.
    ///
    /// This has to be an arc for now since some components keep a copy.
    config: Config,

    /// The base URI for communicating with this server.
    ///
    /// We keep it separately because the config only keeps the configured
    /// value which may be missing.
    service_uri: uri::Https,

    /// Publication server, with configured publishers
    repo_manager: RepositoryManager,

    /// The manager for all our CAs.
    ca_manager: CaManager,

    /// The task queue.
    ///
    /// This needs to remanin an arc for now since it needs to be given to
    /// aggregate listeners.
    tasks: TaskQueue,

    /// The signer.
    ///
    /// This needs to remain an arc for now because it is kept with some
    /// commands.
    signer: KrillSigner,

    /// The actor used for actions initiated by the server itself.
    system_actor: Actor,
    */

    /// The Tokio runtime to spawn tasks onto.
    ///
    /// We currently use it for both async and sync tasks (via
    /// `spawn_blocking`).
    tokio: runtime::Handle,
}


//------------ Errand --------------------------------------------------------

pub struct Errand<Cap, Fut: Future> {
    /// The capture value passed along during execution.
    capture: Cap,

    /// The initial calculation of the errand.
    value: MaybeFuture<Fut>,

    /// The Krill runtime to use and pass along.
    krill: ErrandRuntime,
}

impl<Cap, Fut: Future> Errand<Cap, Fut> {
    pub fn then<Op>(self, op: Op) -> Then<Self, Op> {
        Then {
            before: self,
            op: op
        }
    }
}

impl<Cap, Fut> Phase for Errand<Cap, Fut>
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
            FnOnce(Cap, Self::Output, ErrandRuntime)
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

impl<Before, Op> Phase for Then<Before, Op>
where
    Before: Phase,
    Op: IntoMaybeFuture<Capture = Before::Capture, Input = Before::Output>,
{
    type Capture = Op::Capture;
    type Output = Op::Output;

    fn run<Then>(self, then: Then)
    where
        Then: 
            FnOnce(Op::Capture, Self::Output, ErrandRuntime)
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
        krill: &ErrandRuntime,
    ) -> MaybeFuture<Self::Future>;
}


//------------ Phase ---------------------------------------------------------

/// A single step in running an errand.
pub trait Phase: Sized {
    type Capture: Send + 'static;
    type Output: Send + 'static;

    fn run<Then>(self, then: Then)
    where
        Then: 
            FnOnce(Self::Capture, Self::Output, ErrandRuntime)
            + Send + 'static
    ;

    fn finish(self, tx: oneshot::Sender<Self::Output>);
}


//------------ RunError ------------------------------------------------------

/// An error happened when running an operation.
//
//  This is a separate type in preparation for refactoring error handling. For
//  now, it just wraps a `KrillError`.
#[derive(Debug)]
pub struct RunError(KrillError);

impl RunError {
    pub fn status(&self) -> StatusCode {
        self.0.status()
    }

    pub fn to_error_response(&self) -> ErrorResponse {
        self.0.to_error_response()
    }

    pub fn to_rfc8181_error_code(&self) -> publication::ReportErrorCode {
        self.0.to_rfc8181_error_code()
    }
}

impl From<KrillError> for RunError {
    fn from(src: KrillError) -> Self {
        Self(src)
    }
}

impl From<oneshot::error::RecvError> for RunError {
    fn from(_: oneshot::error::RecvError) -> Self {
        Self(KrillError::internal("operation dropped"))
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl error::Error for RunError { }
