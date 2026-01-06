//! Integration of an async runtime.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use pin_project_lite::pin_project;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;


//------------ Handle --------------------------------------------------------

#[derive(Clone)]
pub struct Handle {
    tokio: tokio::runtime::Handle,
}

impl Handle {
    pub fn current() -> Self {
        Handle {
            tokio: tokio::runtime::Handle::current()
        }
    }

    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tokio.spawn(future)
    }

    pub fn exec<F, Fut>(&self, op: F) -> Errand<Fut::Output>
    where
        F: FnOnce() -> Fut,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let future = op();
        self.tokio.spawn(async move {
            let _ = tx.send(future.await);
        });
        Errand::fut(rx, self.clone())
    }

    pub fn ready<T: Send + 'static>(&self, t: T) -> Errand<T> {
        Errand::ready(t, self.clone())
    }

    pub fn ready_with<F, T, E>(&self, op: F) -> Errand<Result<T, E>>
    where
        F: FnOnce() -> Result<T, E>,
        T: Send + 'static,
        E: Send + 'static,
    {
        self.ready(op())
    }
}

//------------ Errand --------------------------------------------------------

pin_project! {
    pub struct Errand<T> {
        #[pin]
        inner: ErrandInner<T>,
        runtime: Handle,
    }
}

pin_project! {
    #[project = ErrandProj]
    enum ErrandInner<T> {
        Ready {
            res: Option<T>
        },
        Fut {
            #[pin] rx: oneshot::Receiver<T>,
        }
    }
}

impl<T> Errand<T> {
    fn ready(res: T, runtime: Handle) -> Self {
        Self {
            inner: ErrandInner::Ready { res: Some(res) },
            runtime
        }
    }

    fn none(runtime: Handle) -> Self {
        Self {
            inner: ErrandInner::Ready { res: None },
            runtime
        }
    }

    fn fut(rx: oneshot::Receiver<T>, runtime: Handle) -> Self {
        Self { inner: ErrandInner::Fut { rx }, runtime }
    }

    pub fn map<F, U>(self, op: F) -> Errand<U>
    where
        F: FnOnce(T) -> U + Send + 'static,
        T: Send + 'static,
        U: Send + 'static,
    {
        match self.inner {
            ErrandInner::Ready { res } => {
                Errand {
                    inner: ErrandInner::Ready { res: res.map(op) },
                    runtime: self.runtime,
                }
            }
            ErrandInner::Fut { rx } => {
                let (next_tx, next_rx) = oneshot::channel();
                let runtime = self.runtime.clone();
                self.runtime.spawn(async move {
                    if let Ok(res) = rx.await {
                        let res = runtime.tokio.spawn_blocking(|| {
                            op(res)
                        }).await;
                        if let Ok(res) = res {
                            let _ = next_tx.send(res);
                        }
                    }
                });
                Errand::fut(next_rx, self.runtime)
            }
        }
    }

    pub fn map_async<F, Fut>(self, op: F) -> Errand<Fut::Output>
    where
        T: Send + 'static,
        F: FnOnce(T) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        match self.inner {
            ErrandInner::Ready { res } => {
                if let Some(res) = res {
                    self.runtime.exec(move || op(res))
                }
                else {
                    Errand::none(self.runtime)
                }
            }
            ErrandInner::Fut { rx } => {
                let (next_tx, next_rx) = oneshot::channel();
                self.runtime.spawn(async move {
                    if let Ok(res) = rx.await {
                        let _ = next_tx.send(op(res).await);
                    }
                });
                Errand::fut(next_rx, self.runtime)
            }
        }
    }

    pub fn map_errand<F, U>(self, op: F) -> Errand<U>
    where
        F: FnOnce(T) -> Errand<U> + Send + 'static,
        T: Send + 'static,
        U: Send + 'static,
    {
        match self.inner {
            ErrandInner::Ready { res } => {
                match res {
                    Some(res) => op(res),
                    None => Errand::none(self.runtime),
                }
            },
            ErrandInner::Fut { rx } => {
                let (next_tx, next_rx) = oneshot::channel();
                self.runtime.spawn(async move {
                    if let Ok(res) = rx.await {
                        if let Ok(res) = op(res).await {
                             let _ = next_tx.send(res);
                        }
                    }
                });
                Errand::fut(next_rx, self.runtime)
            }
        }
    }

    pub fn block(self) -> Result<T, RecvError> {
        match self.inner {
            ErrandInner::Ready { mut res } => {
                Ok(res.take().expect("polled ready future"))
            }
            ErrandInner::Fut { rx, .. } => {
                rx.blocking_recv()
            }
        }
    }
}

impl<T> Future for Errand<T> {
    type Output = Result<T, RecvError>;

    fn poll(
        self: Pin<&mut Self>, cx: &mut Context<'_>
    ) -> Poll<Self::Output> {
        match self.project().inner.project() {
            ErrandProj::Ready { res } => {
                Poll::Ready(Ok(res.take().expect("polled ready future")))
            }
            ErrandProj::Fut { rx, .. } => {
                rx.poll(cx)
            }
        }
    }
}


//------------ Error ---------------------------------------------------------

pub type RecvError = oneshot::error::RecvError;

