//! The public part of the Krill RPKI server.
//!

use std::{error, fmt};
use hyper::StatusCode;
use rpki::ca::publication;
use tokio::sync::oneshot;
use crate::api::status::ErrorResponse;
use crate::commons::error::KrillError;
use super::runtime::{KrillRuntime, Errand};


//------------ KrillServer ---------------------------------------------------

/// Provides access to a [`KrillManager`] from an async runtime.
///
/// A value of this type is owned by the HTTP server and allows it to call
/// into Krill for processing requests. This can only be achieved via the
/// two methods [`run`][Self::run] and [`run_errand`][Self::run_errand]
/// which provide access to the [`KrillManager`] via a closure run on the
/// sync runtime.
///
/// This type is cheaply clonable and does not need to be kept in an arc.
pub struct KrillServer {
    manager: KrillManager,
}

impl KrillServer {
    /// Runs a sync closure which provides an immediate result.
    ///
    /// The closure `op` is run on the sync runtime. It has access to the
    /// [`KrillManager`] via its sole argument. Whatever the closure returns
    /// is what this async method resolves into.
    ///
    /// If, for whatever reason, the closure does not run to completion,
    /// an error is returned.
    pub async fn run<F, T, E>(
        &self, op: F
    ) -> Result<T, RunError>
    where
        F: FnOnce(&KrillManager) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: Into<RunError> + Send + 'static
    {
        let (tx, rx) = oneshot::channel();
        let manager = self.manager.clone();
        self.manager.runtime.spawn_blocking(move || {
            let _ = tx.send(op(&manager));
        });
        rx.await?.map_err(Into::into)
    }

    /// Runs an errand using the `KrillManager`.
    ///
    /// An errand is a multi-phase process involving a sequence of sync and
    /// async portions chained together. If a method of the [`KrillManager`]
    /// returns such an errand by returning a value that implements the
    /// [`Errand`] trait, the `run_errand` method can be used to evaluate
    /// the errand and receive its result.
    ///
    /// The closure `op` is run on the sync runtime. It has access to the
    /// [`KrillManager`] via its sole argument. The returned errand is then
    /// run on either the sync or async runtimes as needed.
    ///
    /// If, for whatever reason, the closure or returned errand do not run to
    /// completion, an error is returned.
    pub async fn run_errand<F, P, T, E>(
        &self, op: F
    ) -> Result<T, RunError>
    where
        F: FnOnce(&KrillManager) -> P + Send + 'static,
        P: Errand<Output = Result<T, E>>,
        T: Send + 'static,
        E: Into<RunError> + Send + 'static
    {
        let (tx, rx) = oneshot::channel();
        let manager = self.manager.clone();
        self.manager.runtime.spawn_blocking(move || {
            op(&manager).finish(tx);
        });
        rx.await?.map_err(Into::into)
    }
}


//------------ KrillManager --------------------------------------------------

#[derive(Clone)]
pub struct KrillManager {
    runtime: KrillRuntime,
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

