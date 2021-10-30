use std::{
    marker::PhantomData,
    sync::{Arc, RwLock, RwLockReadGuard},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum ProbeError<E> {
    WrongState,
    AwaitingNextProbe,
    CompletedUnusable,
    CallbackFailed(E),
}

/// Probe status based access to the PKCS#11 server.
///
/// To avoid blocking Krill startup due to HSM connection timeout or failure we start in a `AwaitingNextProbe` status which
/// signifies that we haven't yet verified that we can connect to the HSM or that it supports the capabilities that we
/// require.
///
/// At some point later once an initial connection has been established the PKCS#11 signer changes status to either
/// `Usable` or `Unusable` based on what was discovered about the PKCS#11 server.
#[derive(Debug)]
pub struct StatefulProbe<C, E, S> {
    status: RwLock<ProbeStatus<C, E, S>>,

    probe_interval: Duration,
}

pub enum ProbeStatus<C, E, S> {
    /// We haven't yet been able to connect to the HSM. If there was already a failed attempt to connect the timestamp
    /// of the attempt is remembered so that we can choose to space out connection attempts rather than attempt to
    /// connect every time Krill tries to use the signer.
    Probing {
        config: Arc<C>,
        last_probe_time: Option<Instant>,
        phantom: PhantomData<E>,
    },

    /// The HSM was successfully probed but found to be lacking required capabilities and is thus unusable by Krill.
    Unusable,

    /// The HSM was successfully probed and confirmed to have the required capabilities.
    ///
    /// Note that this does not mean that the HSM is currently contactable, only that we were able to contact it at
    /// least once since Krill was started. If the domain name/IP address used to connect to Krill now point to a
    /// different HSM instance the previously determined conclusion that the HSM is usable may no longer be valid.
    ///
    /// In this status we keep state concerning our relationship with the HSM.
    Usable(S),
}

impl<C, E, S> std::fmt::Debug for ProbeStatus<C, E, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Probing { .. } => write!(f, "Probing"),
            Self::Unusable => write!(f, "Unusable"),
            Self::Usable(_) => write!(f, "Usable"),
        }
    }
}

impl<C, E, S> ProbeStatus<C, E, S> {
    /// Marks now as the last probe attempt timestamp.
    ///
    /// Calling this function while not in the Probing state will result in a panic.
    pub fn mark(&mut self) -> Result<(), ProbeError<E>> {
        match self {
            #[rustfmt::skip]
            ProbeStatus::Probing { last_probe_time, .. } => {
                last_probe_time.replace(Instant::now());
                Ok(())
            }
            _ => Err(ProbeError::WrongState),
        }
    }

    pub fn config(&self) -> Result<Arc<C>, ProbeError<E>> {
        match self {
            ProbeStatus::Probing { config, .. } => Ok(config.clone()),
            _ => Err(ProbeError::WrongState),
        }
    }

    pub fn last_probe_time(&self) -> Result<Option<Instant>, ProbeError<E>> {
        match self {
            ProbeStatus::Probing { last_probe_time, .. } => Ok(last_probe_time.clone()),
            _ => Err(ProbeError::WrongState),
        }
    }

    /// Helper function to retrieve the state associated with status Usable. Only callable when in status `Usable`.
    /// Calling this function while in another state will result in a panic.
    pub fn state(&self) -> Result<&S, ProbeError<E>> {
        match self {
            ProbeStatus::Usable(state) => Ok(&state),
            _ => Err(ProbeError::WrongState),
        }
    }
}

impl<C, E, S> StatefulProbe<C, E, S> {
    /// Create a new connector to a server that hasn't been probed yet.
    pub fn new(config: Arc<C>, probe_interval: Duration) -> Self {
        let status = RwLock::new(ProbeStatus::Probing {
            config,
            last_probe_time: None,
            phantom: PhantomData,
        });
        StatefulProbe { status, probe_interval }
    }

    pub fn last_probe_time(&self) -> Result<Option<Instant>, ProbeError<E>> {
        self.status.read().unwrap().last_probe_time()
    }

    /// Get a read lock on the Usable server status, if the server is usable.
    ///
    /// Returns `Ok` with the status read lock if the server is usable, otherwise returns an `Err` because the
    /// server is unusable or we haven't yet been able to establish if it is usable or not.
    ///
    /// Will try probing again if we didn't already manage to connect to the server and the delay period between probes
    /// has elapsed.
    pub fn status<F>(&self, probe: F) -> Result<RwLockReadGuard<ProbeStatus<C, E, S>>, ProbeError<E>>
    where
        F: Fn(&ProbeStatus<C, E, S>) -> Result<S, ProbeError<E>>,
    {
        fn is_time_to_check(time_between_probes: Duration, last_probe_time: Option<Instant>) -> bool {
            match last_probe_time {
                None => true,
                Some(instant) => Instant::now().saturating_duration_since(instant) > time_between_probes,
            }
        }

        fn get_if_usable<C, E, S>(
            status: RwLockReadGuard<ProbeStatus<C, E, S>>,
            retry_interval: Duration,
        ) -> Option<Result<RwLockReadGuard<ProbeStatus<C, E, S>>, ProbeError<E>>> {
            // Check the status through the unlocked read lock
            match &*status {
                ProbeStatus::Usable(_) => {
                    // The server has been confirmed as usable, return the read-lock granting access to the current
                    // status and via it the current state of our relationship with the server.
                    Some(Ok(status))
                }

                ProbeStatus::Unusable => {
                    // The server has been confirmed as unusable, fail.
                    Some(Err(ProbeError::CompletedUnusable))
                }

                ProbeStatus::Probing { last_probe_time, .. } => {
                    // We haven't yet established whether the  server is usable or not. If we haven't yet checked or we
                    // haven't tried checking again for a while, then try contacting it again. If we can't establish
                    // whether or not the server is usable, return an error.
                    if !is_time_to_check(retry_interval, *last_probe_time) {
                        if let Some(instant) = last_probe_time {
                            let until = retry_interval.checked_sub(instant.elapsed()).unwrap(); // TODO
                            info!(
                                "Signer availability checking is cooling off: {:?}s remaining",
                                until.as_secs()
                            );
                        } else {
                            // This should be unreachable
                            info!(
                                "Signer availability checking is cooling off for {:?}s",
                                retry_interval.as_secs()
                            );
                        }
                        Some(Err(ProbeError::AwaitingNextProbe))
                    } else {
                        None
                    }
                }
            }
        }

        /// Verify if the configured server is contactable and supports the required capabilities.
        fn send_probe<C, E, F, S>(probe: &StatefulProbe<C, E, S>, probe_cb: F) -> Result<(), ProbeError<E>>
        where
            F: Fn(&ProbeStatus<C, E, S>) -> Result<S, ProbeError<E>>,
        {
            // Hold a write lock for the duration of our attempt to verify the server so that no other attempt occurs
            // at the same time. Bail out if another thread is performing a probe and has the lock. This is the same result
            // as when attempting to use the server between probe retries.
            let mut status = probe.status.try_write().map_err(|_| ProbeError::AwaitingNextProbe)?;

            // Update the timestamp of our last attempt to contact the server. This is used above to know when we have
            // waited long enough before attempting to contact the server again. This also guards against attempts to probe
            // when probing has already finished as mark() will fail in that case.
            status.mark()?;

            match (probe_cb)(&*status) {
                Ok(usable_state) => {
                    *status = ProbeStatus::Usable(usable_state);
                    Ok(())
                }
                Err(err) => {
                    if matches!(err, ProbeError::CompletedUnusable) {
                        *status = ProbeStatus::Unusable;
                    }
                    Err(err)
                }
            }
        }

        // Return the current status or attempt to set it by probing the server
        let status = self.status.read().unwrap();
        get_if_usable(status, self.probe_interval).unwrap_or_else(|| {
            send_probe(self, probe)
                .and_then(|_| Ok(self.status.read().unwrap()))
                .map_err(|err| match err {
                    ProbeError::CompletedUnusable => err,
                    _ => ProbeError::AwaitingNextProbe,
                })
        })
    }
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Debug, Default)]
    struct Config {
        hostname: String,

        port: u64,
    }

    #[derive(Copy, Clone, Debug, Default)]
    struct State {
        some_state: u8,
    }

    impl State {
        fn some_func(&self) -> u8 {
            self.some_state
        }
    }

    #[derive(Debug)]
    enum SomeError {
        SomeErrorCode,
    }

    fn probe_func(_status: &ProbeStatus<Config, SomeError, State>) -> Result<State, ProbeError<SomeError>> {
        Err(ProbeError::CompletedUnusable)
    }

    #[test]
    fn probe_should_be_permanently_unavailable_with_closure() {
        let config = Arc::new(Config::default());
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_secs(0));
        let res = conn.status(|_| Err(ProbeError::CompletedUnusable));
        match res {
            Err(ProbeError::CompletedUnusable) => {}
            other => panic!("Expected Err(ProbeError::PermanentlyUnusable) but got {:?}", other),
        }
    }

    #[test]
    fn probe_should_be_permanently_unavailable_with_fn() {
        let config = Arc::new(Config::default());
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_secs(0));
        let res = conn.status(probe_func);
        match res {
            Err(ProbeError::CompletedUnusable) => {}
            other => panic!("Expected Err(ProbeError::PermanentlyUnusable) but got {:?}", other),
        }
    }

    #[test]
    fn probe_should_be_permanently_unavailable() {
        let config = Arc::new(Config::default());
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_secs(0));
        let res = conn.status(|_| Err(ProbeError::CompletedUnusable));
        match res {
            Err(ProbeError::CompletedUnusable) => {}
            other => panic!("Expected Err(ProbeError::PermanentlyUnusable) but got {:?}", other),
        }
    }

    #[test]
    fn probe_should_be_temporarily_unavailable() {
        let config = Arc::new(Config::default());
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_secs(0));
        let res = conn.status(|_| Err(ProbeError::AwaitingNextProbe));
        match res {
            Err(ProbeError::AwaitingNextProbe) => {}
            other => panic!("Expected Err(ProbeError::AwaitingNextProbe) but got {:?}", other),
        }
    }

    #[test]
    fn probe_should_be_temporarily_unavailable_on_custom_error() {
        let config = Arc::new(Config::default());
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_secs(0));
        let res = conn.status(|_| Err(ProbeError::CallbackFailed(SomeError::SomeErrorCode)));
        match res {
            Err(ProbeError::AwaitingNextProbe) => {}
            other => panic!("Expected Err(ProbeError::AwaitingNextProbe) but got {:?}", other),
        }
    }

    #[test]
    fn last_probe_time_should_advance() -> Result<(), ProbeError<SomeError>> {
        let config = Arc::new(Config::default());

        // Probing is only done when .get() is called
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_millis(100));
        assert_eq!(None, conn.last_probe_time()?);

        // The first call to .get() should trigger a probe
        let _ = conn.status(|_| Err(ProbeError::AwaitingNextProbe));
        let t1 = conn.last_probe_time()?;
        assert!(t1.is_some());

        // A call to .get() before the next probe interval should NOT result in an updated last probe time
        std::thread::sleep(Duration::from_millis(10));
        let _ = conn.status(|_| Err(ProbeError::AwaitingNextProbe));
        let t2 = conn.last_probe_time()?;
        assert!(t2 == t1);

        // A call to .get() after the next probe interval SHOULD result in an updated last probe time
        std::thread::sleep(Duration::from_millis(200));
        let _ = conn.status(|_| Err(ProbeError::AwaitingNextProbe));
        let t3 = conn.last_probe_time()?;
        assert!(t3 > t1);

        Ok(())
    }

    #[test]
    fn probe_should_change_state_when_usable() -> Result<(), ProbeError<SomeError>> {
        let config = Arc::new(Config::default());
        let new_state = State { some_state: 1 };

        // Probing only happens when .get() is called
        let conn = StatefulProbe::<_, SomeError, State>::new(config, Duration::from_millis(0));
        let new_status = conn.status(|_| Ok(new_state))?;
        assert_eq!(1, new_status.state()?.some_state);
        assert_eq!(1, new_status.state()?.some_func());

        Ok(())
    }
}
