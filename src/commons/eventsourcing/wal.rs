use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

use rpki::ca::idexchange::MyHandle;

use super::{Command, Event, KeyValueError, KeyValueStore, Storable, WithStorableDetails};

//------------ WalSupport ----------------------------------------------------

/// Implement this trait to get write-ahead logging support for a type.
///
/// We achieve write-ahead logging support by insisting that implementing
/// types define the following:
///
/// - commands
///
/// Commands are used to send an intent to change the state. However, rather
/// than changing the state, they return a result which can either be an
/// error or a list of 'events'.
///
/// - events
///
/// Events contain the data that can be applied to a type to change its
/// state. We do this as a separate step, because this will allow us to
/// replay events - from write-ahead logs - to get a stored snapshot to
/// a current state.
///
/// The following caveats apply to this:
///   -- Events MUST NOT cause side-effects
///   -- Events MUST NOT return errors when applied
///   -- All state changes MUST use events
///
/// - errors
///
/// So that we can have type specific errors.
///
/// This is similar to how the [`Aggregate`] trait works, and in fact
/// we re-use some its definitions here - such as [`Event`] and [`Command`].
///
/// But, there is a key difference which is that in this case there are
/// no guarantees that all past events are kept - or rather they are very
/// likely NOT kept. And we have no "init" event.
///
/// While there are similar concepts being used, the concerns here are
/// somewhat different.. we use this type to achieve atomicity and durability
/// by way of the [`WalStore`] defined below, but we can keep things a bit
/// simpler here compared to the fully event-sourced [`Aggregate`] types.
pub trait WalSupport: Storable + Send + Sync + 'static {
    type Command: Command<StorableDetails = Self::StorableCommandDetails>;
    type StorableCommandDetails: WithStorableDetails;
    type Event: Event;
    type Error: std::error::Error + Send + Sync;

    /// Returns the current version.
    fn version(&self) -> u64;

    /// Applies the event to this. This MUST not result in any errors, and
    /// this MUST be side-effect free. Applying the event just updates the
    /// internal data of the aggregate.
    ///
    /// Note the event is moved. This is done because we want to avoid
    /// doing additional allocations where we can.
    fn apply(&mut self, event: Self::Event);

    /// Applies all events. Assumes that:
    /// - the list is contiguous (nothing missing) and ordered from old to new
    /// - the events are all applicable to this
    /// - the version matches that of the first (oldest) event
    fn apply_all(&mut self, events: Vec<Self::Event>) {
        for event in events {
            self.apply(event);
        }
    }

    /// Processes a command. I.e. validate the command, and return a list of
    /// events that will result in the desired new state, but do not apply
    /// these events here.
    ///
    /// The command is moved, because we want to enable moving its data
    /// without reallocating.
    fn process_command(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error>;
}

//------------ WalStore ------------------------------------------------------

/// This type is responsible for loading / saving and updating [`WalSupport`]
/// capable types.
///
/// This is similar to how [`AggregateStore`] is used to manage [`Aggregate`]
/// types. However, there are some important differences:
/// - Commands and events for a change are saved as a single file.
/// - Old commands and events are no longer relevant and will be removed.
///   (we may want to support archiving those in future).
/// - We do not have any listeners in this case.
/// - We cannot replay [`WriteAheadSupport`] types from just events, we
///   *always* need to start with an existing snapshot.
pub struct WalStore<T: WalSupport> {
    kv: KeyValueStore,
    cache: RwLock<HashMap<MyHandle, Arc<T>>>,
}

impl<T: WalSupport> WalStore<T> {
    pub fn disk(work_dir: &Path, name_space: &str) -> WalStoreResult<Self> {
        let mut path = work_dir.to_path_buf();
        path.push(name_space);

        let kv = KeyValueStore::disk(work_dir, name_space)?;
        let cache = RwLock::new(HashMap::new());

        Ok(WalStore { kv, cache })
    }
}

//------------ WalStoreResult-------------------------------------------------

pub type WalStoreResult<T> = Result<T, WalStoreError>;

//------------ WalStoreError -------------------------------------------------

/// This type defines possible Errors for the AggregateStore
#[derive(Debug)]
pub enum WalStoreError {
    KeyStoreError(KeyValueError),
}

impl From<KeyValueError> for WalStoreError {
    fn from(e: KeyValueError) -> Self {
        WalStoreError::KeyStoreError(e)
    }
}
