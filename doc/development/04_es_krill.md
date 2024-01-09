Event Sourcing in Krill
=======================

If you search for it you will find that there are many blog posts about how people made Event Sourcing
and CQRS work for their project. There are also many libraries, for many languages, that provide
frameworks. Some of these libraries will have you believe that their implementation is the
**right** way of doing this... but we believe that there is more than one way to happiness. So,
in Krill we have chosen to use our own local implementation. This lets us use the concepts that we
need, but it allows us the flexibility to adapt it to our specific needs, and avoids the complication
from concepts that we do not need.

Krill uses its own event sourcing library code which can be found under [`src/commons/eventsourcing`](../../src/commons/eventsourcing).
We will describe the concepts and code here, and include code (snippets). But, obviously, the real
code is leading - so be sure to check it and fix this documentation if the two should disagree!


KeyValueStore and JSON
----------------------

Before we delve in to the Krill eventsourcing code, we should talk a bit about storage.
Krill stores all values in a `KeyValueStore`.

This is implemented in the `kvx` library:
https://github.com/nlnetlabs/kvx

There is a PR to port the `kvx` implementation back into the core Krill code (Krill is
the only user after all), and in the process make it support async. To support this,
the code was updated to rely on an enum rather than a trait for `KeyValueStore`. This
PR can be found here:
https://github.com/NLnetLabs/krill/pull/1152

Currently, only disk and memory (for testing) implementations are supported. Database
options may be added in future, but note that that will require async support. The `kvx`
library claims to support postgresql but it can't be used in Krill because while the
library is sync, it uses a runtime under the hood for the database connection and this
conflicts with Krill because it already uses hyper and tokio.

Opt-in locking on disk relies on `fd-lock` in `kvx` and plain `rustix` in the PR (only
supports UNIX). This locking is used by Krill to ensure that updates to CAs, the Publication
Server Access (which Publishers have access) and Publication Server Content are always
applied sequentially.

In principle, since the locking leverages `flock` which is supposedly NFS safe, this
should mean that as of 0.14.4 it is safe to run multiple active Krill instances using
the same shared NFS data directory. But.. this needs proper testing!

Aggregate
---------

As said, the aggregate is a central concept in DDD that is used in combination with event sourcing
and CQRS. Officially the root entity should be called 'aggregate root', but because this a bit wordy
Krill just calls it 'Aggregate' instead. There is trait defined for this that is implemented by
`CertAuth` and `RepositoryAccess` (more on these later).

See `src/commons/eventsourcing/agg.rs` for the following code:
```rust
/// This trait defines an Aggregate for use with the event sourcing framework.
///
/// An aggregate is term coming from DDD (Domain Driven Design) and is used to
/// describe an abstraction where a cluster of structs (the aggregate) provides
/// a 'bounded context' for functionality that is exposed only by a single top-level
/// struct: the aggregate root. Here we name this aggregate root simply 'Aggregate'
/// for brevity.
///
/// The aggregate root is responsible for guarding its own consistency. In the
/// context of the event sourcing framework this means that it can be sent a command,
/// through the [`process_command`] method. A command represents an intent to
/// achieve something sent by the used of the aggregate. The Aggregate will then take
/// this intent and decide whether it can be executed. If successful a number of
/// 'events' are returned that contain state changes to the aggregate. These events
/// still need to be applied to become persisted.
pub trait Aggregate: Storable + Send + Sync + 'static {
    type Command: Command<StorableDetails = Self::StorableCommandDetails>;
    type StorableCommandDetails: WithStorableDetails;
    type Event: Event;
    type InitEvent: Event;
    type Error: std::error::Error + Send + Sync;

    /// Creates a new instance. Expects an event with data needed to
    /// initialize the instance. Typically this means that a specific
    /// 'create' event is passed, with all the needed data, or just an empty
    /// marker if no data is needed. Implementations must return an error in
    /// case the instance cannot be created.
    fn init(event: Self::InitEvent) -> Result<Self, Self::Error>;

    /// Returns the current version of the aggregate.
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
    /// - the events are all applicable to this aggregate
    /// - the version of the aggregate matches that of the first (oldest) event
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
```

As we will see further down, when we get to describe the `AggregateStore<A: Aggregate>`
which ties of all this together, this allows us to focus on business logic in our aggregates.

Just make sure that you define your `Command` and `Event` type, and implement the `process_command`
method. The result should be either an error, or `Vec<Event>`. In case the command is a no-op,
return an empty `Vec`. Furthermore implement `apply` and let your aggregate state be updated
with event data.



Commands and StorableDetails
----------------------------

As can be seen in the trait above, Krill expects that an `Aggregate` defines a
type that it will use for commands. The command MUST implement the `Command` trait
which is defined in `src/commons/eventsourcing/cmd.rs`:

```rust
//// Commands are used to send an intent to change an aggregate.
///
/// Think of this as the data container for your update API, plus some
/// meta-data to ensure that the command is sent to the right instance of an
/// Aggregate, and that concurrency issues are handled.
pub trait Command: fmt::Display + Send + Sync {
    /// Identify the type of storable component for this command. Commands
    /// may contain short-lived things (e.g. an Arc<Signer>) or even secrets
    /// which should not be persisted.
    type StorableDetails: WithStorableDetails;

    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn handle(&self) -> &Handle;

    /// The version of the aggregate that this command updates. If this
    /// command should update whatever the latest version happens to be, then
    /// use None here.
    fn version(&self) -> Option<u64>;

    /// The actor who sent the command. There is no default so as to avoid
    /// accidentally attributing a command by a user instead as if it were an
    /// internal command by Krill itself.
    fn actor(&self) -> &str;

    /// Get the storable information for this command
    fn store(&self) -> Self::StorableDetails;
}
```

We define the `WithStorableDetails` trait in the same file. As mentioned in the
code comments above, we use **this** when we save commands to the audit log, because
the actual command may contain a secret - or more likely an ephemeral thing that
cannot and should not be saved - such as a `KrillSigner` which an Aggregate can
use as part of the executing the command.

```rust
/// Must be implemented for all 'StorableDetails' used in Commands.
///
/// In addition to implementing Storable so that the details can be stored
/// *and* retrieved, the details also need to be able to present a generic
/// CommandSummary for use in history.
pub trait WithStorableDetails: Storable + Send + Sync {
    fn summary(&self) -> CommandSummary;
}
```

Skipping some details now (it's in the code), this is ultimately used when we
store a command using the following struct:

```rust
/// A description of a command that was processed, and the events / or error
/// that followed. Commands that turn out to be no-ops (no events, no errors)
/// should not be stored.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredCommand<S: WithStorableDetails> {
    actor: String,
    time: Time,
    handle: Handle,
    version: u64,  // version of aggregate this was applied to (successful or not)
    sequence: u64, // command sequence (i.e. also incremented for failed commands)
    #[serde(deserialize_with = "S::deserialize")]
    details: S,
    effect: StoredEffect,
}
```

Finally `StoredEffect` here tells us whether the command was successful, or not:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum StoredEffect {
    Error { msg: String },
    Success { events: Vec<u64> },
}
```


Events
------

As mentioned above an `Aggregate` must specify which type of event it uses. Events
MUST implement the `Event` trait (`src/commons/eventsourcing/evt.rs`):

```rust
pub trait Event: fmt::Display + Eq + PartialEq + Send + Sync + Storable + 'static {
    /// Identifies the aggregate, useful when storing and retrieving the event.
    fn handle(&self) -> &Handle;

    /// The version of the aggregate that this event updates. An aggregate that
    /// is currently at version x, will get version x + 1, when the event for
    /// version x is applied.
    fn version(&self) -> u64;
}
```

Events are stored using the `StoredEvent` struct:
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredEvent<E: fmt::Display + Eq + PartialEq + Storable + 'static> {
    id: Handle,
    version: u64,
    #[serde(deserialize_with = "E::deserialize")]
    details: E,
}
```

So, note that `StoredEvent` is not generic over `Event`. But, in practice the defined
`Event` for our two main aggregates are of a type of `StoredEvent`:

```rust
pub type CaEvt = StoredEvent<CaEvtDet>;
```

> IMPORTANT: We can change the internal implementation of an `Aggregate` pretty freely. As
> long as we keep backwards compatibility with regards to past events, we can just delete the
> snapshots and rebuild the current state based on past events. Well, if you look closely at
> the migration code in `src/upgrades/v0_9_0' you will find that it is of course possible
> to add code to parse all past commands and/or events, and reformat them. But, it's a major
> amount of work to do so, so it's better to avoid this if we can. Also note, that we
> can never add new information to past events. They already happened, so we have to deal
> with that.

Hybrid Model
------------

So, time for a confession... and a digression that will make sense when we talk about event
listeners, and things triggered by events.

Before Krill version 0.9 **ALL** CA and Publication Server functions were implemented in
aggregates and used event sourcing. However, as you may know CAs in the RPKI have to
re-publish CRLs and Manifests very, very often. Even when there are no changes to ROAs
these objects must be refreshed before they go stale. By default Krill re-publishes every
16 hours.

This resulted in an enormous amount of commands and events to be generated for CAs, for
a change that is done automatically - and which does not reflect any semantic change
for a CA. Keeping all this stuff in the history led to excessive disk usage, and an audit
trail that is hard to follow. It also has a serious impact on rebuilding state based on
events from scratch i.e. without using snapshots.

Therefore we decided to implement a hybrid model in Krill. The Krill `CertAuth` is still in
charge of *almost* all changes, and in particular all *semantic* changes that users made. But,
the generation of Manifests and CRLs is offloaded to associated component `CaObjects` that
just keeps the latest Manifest and CRL. It can re-sign these because it has access to a
`KrillSigner` and it can get the public key identifier needed for signing from the `CertAuth`.

This is relevant here, because under the hood we use a `PreSaveEventListener` to ensure
that a new Manifest and CRL are written when there is a change in ROAs or issued certificates,
observed in events.


Event Listeners
---------------

The Krill eventsourcing stack defines two different `EventListener` traits which are called
by the `AggregateStore` (see below) when an Aggregate is successfully updated. The first is
called before updates are saved, and it can fail, the second is called after all changes have
been applied, and cannot fail.

```rust
/// This trait defines a listener for events which is designed to receive
/// the events *before* the Aggregate is saved. Thus, they are allowed
/// to return an error in case of issues, which will then roll back the
/// intended change to an aggregate.
pub trait PreSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    fn listen(&self, agg: &A, event: &[A::Event]) -> Result<(), A::Error>;
}
```

```rust
/// This trait defines a listener for events which is designed to receive
/// them *after* the updated Aggregate is saved. Because the updates already
/// happened EventListeners of this type are not allowed to fail.
pub trait PostSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    fn listen(&self, agg: &A, event: &A::Event);
}
```

In a nutshell, we use the event listeners for two things:
- Trigger that the `CaObjects` for a CA gets an updated Manifest and CRL (pre-save).
- Trigger that follow-up tasks are put on the `Scheduler`, based on events.

As discussed in issue: https://github.com/NLnetLabs/krill/issues/1182
it would be best to remove the `PreSaveEventListener` trait and do everything
through (idempotent) triggered tasks on the queue in the `Scheduler`. Note
that Krill will add any missing tasks on this queue at startup, so this means
that even if an aggregate, like a CA, is saved and then the follow-up task
scheduling fails because of an outage, then the task will simply be re-added
when Krill restarts.

AggregateStore
--------------

When Krill interacts with an `Aggregate`, it does so through an `AggregateStore<A: Aggregate>`.
The full code for this type can be found in `src/commons/eventsourcing/store.rs`. Here we will
stick to the highlights of how this type works!

Essentially, the `AggregateStore` provides a convenient access layer to dealing with any `Aggregate`.
Using this let's you focus on pure business logic in your aggregates. Essentially we just
need to implement the `Aggregate`, `Command` and `Event` traits and then the framework will
deal with storage concerns.

The most important pub function signatures (implementation omitted):

```rust
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,

{
    /// Creates an AggregateStore using a disk based KeyValueStore 
    pub fn disk(work_dir: &PathBuf, name_space: &str) -> StoreResult<Self> { ... }

    /// Warms up the cache, to be used after startup. Will fail if any aggregates fail to load.
    pub fn warm(&self) -> StoreResult<()> { ... }

    /// Adds a listener that will receive all events before they are stored.
    pub fn add_pre_save_listener<L: PreSaveEventListener<A>>(&mut self, sync_listener: Arc<L>) { ... }

    /// Adds a listener that will receive a reference to all events after they are stored.
    pub fn add_post_save_listener<L: PostSaveEventListener<A>>(&mut self, listener: Arc<L>) { ... }

    /// Adds a new aggregate instance based on the init event.
    pub fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>> { ... }

    /// Send a command to the latest aggregate referenced by the handle in the command.
    ///
    /// This will:
    /// - Wait for a lock for the latest aggregate for this command.
    /// - Call the A::process_command function
    /// on success:
    ///   - call pre-save listeners with events
    ///   - save command and events
    ///   - call post-save listeners with events
    ///   - return aggregate
    /// on no-op (empty event list):
    ///   - do not save anything, return aggregate
    /// on error:
    ///   - save command and error, return error
    pub fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error> { ... }

    /// Returns true if an instance exists for the id
    pub fn has(&self, id: &Handle) -> Result<bool, AggregateStoreError> { ... }

    // Lists all known ids.
    pub fn list(&self) -> Result<Vec<Handle>, AggregateStoreError> { ... }
}
```

As said, users of `AggregateStore` do not need to worry about the actual storage,
as this is done inside of it using private functions. Still, it's good to talk a bit
more about how this works. And looking at how the struct if built up will help to
explain its inner workings:

```rust
pub struct AggregateStore<A: Aggregate> {
    kv: KeyValueStore,
    cache: RwLock<HashMap<Handle, Arc<A>>>,
    history_cache: Option<Mutex<HashMap<MyHandle, Vec<CommandHistoryRecord>>>>,
    pre_save_listeners: Vec<Arc<dyn PreSaveEventListener<A>>>,
    post_save_listeners: Vec<Arc<dyn PostSaveEventListener<A>>>,
}
```

- Applying changes

ALL changes to Aggregates, like `CertAuth` are done through the `command` function.
This function waits for a lock (using flock mentioned earlier) to ensure that
all changes to the Aggregate are applied sequentially.

First the `Aggregate` is retrieved from the in memory cache if present. If there
is no cached instance then latest snapshot is retrieved from storage instead. If
there is also no snapshot, then the INIT command (i.e. with version 0) is retrieved
and applied instead. Then the key value store is queried for follow-up `StoredCommand`
values (for the version of the `Aggregate`) which are then applied. Note that
this would mean, in a possible cluster set up that guarantees locking, that even
if a cluster node is behind the other, it will simply find the missing updates.

Once the latest `Aggregate` has been retrieved, the `Command` is sent to it. Note
that this `Command` is not a `StoredCommand`. `Command` contains the intent for a change,
while `StoredCommand` contains the result of such a change. The `Aggregate` is responsible
for verifying the command and it can return with: an error, no effect, or a vec
of change events.

If a command has no effect, i.e. there is no error and no change, then it is
simply forgotten.

If a command has an effect then a `StoredCommand` is created that contains a
storable representation of the command (e.g. certain values in a command, like
an `Arc<Signer>`, or `Arc<Config>` are not included) and either the error or
a Vec of Events. This `StoredCommand` gets a unique key name based on the
version of the `Aggregate` that it affects.

If there should be an existing key-value pair for this `StoredCommand`, then
this indicates that the locking mechanism failed somehow. This should not happen,
but if it did, then the command is NOT saved. Instead Krill exits with an error
message.

But if all is well (as expected), then the command with events is applied
to the aggregate. Note that this just updates its version in case of a command
that resulted in an error. The in-memory cached aggregate is updated to
help performance when retrieving it later. Then the command is saved.

- Retrieving

When retrieving an `Aggregate` for read access Krill actually follows
the same code path that is used for applying a `Command`, except that in
this case the underlying function that takes care of locking and retrieving
the latest Aggregate is called with `None` instead of `Some(command)`, so
it simply returns without trying to apply any changes. This ensures however,
that the same locking rules are observed in both cases and allows us to
avoid code duplication (thus increasing the loci for bugs).

- Snapshots

Note that we do not update the full snapshot on every change because this
could create a performance issue in cases where aggregates are big (e.g. a
CA with many children or objects) and serialization takes a long time. Instead,
updating the snapshots is done daily through a different code path from the `Scheduler`.
See `Task::UpdateSnapshots`. This code, again, actually uses the same underlying
function as above to retrieve the snapshot, this time setting the `save_snapshot`
parameter to true to ensure that the snapshot is saved.
