Event Sourcing in Krill
=======================

If you search for it you will find that there are many blog posts about how people made Event Sourcing
and CQRS work for their project. There are also many libraries, for many languages, that provide
frameworks. Some of these libraries will have you believe that their implementation is the
**right** way of doing this... but we believe that there is more than one way to happiness. So,
in Krill we have chosen to use our own local implementation. This lets us use the concepts that we
need, but it allows us the flexibility to adapt it to our specific needs, and avoids the complication
from concepts that we do not need.

Krill uses its own event sourcing library code, which is used by both the `PubServer` and `CaServer`.
The components can be found under `src/commons/eventsourcing`. We will describe the concepts and code
here, and include code (snippets). But, obviously, the real code is leading - so be sure to check it
and fix this documentation if the two should disagree!


Aggregate
---------

As said, the aggregate is a central concept in DDD that is used in combination with event sourcing
and CQRS. Officially the root entity should be called 'aggregate root', but because this a bit wordy
Krill just calls it 'Aggregate' instead. There is trait defined for this that is implemented by
`CertAuth` and `RepositoryAccess` (more on these later).

See `src/commons/eventsourcing/agg.rs` for the following code:
```
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
    /// initialise the instance. Typically this means that a specific
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

    /// Applies all events. Assumes that the list ordered, starting with the
    /// oldest event, applicable, self.version matches the oldest event, and
    /// contiguous, i.e. there are no missing events.
    fn apply_all(&mut self, events: Vec<Self::Event>) {
        for event in events {
            self.apply(event);
        }
    }

    /// Processes a command. I.e. validate the command, and return a list of
    /// events that will result in the desired new state, but do not apply
    /// these event here.
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

```
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

```/// Must be implemented for all 'StorableDetails' used in Commands.
///
/// In addition to implementing Storable so that the details can be stored
/// *and* retrieved, the details also need to be able to present a generic
/// CommandSummer for use in history.
pub trait WithStorableDetails: Storable + Send + Sync {
    fn summary(&self) -> CommandSummary;
}
```

Skipping some details now (it's in the code), this is ultimately used when we
store a command using the following struct:

```
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

```
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

```
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
```
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

```
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
charge of *almost* all changes, an in particular all *semantic* changes that users made. But,
the generation of Manifests and CRLs is offloaded to associated component `CaObjects` that
just keeps the latest Manifest and CRL. It can re-sign these because it has access to a
`KrillSigner` and it can get the public key identifier needed for signing from the `CertAuth`.

Similarly the Publication Server has now been updated to keep commands and events for semantically
important changes: add or remove a publisher. But it no longer keeps the history of all deltas
sent by publishers in its history, as this resulted in excessive history, disk usage and made
data migrations very slow in cases where we needed to change the data format.


Event Listeners
---------------

The Krill eventsourcing stack defines two different `EventListener` traits which are called
by the `AggregateStore` (see below) when an Aggregate is successfully updated. The first is
called before updates are saved, and it can fail, the second is called after all changes have
been applied, and cannot fail:

```
/// This trait defines a listener for events which is designed to receive
/// the events *before* the Aggregate is saved. Thus, they are allowed
/// to return an error in case of issues, which will then roll back the
/// intended change to an aggregate.
pub trait PreSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    fn listen(&self, agg: &A, event: &[A::Event]) -> Result<(), A::Error>;
}
```

```
/// This trait defines a listener for events which is designed to receive
/// them *after* the updated Aggregate is saved. Because the updates already
/// happened EventListeners of this type are not allowed to fail.
pub trait PostSaveEventListener<A: Aggregate>: Send + Sync + 'static {
    fn listen(&self, agg: &A, event: &A::Event);
}
```


AggregateStore
--------------

When Krill interacts with an `Aggregate`, it does so through an `AggregateStore<A: Aggregate>`.
The full code for this type can be found in `src/commons/eventsourcing/store.rs`. Here we will
stick to the highlights of how this type works!

Essentially, the `AggregateStore` provides a convenient access layer to dealing with any `Aggregate`.
Using this let's you focus on pure business logic in your aggregates. Essentially we just
need to implement the `Aggregate`, `Command` and `Event` traits and then the framework will
deal with storage concerns.

The most important function signatures (implementation omitted):

```
impl<A: Aggregate> AggregateStore<A>
where
    A::Error: From<AggregateStoreError>,

{
    /// Creates an AggregateStore using a disk based KeyValueStore 
    pub fn disk(work_dir: &PathBuf, name_space: &str) -> StoreResult<Self>;

    /// Warms up the cache, to be used after startup. Will fail if any aggregates fail to load.
    /// In that case the user may want to use the recover option to see what can be salvaged.
    pub fn warm(&self) -> StoreResult<()>;

    /// Recovers the aggregates by verifying all commands, and the corresponding events.
    /// Use this in case the state on disk is found to be inconsistent. I.e. the `warm`
    /// function failed and Krill exited.
    pub fn recover(&self) -> StoreResult<()>

    /// Adds a listener that will receive all events before they are stored.
    pub fn add_pre_save_listener<L: PreSaveEventListener<A>>(&mut self, sync_listener: Arc<L>);

    /// Adds a listener that will receive a reference to all events after they are stored.
    pub fn add_post_save_listener<L: PostSaveEventListener<A>>(&mut self, listener: Arc<L>);

    /// Adds a new aggregate instance based on the init event.
    pub fn add(&self, init: A::InitEvent) -> StoreResult<Arc<A>>;

    /// Sends a command to the appropriate aggregate, and on
    /// success: save command and events, return aggregate
    /// no-op: do not save anything, return aggregate
    /// error: save command and error, return error
    pub fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error>;

    /// Retrieve the latest aggregate for this command.
    /// Call the A::process_command function
    /// on success:
    ///   - call pre-save listeners with events
    ///   - save command and events
    ///   - call post-save listeners with events
    ///   - return aggregate
    /// on no-op (empty event list):
    ///   - do not save anything, return aggregate
    /// on error:
    ///   - save command and error, return error
    pub fn command(&self, cmd: A::Command) -> Result<Arc<A>, A::Error>;

    /// Returns true if an instance exists for the id
    pub fn has(&self, id: &Handle) -> Result<bool, AggregateStoreError>;

    // Lists all known ids.
    pub fn list(&self) -> Result<Vec<Handle>, AggregateStoreError>;

}

```






