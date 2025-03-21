//! Event sourcing support for Krill.
//!
//! This module implements an event sourcing framework for use specifically
//! with Krill.
//!
//! # Event Sourcing Overview
//! 
//! ## The Audit is the Truth
//! 
//! Event sourcing is a technique based on the concept that the current state
//! of an entity is based on a full record of past events – which can be
//! replayed – rather than saving and loading the state using something like
//! object-relational mapping or serialization.
//! 
//! A commonly used example to explain this concept is bookkeeping. In
//! bookkeeping one tracks all financial transactions, like money coming in
//! and going out of an account. The current state of an account is determined
//! by the culmination of all these changes over time. Using this approach,
//! and assuming that no one altered the historical records, we can be 100%
//! certain that the current state reflects reality. Conveniently, we also
//! have a full audit trail which can be shown.
//! 
//! 
//! ## CQRS and Domain Driven Design
//! 
//! Event sourcing is often combined with CQRS: Command Query Responsibility
//! Segregation. The idea here is that there is a separation between intended
//! changes (commands) sent to your entity, the internal state of the entity,
//! and its external representation.
//! 
//! Separating these concerns we can also borrow heavily from
//! ["Domain Driven Design"](https://en.wikipedia.org/wiki/Domain-driven_design). In DDD structures are organized into so-called “aggregates”
//! of related structures. At their root they are joined by an
//! “aggregate root”.
//! 
//!
//! ## Commands, Events and Data
//! 
//! This separation means that the aggregate is a bit like a black box to the
//! outside world, but in a positive sense. Users of the code just need to
//! know what messages of intent – commands – they can send to it. This
//! interface, like an API, should be fairly stable.
//! 
//! The first thing to do when a command is sent is that an aggregate is
//! retrieved from storage, so that it can receive a command. The state of
//! the aggregate is the result of all past events – but, because this can
//! get slow, aggregate snapshots are often used for efficiency. If a
//! snapshot does not include the latest events, then they are simply
//! re-applied to it.
//! 
//! When an aggregate receives a command it can see if a change can be
//! applied. It is fully in charge of its own consistency. If it isn't then
//! the aggregate root is usually at the wrong level. The result of the
//! command can either be an error – the command is rejected – or a number
//! of events representing the state changes are applied to the aggregate.
//! 
//! When events are applied they are also saved, so that they can be replayed
//! later. Furthermore, implementations often use message queues where events
//! are posted as well. This allows other components in the code to be
//! triggered by changes in an aggregate.
//! 
//! In its purest form, these messages can then be used to (re-) generate
//! one or more data representations that users can *query*. E.g., you could
//! populate data tables in a SQL database. However, we are currently not
//! doing this.
//! 
//! This combination of techniques has been championed by various people,
//! most notably Greg Young and Martin Fowler.
//!
//!
//! # Event Sourcing in Krill
//! 
//! If you search for it you will find that there are many blog posts about
//! how people made event sourcing and CQRS work for their project. There are
//! also many libraries, for many languages, that provide frameworks. Some of
//! these libraries will have you believe that their implementation is the
//! **right** way of doing this – but we believe that there is more than one
//! way to happiness. So, in Krill we have chosen to use our own local
//! implementation. This lets us use the concepts that we need, but it allows
//! us the flexibility to adapt it to our specific needs, and avoids the
//! complication from concepts that we do not need.
//! 
//! This module is Krill’s own event sourcing library code. In the following,
//! we will describe the concepts and code and include code (snippets).
//!
//! For an example use of the framework, see the `test` sub-module of this
//! module.
//! 
//! 
//! ## `KeyValueStore` and JSON
//!
//! Before we delve in to the Krill event sourcing code, we should talk a bit
//! about storage. Krill stores all values in a key-value store. This is
//! implemented in the [`commons::storage`][crate::commons::storage]
//! module.
//! 
//! The store is agnostic of specific storage backends. Currently, only disk
//! and memory (for testing) implementations are supported. Database
//! options will be added in future.
//! 
//! Opt-in locking on disk relies on the `fd-lock` crate This locking is used
//! by Krill to ensure that updates to CAs, the publication server access
//! and publication server content are always applied sequentially.
//! 
//! 
//! ## Aggregate
//! 
//! As said, the aggregate is a central concept in DDD that is used in
//! combination with event sourcing and CQRS. Officially the root entity
//! should be called “aggregate root,” but because this a bit wordy Krill
//! just calls it 'Aggregate' instead. The trait [`Aggregate`] is defined for
//! this that is implemented by, for instance,
//! [`CertAuth`][crate::ca::CertAuth] and
//! [`RepositoryAccess`][crate::pubd::RepositoryAccess]. 
//! 
//! As we will see further down, when we get to describe the
//! [`AggregateStore<A>`] which ties all of this together. This allows us to
//! focus on business logic in our aggregates.
//! 
//! For each aggregate, you need to your command and Event types, and
//! implement the [`Aggregate::process_command`] method that processes a
//! command. The result should be either an error, or `Vec<Event>`. In case
//! the command is a no-op, return an empty `Vec`. Furthermore implement
//! [`Aggregate::apply`] and let your aggregate state be updated with event
//! data.
//! 
//! 
//! ## Commands and Storable Details
//! 
//! As can be seen in the trait declaration, Krill expects that an
//! [`Aggregate`] defines a type that it will use for commands. The command
//! *must* implement the [`Command`] trait.
//! 
//! When storing a command in the audit log, we may want to remove secret
//! data or, more likely, ephemeral things that cannot and should not be
//! saved. The trait [`WithStorableDetails`] takes care of producing a
//! command summary that can be stored. This summary is serialized into
//! a [`StoredCommand`] which contains some accounting information as well
//! as the command summary.
//!
//! It also contains the [`StoredEffect`], which tells us whether the
//! command was successful or not with more details for each case.
//! 
//! 
//! ## Events
//! 
//! As mentioned above an [`Aggregate`] must specify which type of event it
//! uses. Events must implement the [`Event`] trait. They are stored in
//! a [`StoredCommand`] structure.
//! 
//! > **Important:** We can change the internal implementation of an
//! > [`Aggregate`] pretty freely. As long as we keep backwards compatibility
//! > with regards to past events, we can just delete the snapshots and
//! > rebuild the current state based on past events. It is of course possible
//! > to add code to parse all > past commands and events, and reformat them.
//! > But, it's a major amount of work to do so, so it's better to avoid this
//! > if we can. Also note, that we can never add new information to past
//! > events. They already happened, so we have to deal with that.
//! 
//!
//! ## Hybrid Model
//! 
//! Before Krill version 0.9 *all* CA and Publication Server functions were
//! implemented in aggregates and used event sourcing. However, CAs in the
//! RPKI have to re-publish CRLs and Manifests very often. Even when
//! there are no changes to ROAs these objects must be refreshed before they
//! go stale. By default Krill re-publishes every! 16 hours.
//! 
//! This resulted in an enormous amount of commands and events to be
//! generated for CAs, for a change that is done automatically – and which
//! does not reflect any semantic change for a CA. Keeping all this stuff in
//! the history led to excessive disk usage, and an audit trail that is hard
//! to follow. It also has a serious impact on rebuilding state based on
//! events from scratch, i.e., without using snapshots.
//! 
//! Therefore we decided to implement a hybrid model in Krill. The Krill
//! [`CertAuth`][crate::ca::CertAuth] is still in charge of *almost*
//! all changes, and in particular all *semantic* changes that users made.
//! But, the generation of Manifests and CRLs is offloaded to an associated
//! component [`CaObjects`][crate::ca::publishing::CaObjects] that just keeps
//! the latest Manifest and CRL. It can re-sign these because it has access
//! to a [`KrillSigner`][crate::commons::crypto::KrillSigner] and it can get
//! the public key identifier needed for signing from the `CertAuth`.
//! 
//! This is relevant here, because under the hood we use a
//! [`PreSaveEventListener`] to ensure that a new Manifest and CRL are
//! written when there is a change in ROAs or issued certificates, observed
//! in events.
//! 
//! 
//! ## Event Listeners
//! 
//! The Krill event sourcing stack defines two different event listener
//! traits which are called by the [`AggregateStore`] when an aggregate is
//! successfully updated. The first, [`PreSaveEventListener`] is called
//! before updates are saved, and it can fail, the second,
//! [`PostSaveEventListener`] is called after all changes have been applied,
//! and thus cannot fail.
//! 
//! In a nutshell, we use the event listeners for two things:
//!
//! * a pre-save trigger that the
//!   [`CaObjects`][crate::ca::publishing::CaObjects]
//!   for a CA gets an updated Manifest and CRL, and
//! * triggers that follow-up tasks are put on the scheduler, based on events.
//! 
//! As discussed in issue
//! [1182](https://github.com/NLnetLabs/krill/issues/1182), it would be best
//! to remove the `PreSaveEventListener` trait and do everything through
//! (idempotent) triggered tasks on the queue in the scheduler. Note that
//! Krill will add any missing tasks on this queue at startup, so this means
//! that even if an aggregate, like a CA, is saved and then the follow-up
//! task scheduling fails because of an outage, the task will simply be
//! re-added when Krill restarts.
//!
//!
//! ## Aggregate Store
//! 
//! When Krill interacts with an aggregate, it does so through an
//! [`AggregateStore<A>`]. The aggregate store provides a convenient access
//! layer to dealing with any aggregate. Using this lets you focus on pure
//! business logic in your aggregates. Essentially, we just need to implement
//! the [`Aggregate`], [`Command`] and [`Event`] traits and then the
//! framework will deal with storage concerns.
//! 
//! The most important pub function signatures (implementation omitted):
//! 
//! ### Applying changes
//! 
//! All changes to aggregates are done through the
//! [`command`][AggregateStore::command] function. This function waits for a
//! lock to ensure that all changes to the Aggregate are applied
//! sequentially.
//! 
//! First the aggregate is retrieved from the in memory cache if present. If
//! there is no cached instance then latest snapshot is retrieved from
//! storage instead. If there is also no snapshot, then the init command
//! (i.e. with version 0) is retrieved and applied instead. Then the key
//! value store is queried for follow-up [`StoredCommand`] values (for the
//! version of the aggregate) which are then applied.
//! 
//! Once the latest aggregate has been retrieved, the command is sent to it.
//! Note that this command is not a [`StoredCommand`]. It contains the intent
//! for a change, while [`StoredCommand`] contains the result of such a
//! change. The aggregate is responsible for verifying the command and it can
//! return with: an error, no effect, or a vec of change events.
//! 
//! If a command has no effect, i.e. there is no error and no change, then it
//! is simply forgotten.
//! 
//! If a command has an effect then a [`StoredCommand`] is created that
//! contains a storable representation of the command (e.g. certain values in
//! a command, like an `Arc<Signer>`, or `Arc<Config>` are not included) and
//! either the error or a vec of events. This stored command gets a unique
//! key name based on the version of the aggregate that it affects.
//! 
//! If there should be an existing key-value pair for this stored command,
//! then this indicates that the locking mechanism failed somehow. This
//! should not happen, but if it did, then the command is NOT saved. Instead
//! Krill exits with an error message.
//! 
//! But if all is well and as expected, the command with events is applied
//! to the aggregate. Note that this just updates its version in case of a
//! command that resulted in an error. The in-memory cached aggregate is
//! updated to help performance when retrieving it later. Then the command
//! is saved.
//! 
//! ### Retrieving
//! 
//! When retrieving an aggregate for read access, Krill actually follows
//! the same code path that is used for applying a command, except that in
//! this case the underlying function that takes care of locking and
//! retrieving the latest Aggregate is called with `None` instead of
//! `Some(command)`, so it simply returns without trying to apply any
//! changes. This ensures however, that the same locking rules are observed
//! in both cases and allows us to avoid code duplication.
//! 
//! ### Snapshots
//! 
//! Note that we do not update the full snapshot on every change because this
//! could create a performance issue in cases where aggregates are big (e.g.,
//! a CA with many children or objects) and serialization takes a long time.
//! Instead, updating the snapshots is done daily through a different code
//! path from the scheduler. See `Task::UpdateSnapshots`. This code, again,
//! actually uses the same underlying function as above to retrieve the
//! snapshot, this time setting the `save_snapshot` parameter to true to
//! ensure that the snapshot is saved.
//!
//!
//! ## WAL Store
//!
//! The [`WalStore`] – WAL being short for write-ahead log – is a simplified
//! version of the full aggregate store. It doesn’t store the full command
//! history of an instance but only the changes since the last snapshot was
//! created. Listeners aren’t supported either.

mod agg;
mod store;
mod test;
mod wal;

pub use self::agg::{
    Aggregate, Command, CommandDetails, Event, InitCommand,
    InitCommandDetails, InitEvent, PostSaveEventListener,
    PreSaveEventListener, SentCommand, SentInitCommand, StoredCommand,
    StoredCommandBuilder, StoredEffect, WithStorableDetails
};
pub use self::store::{AggregateStore, AggregateStoreError, Storable};
pub use self::wal::{
    WalCommand, WalChange, WalSet, WalStore, WalStoreError, WalSupport,
};

