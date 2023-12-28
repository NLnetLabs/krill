Certificate Authority Manager
=============================

A single Krill instance can have multiple Certificate Authorities (CAs). The
`CaManager` is the central component that is responsible for managing them.

The core functionality of CAs is contained in the event-sourced `CertAuth` type,
but we have two more companion types for CAs: `CaObjects` is used to manage
manifests and CRLs for CAs, and `StatusStore` is used to track the `CaStatus`
of each CA which tells us about the last successful exchange, or issues, that
a CA has had when connecting to its parent(s) and repository.

The reason for this split in responsibilities is that tracking the issuance
of new manifests and CRLs, or the last successful check with a parent for
resource entitlements (default: every 10 mins) would result in an excessive
amount of commands and events in the history. In itself that is not an issue
as long as these historical entries would be valuable to rebuilding or
understanding the current state of a CA, but the **automatic** generation
of CRLs and manifests, and historical connections between a CA and
its parent or repository are not very interesting in this regard.

The `CaManager` can also manage an embedded TA Signer, in case a testbed setup
is used (as we do in tests), and a TA Proxy.

It also has access to an `Arc<TaskQueue>` that is shared with the `Scheduler`
so that it can add or reschedule certain tasks through the API. For example,
this is used to add a task to sync a CA with its parent 'now' when requested
through the UI or CLI.

And, for completeness, this component has access to a `KrillSigner` that
can be used to sign things, and the central `Config` that contains runtime
settings such as the frequency by which to republish new manifests and CRLs.

Combined we then get this structure:

```rust
pub struct CaManager {
    // Used to manage CAs
    ca_store: AggregateStore<CertAuth>,

    // Used to manage objects for CAs. Also shared with the ca_store as well
    // as a listener so that it can create manifests and CRLs as needed. Accessed
    // here for publishing.
    ca_objects_store: Arc<CaObjectsStore>,

    // Keep track of CA parent and CA repository interaction status.
    status_store: StatusStore,

    // We may have a TA Proxy that we need to manage. Many functions are
    // similar to CA operations, so it makes sense to manage this as a
    // special kind of CA here.
    ta_proxy_store: Option<AggregateStore<TrustAnchorProxy>>,

    // We may also have a local TA signer - in case we are running in
    // testbed or benchmarking mode - so that we can do all TA signing
    // without the need for user interactions through the API and
    // TA signer CLI.
    ta_signer_store: Option<AggregateStore<TrustAnchorSigner>>,

    // shared task queue:
    // - listens for events in the ca_store
    // - processed by the Scheduler
    // - can be used here to schedule tasks through the api
    tasks: Arc<TaskQueue>,

    config: Arc<Config>,
    signer: Arc<KrillSigner>,

    // System actor is used for (scheduled or triggered) system actions where
    // we have no operator actor context.
    system_actor: Actor,
}
```

Initialization
--------------

The `CaManager` is instantiated when Krill starts. All its components ultimately
rely on the `KeyValueStore` - which currently only supports a disk based back-end,
but which can be modified to support other storage options in future.

For full details see `CaManager::build`. It includes extensive comments.

Worth noting here is that the event listening is used here. For example, if a
`CaEvtDet::RoasUpdated` event occurs, then this will trigger:
1. (pre-save) that the `CaObjectsStore` updates the ROAs held by the CA,
   and generates a new CRL and manifest; and
2. (post-save) that the `TaskQueue` notices, and schedules a task to
   synchronize the contents of the `CaObjects` with the CA's repository.

But, see issue https://github.com/NLnetLabs/krill/issues/1182. It would be
better to remove the pre-save listener trait altogether and let a new CRL
and manifest be generated post-save. This can be done as idem-potent
`Task::RepublishIfNeeded` by changing the `CaObjects` implementation to
simply query the CA for the full set of current objects and then letting
it decide to republish, not only because it's time, but also because content
haas changed.


Asynchronous Actions
--------------------

The aforementioned `TaskQueue` is shared with the `Scheduler` which is owned
by `KrillServer`. The `Scheduler` runs as a separate async function and is started
and watches the `TaskQueue` for queued tasks.

The `TaskQueue` orders `Task`-s by `Priority`. The `Priority` is based on timestamps.
The lowest timestamp value results in the highest priority. The `Task` enum is explained
below and contains the various background tasks that may be scheduled. They are scheduled
or re-scheduled with an appropriate priority. Generally speaking:
- we use 'now' for triggered tasks - such as sync with repo
- we use 'now' pus 5 minutes for rescheduling failed syncs with parent/repo
- we use 'now' plus a configurable interval for scheduling any recurring tasks

Furthermore, it should be noted that if a task is already present on the `TaskQueue`,
then scheduling it again will result in a single task being scheduled using the
highest priority between 'new' and 'existing'.

A Krill instance only has a single (singleton) `CaManager` and `RepositoryManager`, which
are kept as `Arc<CaManager>` and `Arc<RepositoryManager>` so that they (well the reference)
can easily be shared with the `Scheduler`, allowing it for example to get the latest objects
for a CA, or to get a CA to sign an RFC 8181 or RFC 6492 message. Furthermore, it also
allows this background job to send new triggered commands to a CA, e.g.: update a received
certificate under a parent.

This approach allows that changes to CAs can be made locally and promptly, without
needing to wait for synchronization with a remote system like a parent or repository.
Furthermore it allows that in case of any issues in connecting to a remote system,
the task can be rescheduled.

Tasks are defined in the `daemon::mq::Task` enum. See the code and comments for
more details. Here, we will highlight a couple:

### Task::QueueStartTasks

Essentially this ensures that all *missing* tasks are rescheduled at startup. See
`daemon::scheduler::Scheduler::queue_start_tasks` for details.


### Task::SyncRepo

These tasks are used to trigger that a CA synchronizes with its repository. All
objects that need to be published have already been created, so this is just about
synchronizing the content. If a `SyncRepo` task fails, then it will be rescheduled
with a new priority 5 minutes into future (const: `SCHEDULER_REQUEUE_DELAY_SECONDS`).

Successes and failures will be tracked in the `StatusStore` held by the `CaManager`.

### Task::SyncParent

These tasks are used to trigger that a CA synchronizes with a specific parent.

There are three synchronization scenarios between a CA and its parent:

1) pending certificate request exists

In this case the pending request is sent to the parent. If the certificate is
signed by the parent this will trigger that a new command is sent to the `CertAuth`
to update the received certificate under a parent. This in turn can trigger changes
in the CA, such as issuing/removing ROAs because of changes in resource entitlements.
Such content changes will trigger that the `CaObjects` structure is updated,
generates a new manifest and CRL, and that a `SyncRepo` task is added.

2) pending revocation request exists

Revocation requests are added when the CA performs a key roll and it's ready to
remove the old key. If any revocation requests exist, then they will be sent to
the parent, and when confirmed the `CertAuth` will be sent a command to complete
the key roll. That in turn will trigger that the old key is removed and its objects
are removed from the `CaObjects` structure. That in turn will then trigger a
`SyncRepo` task to be added.

3) no pending request exists

In this case the job will result in a "Resource Class List Query" (section 3.3.1 of RFC 6492)
to be sent to the parent. The response to this query contains the current
entitlements to resources and validity times under a parent. This response
will then be sent to the `CertAuth` in the form of a command to update its
entitlements. This command will result in a no-op in case there are no changes.
But, if there are changes then it will result in appropriate new events, such
as generation of new certificate request. That will then trigger that the
parent synchronization is scheduled again.

If the task was successful, then a new `Task::SyncParent` is scheduled using
the appropriate (variable) interval returned by `config.ca_refresh_next()`.
If the task was a failure (hard communication error), then it will be rescheduled
with a new priority 5 minutes into future (const: `SCHEDULER_REQUEUE_DELAY_SECONDS`).

### Task::CheckSuspendChildren

This task triggers that inactive children are suspended IFF this non-default
behaviour is enabled in config.

### Task::RepublishIfNeeded

This task triggers that all CAs check whether any manifest or CRL need to be
re-issued, and if so do that re-issuance. Any such re-issuance will result
in events that the listener will pick up, which in turn will ensure that
the appropriate `Task::SyncRepo` is scheduled.

Note: we may change this behaviour in future to just schedule the specific
republish for a known CA and resource class based on last issuance instead.
This would save scanning, and would allow reporting the planned re-issuance
more easily.

### Task::RenewObjectsIfNeeded

This tasks triggers that all CAs check whether any signed objects need
to be re-issued.

We may want to change this behaviour in future to just have specific tasks
for reissuing specific objects instead. This would allow us to report these
things more clearly.

But it will require that we perform checks at startup time and/or have a
persistent queue - to ensure that the tasks are not lost (typically they
would be around 1 year into the future on every issuance). Plus we would
need logic to clean up tasks for removed objects - so this needs some thought.

### Task::RefreshAnnouncementsInfo

This task checks whether the time has come to try and re-fetch RIS Whois
BGP information and update the `Arc<BgpAnalyser>`.

### Task::SweepLoginCache

This task triggers that expired logins are removed from the cache in
case the `multi-user` feature is enabled.

### Task::ResourceClassRemoved

This task is planned when a resource class is removed, and it triggers
that any remaining keys are requested to be revoked by the parent. A resource
class can be removed because the parent no longer entitles the CA to have
certain resources, and in that case the revocation request may fail. This
is treated as a non-critical issue.

Note that if the CA actively removes a parent, it will pro-actively send
revocation requests for all its keys first, remove *all* resource classes
under a parent so that objects will be withdrawn, and then remove the
actual parent altogether.

### Task::UnexpectedKey

> NOTE: This case has never been observed in the wild.

This is an unlikely case which actually needs better testing.

In this case the parent CA returned "Resource Class List Response" in
an earlier exchange, that contained keys unknown to this CA. In such cases
the CA will generate events that trigger that revocation of any surplus
key is requested.

We should remove and replace this logic.. what we probably should do
in this case is that we do a full re-synchronization in terms of keys
with the parent in question. Removing and then re-adding the parent is
probably the easiest way to achieve this.
