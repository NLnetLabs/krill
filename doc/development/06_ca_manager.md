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
of new manifests and CRLs (default: every 16 hours), or the last successful
check with a parent for resource entitlements (default: every 10 mins) would
result in an excessive amount of commands and events in the history. In itself
that is not an issue as long as these historical entries would be valuable
to rebuilding or understanding the current state of a CA, but the **automatic**
generation of CRLs and manifests, and historical connections between a CA and
its parent or repository are not very interesting in this regard.

As a result the `CaManager` is fairly complex because it needs to handle
these three components in parallel, together with a `CaLocks` structure
which is used lock read and write access to individual CAs that is manages.

And, for completeness, this component has access to a `KrillSigner` that
can be used to sign things, and the central `Config` that contains runtime
settings such as the frequency by which to republish new manifests and CRLs.

Combined we then get this structure:

```rust
#[derive(Clone)]
pub struct CaManager {
    ca_store: Arc<AggregateStore<CertAuth>>,
    ca_objects_store: Arc<CaObjectsStore>,
    status_store: Arc<Mutex<StatusStore>>,
    locks: Arc<CaLocks>,
    config: Arc<Config>,
    signer: Arc<KrillSigner>,
}
```


Triggered Actions - Event Listeners
-----------------------------------

As mentioned when we [described](./04_es_krill.md) the event sourcing architecture,
we can have so-called listeners which are notified of events either before (pre), or
after (post) they are saved. The `CaManager` uses this to connect its `self.ca_store`
to the `self.ca_objects_store` as well as to a `MessageQueue` that is passed in at
construction time:

```rust
impl CaManager {
    /// Builds a new CaServer. Will return an error if the TA store cannot be initialized.
    pub async fn build(config: Arc<Config>, mq: Arc<MessageQueue>, signer: Arc<KrillSigner>) -> KrillResult<Self> {
        let mut ca_store = AggregateStore::<CertAuth>::disk(&config.data_dir, CASERVER_DIR)?;
        let ca_objects_store = Arc::new(CaObjectsStore::disk(config.clone(), signer.clone())?);

        .....
        ca_store.add_pre_save_listener(ca_objects_store.clone());
        ca_store.add_post_save_listener(mq);

        ....
    }
}
```

This setup allows the `CaObjectsStore` to be notified of events for each CA, and
this way it can keep track of any changes in resource classes held by the CA and
ROAs and/or delegated certificates - and ensure that a new manifest and CRL are
generated when needed. The `MessageQueue` is mainly used to listen for events in
a `CertAuth` which warrant that a synchronization with a parent, or repository is
triggered.

For example, if a `CaEvtDet::RoasUpdated` event occurs, then this will trigger:
1. (pre-save) that the `CaObjectsStore` updates the ROAs held by the CA,
   and generates a new CRL and manifest; and
2. (post-save) that the `MessageQueue` notices, and schedules a task to
   synchronize the contents of the `CaObjects` with the CA's repository.


Asynchronous Actions
--------------------

The aforementioned `MessageQueue` is shared with the `Scheduler` which is owned
by `KrillServer`. The `Scheduler` uses the `clokwerk.rs` library to schedule several
background jobs in Krill. One of these jobs watches the `MessageQueue` for queued
tasks, added here because of events that occurred.

This background job has access to its own `Arc<CaManager>` and `Arc<RepositoryManager>`,
allowing it for example to get the latest objects for a CA, or to get a CA to sign an
RFC 8181 or RFC 6492 message. Furthermore, it also allows this background job to send
new triggered commands to a CA, e.g.: update a received certificate under a parent.

This approach allows that changes to CAs can be made locally and promptly, without
needed to wait for synchronisation with a remote system like a parent or repository.
Furthermore it allows that in case of any issues in connecting to a remote system,
the task can be rescheduled.

The following tasks are defined:

```rust
pub enum QueueTask {
    ServerStarted,

    SyncRepo(Handle),
    RescheduleSyncRepo(Handle, Time),

    SyncParent(Handle, ParentHandle),
    RescheduleSyncParent(Handle, ParentHandle, Time),

    ResourceClassRemoved(Handle, ParentHandle, HashMap<ResourceClassName, Vec<RevocationRequest>>),
    UnexpectedKey(Handle, ResourceClassName, RevocationRequest),
}
```

* ServerStarted

With this task Krill schedules that all Krill CAs perform a full synchronisation
with their parents and repositories after every restart.

* SyncRepo/RescheduleSyncRepo

These tasks are used to trigger that a CA synchronises with its repository. All
objects that need to be published have already been created, so this is just about
synchronising the content. If a `SyncRepo` task fails, then a `RescheduleSyncRepo`
will be added. The latter keeps track of the time when a synchronisation should
be attempted again.

Successes and failures will be tracked in the `StatusStore` held by the `CaManager`.

* SyncParent/RescheduleSyncParent

These tasks are used to trigger that a CA synchronises with a specific parent.

There are three synchronisation scenarios between a CA and its parent:

1) pending certificate request exists

In this case the pending request is sent to the parent. If the certificate is
signed by the parent this will trigger that a new command is sent to the `CertAuth`
to update the received certificate under a parent. This in turn can trigger changes
in the CA, such as issuing/removing ROAs because of changes in resource entitlements.
In such change in content will trigger that the `CaObjects` structure is updated,
generates a new manifest and CRL, and that a `SyncRepo` task as added.

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
parent synchronisation is scheduled again.

* ResourceClassRemoved

This task is planned when a resource class is removed, and it triggers
that any remaining keys are requested to be revoked by the parent. A resource
class can be removed because the parent no longer entitles the CA to have
certain resources, and in that case the revocation request may fail. This
is treated as a non-critical issue.

Note that if the CA actively removes a parent, it will pro-actively send
revocation requests for all its keys first, and we do not trigger this task.

* UnexpectedKey

> NOTE: This case has never been observed in the wild.

This is an unlikely case which actually needs better testing.

In this case the parent CA returned "Resource Class List Response" in
an earlier exchange, that contained keys unknown to this CA. In such cases
the CA will generate events that trigger that revocation of any surplus
key is requested.

We should remove and replace this logic.. what we probably should do
in this case is that we do a full re-synchronisation in terms of keys
with the parent in question. Removing and then re-adding the parent is
probably the easiest way to achieve this.










