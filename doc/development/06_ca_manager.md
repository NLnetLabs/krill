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
which is used lock read and write access to individual CAs that it manages.

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

Initialization
--------------

The `CaManager` is instantiated when Krill starts. All its components ultimately
rely on the `KeyValueStore` - which currently only supports a disk based back-end,
but which can be modified to support other storage options in future.

Let's first have a look at the initialization code and the included comments, and
then explain a bit more below.

```rust
impl CaManager {
    /// Builds a new CaServer. Will return an error if the CA store cannot be initialized.
    pub async fn build(config: Arc<Config>, mq: Arc<TaskQueue>, signer: Arc<KrillSigner>) -> KrillResult<Self> {
        // Create the AggregateStore for the event-sourced `CertAuth` structures that handle
        // most CA functions.
        let mut ca_store = AggregateStore::<CertAuth>::disk(&config.data_dir, CASERVER_DIR)?;

        if config.always_recover_data {
            // If the user chose to 'always recover data' then do so.
            // This is slow, but it will ensure that all commands and events are accounted for,
            // and there are no incomplete changes where some but not all files for a change were
            // written to disk.
            ca_store.recover()?;
        } else if let Err(e) = ca_store.warm() {
            // Otherwise we just tried to 'warm' the cache. This serves two purposes:
            // 1. this ensures that all `CertAuth` structs are available in memory
            // 2. this ensures that there are no apparent data issues
            //
            // If there are issues, then complain and try to recover.
            error!(
                "Could not warm up cache, data seems corrupt. Will try to recover!! Error was: {}",
                e
            );
            ca_store.recover()?;
        }

        // Create the `CaObjectStore` that is responsible for maintaining CA objects: the `CaObjects`
        // for a CA gets copies of all ROAs and delegated certificates from the `CertAuth` and is responsible
        // for manifests and CRL generation.
        let ca_objects_store = Arc::new(CaObjectsStore::disk(config.clone(), signer.clone())?);

        // Register the `CaObjectsStore` as a pre-save listener to the 'ca_store' so that it can update
        // its ROAs and delegated certificates and/or generate manifests and CRLs when relevant changes
        // occur in a `CertAuth`.
        ca_store.add_pre_save_listener(ca_objects_store.clone());

        // Register the `TaskQueue` as a post-save listener to 'ca_store' so that relevant changes in
        // a `CertAuth` can trigger follow up actions. Most importantly: synchronize with a parent CA or
        // the RPKI repository.
        ca_store.add_post_save_listener(mq);

        // Create the status store which will maintain the last known connection status between each CA
        // and their parent(s) and repository.
        let status_store = StatusStore::new(&config.data_dir, STATUS_DIR)?;

        // Create the per-CA lock structure so that we can guarantee safe access to each CA, while allowing
        // multiple CAs in a single Krill instance to interact: e.g. a child can talk to its parent and they
        // are locked individually.
        let locks = Arc::new(CaLocks::default());

        Ok(CaManager {
            ca_store: Arc::new(ca_store),
            ca_objects_store,
            status_store: Arc::new(Mutex::new(status_store)),
            locks,
            config,
            signer,
        })
    }
}
```

To illustrate how the event listening is used here: If a `CaEvtDet::RoasUpdated` event occurs,
then this will trigger:
1. (pre-save) that the `CaObjectsStore` updates the ROAs held by the CA,
   and generates a new CRL and manifest; and
2. (post-save) that the `TaskQueue` notices, and schedules a task to
   synchronize the contents of the `CaObjects` with the CA's repository.


Asynchronous Actions
--------------------

The aforementioned `TaskQueue` is shared with the `Scheduler` which is owned
by `KrillServer`. The `Scheduler` runs as a separate async function and is started
and watches the `TaskQueue` for queued tasks.

The `TaskQueue` use a `PriorityQueue` ordering `Task`-s by `Priority`. The `Priority`
is based on timestamps - where the lowest timestamp value results in the highest
priority. The `Task` enum is explained below and contains the various background
tasks that may be scheduled. They are scheduled or re-scheduled with an appropriate
priority. Generally speaking:
- we use 'now' for triggered tasks - such as sync with repo
- we use 5 minutes for rescheduling failed syncs with parent/repo
- we use a configurable interval for scheduling any recurring tasks

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

The following tasks are defined:

```rust
pub enum Task {
    ServerStarted,

    SyncRepo {
        ca: Handle,
    },

    SyncParent {
        ca: Handle,
        parent: ParentHandle,
    },

    CheckSuspendChildren {
        ca: Handle,
    },

    RepublishIfNeeded,
    RenewObjectsIfNeeded,

    RefreshAnnouncementsInfo,

    #[cfg(feature = "multi-user")]
    SweepLoginCache,

    ResourceClassRemoved {
        ca: Handle,
        parent: ParentHandle,
        rcn: ResourceClassName,
        revocation_requests: Vec<RevocationRequest>,
    },
    UnexpectedKey {
        ca: Handle,
        rcn: ResourceClassName,
        revocation_request: RevocationRequest,
    },
}
```

### Task::ServerStarted

This task is added during startup and triggers that other tasks are properly
scheduled. We could just add all relevant other tasks instead but this would
cause a minor delay when booting. We may change this later though if people
think it would be better or more clear..

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

But it will require that perform checks at startup time and/or have a
persistent queue - to ensure that the tasks are not lost (typically they
would be around a 1 year into future on every issuance). Plus we would
need logic to clean up tasks for removed objects - so this needs some thought.

### Task::RefreshAnnouncementsInfo

This task checks whether the time has come to try an re-fetch RIS Whois
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



CA Instances and Identity
-------------------------

> Note: this is about adding / removing a CA in Krill. This is not about
> adding/removing parents - or children - to a CA. See below for those
> actions!

### Initialize a CA

The following function initializes a new CA.

```rust
/// # CA instances and identity
///
impl CaManager {
    /// Initializes a CA without a repo, no parents, no children, no nothing
    pub fn init_ca(&self, handle: &Handle) -> KrillResult<()> { ... }
}
```

This results in an initialization event to be sent to the `ca_store`, which contains
the handle (name) and a newly generated ID certificate - the `KrillSigner` owned by
the `CaManager` is used to generate the key pair and sign this ID certificate.


### Get a `CertAuth`

We can get an existing `CertAuth` using the following function.

```rust
impl CaManager {
    /// Gets a CA by the given handle, returns an `Err(ServerError::UnknownCA)` if it
    /// does not exist.
    pub async fn get_ca(&self, handle: &Handle) -> KrillResult<Arc<CertAuth>> { ... }
}
```

**NOTE:** We do not expose the `CertAuth` type to the public API. But we have functions
for public types. The most interesting ones are probably:

```rust
/// # Data presentation
///
impl CertAuth {
    /// Returns a `CertAuthInfo` for this, which includes a data representation
    /// of the internal structure, in particular with regards to parent, children,
    /// resource classes and keys.
    pub fn as_ca_info(&self) -> CertAuthInfo { ... }

    /// Returns the current RoaDefinitions for this, i.e. the intended authorized
    /// prefixes. Provided that the resources are held by this `CertAuth` one can
    /// expect that corresponding ROA **objects** are created by the system.
    pub fn roa_definitions(&self) -> Vec<RoaDefinition> { ... }
    
    /// Returns the complete set of all currently received resources, under all parents, for
    /// this `CertAuth`
    pub fn all_resources(&self) -> ResourceSet { ... }

    /// Returns an RFC 8183 Child Request - which can be represented as XML to a
    /// parent of this `CertAuth`
    pub fn child_request(&self) -> rfc8183::ChildRequest { ... }

    /// Returns an RFC 8183 Publisher Request - which can be represented as XML to a
    /// repository for this `CertAuth`
    pub fn publisher_request(&self) -> rfc8183::PublisherRequest { ... }
}
```


### Update ID Certificate

```rust
/// # CA instances and identity
///
impl CaManager {
    /// Updates the self-signed ID certificate for a CA. Use this with care as
    /// RFC 8183 only talks about initial ID exchanges in the form of XML files.
    /// It does not talk about updating identity certificates and keys. Krill supports
    /// that a new ID key pair and certificate is generated, and has functions to update
    /// this for a parent, a child, a repo and a publisher, but other implementations may
    /// not support that identities are updated after initialization.
    pub async fn ca_update_id(&self, handle: Handle, actor: &Actor) -> KrillResult<()> {
        let cmd = CmdDet::update_id(&handle, self.signer.clone(), actor);
        self.send_command(cmd).await?;
        Ok(())
    }
}
```


CA Repository Related Functions
-------------------------------


### CA Repository Configuration

Before a CA can publish anything they need to have a repository configured. We need to
submit a `RepositoryContact`, which wraps and RFC 8183 Response:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub struct RepositoryContact {
    repository_response: rfc8183::RepositoryResponse,
}
```

Then submit it to the following function:

```rust
impl CaManager {
    /// Update repository where a CA publishes.
    pub async fn update_repo(
        &self,
        handle: Handle,
        new_contact: RepositoryContact,
        actor: &Actor
    ) -> KrillResult<()> { ... }
}
```

This will result in a `CmdDet::RepoUpdate` to be sent to the `CertAuth`. 

If there was no repository defined, then this will result in a `CaEvtDet::RepoUpdated` event.
This event will then be picked up by the `TaskQueue` as post-save event listener and
trigger that the CA synchronizes with its parents, because now that it has somewhere
to publish it can actually request certificates.

If there **was** a repository defined, then Krill will also initiate key rolls for all
existing resource classes. If any of these already had a key roll in progress, then an
`Error::KeyRollNotAllowed` is returned and the repository update is refused. When key rolls
are initiated we will see two additional events for each resource class: `CaEvtDet::KeyRollPendingKeyAdded`
which contains the new key id, and `CaEvtDet::CertificateRequested` with a request for the
new key, using the new repository URIs.

When these events are applied the previous repository will be preserved for the existing keys
first - so that they can continue to use the old URIs in subsequent certificate requests. Then
the default repository is updated. And then the new keys and requests are added.

To complete the migration to a new repository the key roll must be finished first by activating
the new keys. This is not done automatically (yet), but requires that the operator sends the
appropriate command. Officially one should wait for 24 hours before activating a new key so
that RPs have ample time to discover it. However, if the old repository is unreachable and this
triggered the migration, then it would be advisable to activate this new key asap.

> **NOTE:** `CaManager` performs no validation whether a new repository can be reached,
> but `KrillServer` **does** this, before calling the function above.


### CA Repository Objects and Status

To verify the current set of objects that a CA wants to publish, and the set of objects
that a CA has published, we can use the following functions:

```rust
impl CaManager {
    /// Get the current objects for a CA for each repository that it's using.
    ///
    /// Notes:
    /// - typically a CA will use only one repository, but during migrations there may be multiple.
    /// - these objects may not have been published (yet) - check `ca_repo_status`.
    pub async fn ca_repo_elements(&self, ca: &Handle) -> KrillResult<HashMap<RepositoryContact, Vec<PublishElement>>> { ... }

    /// Returns the RepoStatus for a CA, this includes the last connection time and result, and the
    /// objects currently known to be published.
    ///
    /// NOTE: This contains the status of the **CURRENT** repository only. It could be extended to
    /// include the status of the old repository during a migration.
    pub async fn ca_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> { ... }
}
```

### CA Repository Content Generation

The set of objects to be published by a Krill CA is updated whenever there are relevant changes. For
example: when the intended RouteAuthorizations are updated (see below), ROA *objects* are updated and
this triggers (through the pre-save-event-listener) that the relevant manifest(s) and CRL(s) are also
generated. Alternatively new manifests and CRLs can be generated when the 'republish' background job
detects that an update is needed before the time for the 'next update' is drawing near.

See the following code in `scheduler.rs`:

```rust
fn make_cas_republish(ca_server: Arc<CaManager>, event_queue: Arc<TaskQueue>) -> ScheduleHandle {
    SkippingScheduler::run(
        SCHEDULER_INTERVAL_SECONDS_REPUBLISH,
        "CA certificate republish",
        move || {
            let mut rt = Runtime::new().unwrap();
            rt.block_on(async {
                debug!("Triggering background republication for all CAs, note this may be a no-op");
                match ca_server.republish_all().await {
                    Err(e) => error!("Background republishing of MFT and CRLs failed: {}", e),
                    Ok(cas) => {
                        for ca in cas {
                            info!("Re-issued MFT and CRL for CA: {}", ca);
                            event_queue.schedule_sync_repo(ca);
                        }
                    }
                }
            })
        },
    )
}
```

Whenever a change in the CA's content occurs the following function is called to schedule that the
CA will synchronize its updated content with its repository as a separate - asynchronous - effort.
We also have a function to RE-schedule this synchronization which is called in case a synchronization
failed:

```rust
impl TaskQueue {
    /// Schedules that a CA synchronizes with its repositories.
    pub fn schedule_sync_repo(&self, ca: Handle) {
        self.schedule(Task::SyncRepo(ca));
    }

    /// RE-Schedules that a CA synchronizes with its repositories. This function
    /// takes a time argument to indicate *when* the resynchronization should be
    /// attempted.
    pub fn reschedule_sync_repo(&self, ca: Handle, time: Time) {
        self.schedule(Task::RescheduleSyncRepo(ca, time));
    }
}
```

### CA Repository Synchronization

We have the following function in `CaManager` that triggers that tasks
are scheduled to synchronize each CA with their Repository.

```rust
impl CaManager {
    /// Schedule synchronizing all CAs with their repositories.
    pub fn cas_schedule_repo_sync_all(&self, actor: &Actor) { ... }
}
```

The above results in `Task::SyncRepo` tasks to be added to the `TaskQueue`,
monitored by the `Scheduler`, which will then trigger a call this function:

```rust
impl CaManager {
    /// Synchronize a CA with its repositories.
    ///
    /// Note typically a CA will have only one active repository, but in case
    /// there are multiple during a migration, this function will ensure that
    /// they are all synchronized.
    ///
    /// In case the CA had deprecated repositories, then a clean up will be
    /// attempted. I.e. the CA will try to withdraw all objects from the deprecated
    /// repository. If this clean up fails then the number of clean-up attempts
    /// for the repository in question is incremented, and this function will
    /// fail. When there have been 5 failed attempts, then the old repository
    /// is assumed to be unreachable and it will be dropped - i.e. the CA will
    /// no longer try to clean up objects.
    pub async fn cas_repo_sync_single(&self, ca_handle: &Handle) -> KrillResult<()> { ... }
}
```


CA as Child Related Functions
-----------------------------

The following functions are used to manage parents of CAs.

```rust
/// # CAs as children
///
impl CaManager {
    /// Adds a parent to a CA. This will trigger that the CA connects to this new parent
    /// in order to learn its resource entitlements and set up the resource class(es) under
    /// this parent, and request certificate(s).
    pub async fn ca_parent_add(
        &self,
        handle: Handle,
        parent: ParentCaReq,
        actor: &Actor
    )-> KrillResult<()> { ... }

    /// Removes a parent from a CA, this will trigger that best effort revocations of existing
    /// keys under this parent are requested. Any resource classes under the parent will be removed
    /// and all relevant content will be withdrawn from the repository.
    pub async fn ca_parent_remove(
        &self,
        handle: Handle,
        parent: ParentHandle,
        actor: &Actor
    ) -> KrillResult<()> { ... }

    /// Updates a parent of a CA, this can be used to update the service uri and/or
    /// identity certificate for an existing parent.
    pub async fn ca_parent_update(
        &self,
        handle: Handle,
        parent: ParentHandle,
        contact: ParentCaContact,
        actor: &Actor,
    ) -> KrillResult<()> { ... }

    /// Returns the parent statuses for this CA
    pub async fn ca_parent_statuses(&self, ca: &Handle) -> KrillResult<ParentStatuses> { ... }

    /// Schedule refreshing all CAs as soon as possible:
    ///
    /// Note: this function can be called manually through the API, but normally the
    ///       CA refresh process is replanned on the task queue automatically.
    pub async fn cas_schedule_refresh_all(&self) {
        if let Ok(cas) = self.ca_store.list() {
            for ca_handle in cas {
                self.cas_schedule_refresh_single(ca_handle).await;
            }
        }
    }

    /// Refresh a single CA with its parents, and possibly suspend inactive children.
    pub async fn cas_schedule_refresh_single(&self, ca_handle: Handle) {
        self.ca_schedule_sync_parents(&ca_handle).await;
    }
```


CA as Parent Related Functions
------------------------------

The following functions are used to manage children of CAs.

```rust
/// # CAs as children
///
impl CaManager {
    /// Adds a child under a CA. The 'service_uri' is used here so that
    /// the appropriate `ParentCaContact` can be returned. If the `AddChildRequest`
    /// contains resources not held by this CA, then an `Error::CaChildExtraResources`
    /// is returned.
    pub async fn ca_add_child(
        &self,
        ca: &Handle,
        req: AddChildRequest,
        service_uri: &uri::Https,
        actor: &Actor,
    ) -> KrillResult<ParentCaContact> { ... }

    /// Show details for a child under the TA.
    pub async fn ca_show_child(
        &self,
        ca: &Handle,
        child: &ChildHandle
    ) -> KrillResult<ChildCaInfo> { ... }

    /// Gets an RFC8183 Parent Response for the child.
    pub async fn ca_parent_response(
        &self,
        ca: &Handle,
        child_handle: ChildHandle,
        tag: Option<String>,
        service_uri: &uri::Https,
    ) -> KrillResult<rfc8183::ParentResponse> { ... }

    /// Update a child under this CA. The submitted `UpdateChildRequest` can contain a
    /// new `IdCert`, or `ResourceSet`, or both. When resources are updated, the existing
    /// resource entitlements are replaced by the new value - i.e. this is not a delta
    /// and it affects all Internet Number Resource (INR) types (IPv4, IPV6, ASN). Setting
    /// resource entitlements beyond the resources held by the parent CA will return
    /// an `Error::CaChildExtraResources`.
    pub async fn ca_child_update(
        &self,
        handle: &Handle,
        child: ChildHandle,
        req: UpdateChildRequest,
        actor: &Actor,
    ) -> KrillResult<()> { ... }

    /// Removes a child from this CA. This will also ensure that certificates issued to the child
    /// are revoked and withdrawn.
    pub async fn ca_child_remove(&self, ca: &Handle, child: ChildHandle, actor: &Actor) -> KrillResult<()> { ... }

    /// Processes an RFC6492 sent to this CA:
    /// - parses the message bytes
    /// - validates the request
    /// - processes the child request
    /// - signs a response and returns the bytes
    pub async fn rfc6492(&self, ca_handle: &Handle, msg_bytes: Bytes, actor: &Actor) -> KrillResult<Bytes> { ... }
}
```

ROA Support
-----------

The following function is used to update the ROAs under a CA:

```rust
/// # Route Authorization functions
///
impl CaManager {
    /// Update the routes authorized by a CA. This will trigger that ROAs
    /// are made in the resource classes that contain the prefixes. If the
    /// update is rejected, e.g. because the CA does not have the necessary
    /// prefixes then an `Error::RoaDeltaError` will be returned.
    /// If the update is successful, new manifest(s) and CRL(s) will be created,
    /// and resynchronization between the CA and its repository will be triggered.
    /// Finally note that ROAs may be issued on a per prefix basis, or aggregated
    /// by ASN based on the defaults or values configured.
    pub async fn ca_routes_update(
        &self,
        handle: Handle,
        updates: RouteAuthorizationUpdates,
        actor: &Actor,
    ) -> KrillResult<()> { ... }

    /// Re-issue about to expire ROAs in all CAs. This is a no-op in case
    /// ROAs do not need re-issuance. If new ROAs are created they will also
    /// be published (event will trigger that MFT and CRL are also made, and
    /// and the CA in question synchronizes with its repository).
    pub async fn renew_roas_all(&self, actor: &Actor) -> KrillResult<()> { ... }
}
```

Note that Krill also support ROA analysis, dry-run and suggestions. These functions
are implemented in the `BgpAnalyser` type, which keeps track of announcements that
it has seen (RIS whois), and can take a CA's current ROA definitions as input.


CA Key Rolls
------------

Krill supports key roll operations as defined in RFC 6489, except that the key roll
is fully manual. I.e. it's up to the operator to observe the 24 hour staging period
before activating new keys, and phasing out old keys.

```rust
/// CA Key Roll functions
///
impl CaManager {
    /// Initiate an RFC 6489 key roll for all active keys in a CA older than the specified duration.
    pub async fn ca_keyroll_init(&self, handle: Handle, max_age: Duration, actor: &Actor) -> KrillResult<()> { ... }

    /// Activate a new key, as part of the key roll process (RFC6489). Only new keys that
    /// have an age equal to or greater than the staging period are promoted. The RFC mandates
    /// a staging period of 24 hours, but we may use a shorter period for testing and/or emergency
    /// manual key rolls.
    pub async fn ca_keyroll_activate(&self, handle: Handle, staging: Duration, actor: &Actor) -> KrillResult<()> { ... }
}
```

Note that key rolls are also used in case a CA is migrated to a new repository. In such cases
a key roll will be initiated and the new key will use the new repository, while the -still current-
key continues to use the previous repository. The operator then needs to call `ca_keyroll_activate`
to complete the keyroll and phase out the old repository. If this is a planned migration, then it
is good to observe the 24 hours period. However, if the the old repository is no longer reachable 
and this might have been the cause of the migration, then it is advised to activate the new key asap.


CA History
----------

CA History can be inspected with the following functions:

```rust
/// # CA History
///
impl CaManager {
    /// Gets the history for a CA.
    pub async fn get_ca_history(&self, handle: &Handle, crit: CommandHistoryCriteria) -> KrillResult<CommandHistory> { ... }

    /// Shows the details for a CA command.
    pub fn get_ca_command_details(&self, handle: &Handle, command: CommandKey) -> KrillResult<CaCommandDetails> { ... }
}
```

The `CommandHistoryCriteria` can be used for filtering and pagination. The returned `CommandHistory` looks like this:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistory {
    offset: usize,
    total: usize,
    commands: Vec<CommandHistoryRecord>,
}

/// A description of a command that was processed, and the events / or error
/// that followed. Does not include the full stored command details, but only
/// the summary which is shown in the history response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandHistoryRecord {
    pub key: String,
    pub actor: String,
    pub timestamp: i64,
    pub handle: Handle,
    pub version: u64,
    pub sequence: u64,
    pub summary: CommandSummary,
    pub effect: StoredEffect,
}

impl CommandHistoryRecord {
    ...
    pub fn command_key(&self) -> Result<CommandKey, CommandKeyError> {
        CommandKey::from_str(&self.key)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub enum StoredEffect {
    Error { msg: String },
    Success { events: Vec<u64> },
}
```

So, we can get a list of commands and their effect. If they were successful, we just get the
versions of the events.

Use the `get_ca_command_details` function to look at a specific command in more detail:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaCommandDetails {
    command: StoredCommand<StorableCaCommand>,
    result: CaCommandResult,
}


#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CaCommandResult {
    Error(String),
    Events(Vec<ca::CaEvt>),
}

/------------ StorableCaCommand -------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum StorableCaCommand {
    MakeTrustAnchor,
    ChildAdd {
        child: ChildHandle,
        ski: Option<String>,
        resources: ResourceSet,
    },
    ChildUpdateResources {
        child: ChildHandle,
        resources: ResourceSet,
    },
    ChildUpdateId {
        child: ChildHandle,
        ski: String,
    },
    ChildCertify {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        limit: RequestResourceLimit,
        ki: KeyIdentifier,
    },
    ChildRevokeKey {
        child: ChildHandle,
        revoke_req: RevocationRequest,
    },
    ChildRemove {
        child: ChildHandle,
    },
    GenerateNewIdKey,
    AddParent {
        parent: ParentHandle,
        contact: StorableParentContact,
    },
    UpdateParentContact {
        parent: ParentHandle,
        contact: StorableParentContact,
    },
    RemoveParent {
        parent: ParentHandle,
    },
    UpdateResourceEntitlements {
        parent: ParentHandle,
        entitlements: Vec<StorableRcEntitlement>,
    },
    UpdateRcvdCert {
        resource_class_name: ResourceClassName,
        resources: ResourceSet,
    },
    KeyRollInitiate {
        older_than_seconds: i64,
    },
    KeyRollActivate {
        staged_for_seconds: i64,
    },
    KeyRollFinish {
        resource_class_name: ResourceClassName,
    },
    RoaDefinitionUpdates {
        updates: RoaDefinitionUpdates,
    },
    AutomaticRoaRenewal,
    Republish,
    RepoUpdate {
        service_uri: Option<ServiceUri>,
    },
    RepoRemoveOld,
    RtaPrepare {
        name: RtaName,
    },
    RtaSign {
        name: RtaName,
    },
    RtaCoSign {
        name: RtaName,
    },
    Deactivate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum CaEvtDet {
    // Being a Trust Anchor
    TrustAnchorMade {
        ta_cert_details: TaCertDetails,
    },

    // Being a parent Events
    ChildAdded {
        child: ChildHandle,
        id_cert: Option<IdCert>,
        resources: ResourceSet,
    },
    ChildCertificateIssued {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    },
    ChildKeyRevoked {
        child: ChildHandle,
        resource_class_name: ResourceClassName,
        ki: KeyIdentifier,
    },
    ChildCertificatesUpdated {
        resource_class_name: ResourceClassName,
        updates: ChildCertificateUpdates,
    },
    ChildUpdatedIdCert {
        child: ChildHandle,
        id_cert: IdCert,
    },
    ChildUpdatedResources {
        child: ChildHandle,
        resources: ResourceSet,
    },
    ChildRemoved {
        child: ChildHandle,
    },

    // Being a child Events
    IdUpdated {
        id: Rfc8183Id,
    },
    ParentAdded {
        parent: ParentHandle,
        contact: ParentCaContact,
    },
    ParentUpdated {
        parent: ParentHandle,
        contact: ParentCaContact,
    },
    ParentRemoved {
        parent: ParentHandle,
    },
    ResourceClassAdded {
        resource_class_name: ResourceClassName,
        parent: ParentHandle,
        parent_resource_class_name: ParentResourceClassName,
        pending_key: KeyIdentifier,
    },
    ResourceClassRemoved {
        resource_class_name: ResourceClassName,
        parent: ParentHandle,
        revoke_requests: Vec<RevocationRequest>,
    },
    CertificateRequested {
        resource_class_name: ResourceClassName,
        req: IssuanceRequest,
        ki: KeyIdentifier, // Also contained in request. Drop?
    },
    CertificateReceived {
        resource_class_name: ResourceClassName,
        rcvd_cert: RcvdCert,
        ki: KeyIdentifier, // Also in received cert. Drop?
    },

    // Key life cycle
    KeyRollPendingKeyAdded {
        // A pending key is added to an existing resource class in order to initiate
        // a key roll. Note that there will be a separate 'CertificateRequested' event for
        // this key.
        resource_class_name: ResourceClassName,
        pending_key_id: KeyIdentifier,
    },
    KeyPendingToNew {
        // A pending key is marked as 'new' when it has received its (first) certificate.
        // This means that the key is staged and a mft and crl will be published. According
        // to RFC 6489 this key should be staged for 24 hours before it is promoted to
        // become the active key. However, in practice this time can be shortened.
        resource_class_name: ResourceClassName,
        new_key: CertifiedKey, // pending key which received a certificate becomes 'new', i.e. it is staged.
    },
    KeyPendingToActive {
        // When a new resource class is created it will have a single pending key only which
        // is promoted to become the active (current) key for the resource class immediately
        // after receiving its first certificate. Technically this is not a roll, but a simple
        // first activation.
        resource_class_name: ResourceClassName,
        current_key: CertifiedKey, // there was no current key, pending becomes active without staging when cert is received.
    },
    KeyRollActivated {
        // When a 'new' key is activated (becomes current), the previous current key will be
        // marked as old and we will request its revocation. Note that any current ROAs and/or
        // delegated certificates will also be re-issued under the new 'current' key. These changes
        // are tracked in separate `RoasUpdated` and `ChildCertificatesUpdated` events.
        resource_class_name: ResourceClassName,
        revoke_req: RevocationRequest,
    },
    KeyRollFinished {
        // The key roll is finished when the parent confirms that the old key is revoked.
        // We can remove it and stop publishing its mft and crl.
        resource_class_name: ResourceClassName,
    },
    UnexpectedKeyFound {
        // This event is generated in case our parent reports keys to us that we do not
        // believe we have. This should not happen in practice, but this is tracked so that
        // we can recover from this situation. We can request revocation for all these keys
        // and create new keys in the RC as needed.
        resource_class_name: ResourceClassName,
        revoke_req: RevocationRequest,
    },

    // Route Authorizations
    RouteAuthorizationAdded {
        // Tracks a single authorization (VRP) which is added. Note that (1) a command to
        // update ROAs can contain multiple changes in which case multiple events will
        // result, and (2) we do not have a 'modify' event. Modifications of e.g. the
        // max length are expressed as a 'removed' and 'added' event in a single transaction.
        auth: RouteAuthorization,
    },
    RouteAuthorizationRemoved {
        // Tracks a single authorization (VRP) which is removed. See remark for RouteAuthorizationAdded.
        auth: RouteAuthorization,
    },
    RoasUpdated {
        // Tracks ROA *objects* which are (re-)issued in a resource class.
        resource_class_name: ResourceClassName,
        updates: RoaUpdates,
    },

    // Publishing
    RepoUpdated {
        // Adds the repository contact for this CA so that publication can commence,
        // and certificates can be requested from parents. Note: the CA can only start
        // requesting certificates when it knows which URIs it can use.
        contact: RepositoryContact,
    },
    RepoCleaned {
        // Mark an old repository as cleaned, so that it can be removed.
        contact: RepositoryContact,
    },

    // Rta
    //
    // NOTE RTA support is still experimental and incomplete.
    RtaSigned {
        // Adds a signed RTA. The RTA can be single signed, or it can
        // be a multi-signed RTA based on an existing 'PreparedRta'.
        name: RtaName,
        rta: SignedRta,
    },
    RtaPrepared {
        // Adds a 'prepared' RTA. I.e. the context of keys which need to be included
        // in a multi-signed RTA.
        name: RtaName,
        prepared: PreparedRta,
    },
}
```




