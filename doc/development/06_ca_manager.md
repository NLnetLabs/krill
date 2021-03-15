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
    pub async fn build(config: Arc<Config>, mq: Arc<MessageQueue>, signer: Arc<KrillSigner>) -> KrillResult<Self> {
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

        // Register the `MessageQueue` as a post-save listener to 'ca_store' so that relevant changes in
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
needed to wait for synchronization with a remote system like a parent or repository.
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

### QueueTask::ServerStarted

With this task Krill schedules that all Krill CAs perform a full synchronization
with their parents and repositories after every restart.

### QueueTask::SyncRepo/RescheduleSyncRepo

These tasks are used to trigger that a CA synchronizes with its repository. All
objects that need to be published have already been created, so this is just about
synchronizing the content. If a `SyncRepo` task fails, then a `RescheduleSyncRepo`
will be added. The latter keeps track of the time when a synchronization should
be attempted again.

Successes and failures will be tracked in the `StatusStore` held by the `CaManager`.

### QueueTask::SyncParent/RescheduleSyncParent

These tasks are used to trigger that a CA synchronizes with a specific parent.

There are three synchronization scenarios between a CA and its parent:

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
parent synchronization is scheduled again.

### QueueTask::ResourceClassRemoved

This task is planned when a resource class is removed, and it triggers
that any remaining keys are requested to be revoked by the parent. A resource
class can be removed because the parent no longer entitles the CA to have
certain resources, and in that case the revocation request may fail. This
is treated as a non-critical issue.

Note that if the CA actively removes a parent, it will pro-actively send
revocation requests for all its keys first, and we do not trigger this task.

### QueueTask::UnexpectedKey

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

The following function initializes as new CA.

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

Before a CA can publish anything they need to have a repository configured. Currently
Krill still has the concept of an 'embedded' - in this Krill instance - vs 'Rfc8181'
remote repository. However, we plan to change this in the very short term. Even if
a Repository Server on the same Krill Instance is used, it can do the full RFC 8181
protocol - so having just one option will greatly simplify things.

For now, get an RFC 8181 Repository Response from the Publication Server, which we
would get in response to the `rfc8183::PublisherRequest` we get from `CertAuth::publisher_request()`,
and create the following enum:

```rust
pub enum RepositoryContact {
    Embedded {
        info: RepoInfo,
    },
    Rfc8181 {
        server_response: rfc8183::RepositoryResponse,
    },
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
This event will then be picked up by the `MessageQueue` as post-save event listener and
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
the new keys. This is not done automatically (yet), but requires that the operators sends the
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
    /// - these object may not have been published (yet) - check `ca_repo_status`.
    pub async fn ca_repo_elements(&self, ca: &Handle) -> KrillResult<HashMap<RepositoryContact, Vec<PublishElement>>> { ... }

    /// Returns the RepoStatus for a CA, this includes the last connection time and result, and the
    /// objects currently known to be published.
    ///
    /// NOTE: This contains the status of the **CURRENT** repository only. It could be extended to
    /// include the status of the old repository during a migration.
    pub async fn ca_repo_status(&self, ca: &Handle) -> KrillResult<RepoStatus> { ... }
}
```

### CA Repository Synchronization

This will be improved, see issue #440.

For now synchronization with a remote repository is handled by the `CaPublisher` type which can
contain an option of an embedded repository. This is to support the two current models: RFC compliant
remote - or even local - repository, and the embedded.

When we remove the 'embedded' option this can all be simplified massively.

So, not putting too much effort in documenting this right now.. suffice to say that synchronization
with repositories is triggered by the `MessageQueue` listening for relevant events.

In addition to this we have a function on `KrillServer` to trigger that all CAs synchronize with their
repository:

```rust
/// # Bulk background operations CAS
///
impl KrillServer {
    /// Re-sync all CAs with their repositories
    pub async fn resync_all(&self, actor: &Actor) -> KrillEmptyResult { ... }
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

    /// Refresh all CAs:
    /// - process all CAs in parallel
    /// - process all parents for CAs in parallel
    ///    - send pending requests if present, or
    ///    - ask parent for updates and process if present
    pub async fn cas_refresh_all(&self, actor: &Actor) { ... }

    /// Synchronizes a CA with one of its parents:
    ///   - send pending requests if present; otherwise
    ///   - get and process updated entitlements
    ///
    /// Note: if new request events are generated as a result of processing updated entitlements
    ///       then they will trigger that this synchronization is called again so that the pending
    ///       requests can be sent.
    pub async fn ca_sync_parent(&self, handle: &Handle, parent: &ParentHandle, actor: &Actor) -> KrillResult<()> { ... }
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
    /// new `IdCert`, or `ResourceSet`. If both are updated in a single update, then
    /// an `Error::CaChildUpdateOneThing` is returned. When resource entitlements are updated,
    /// the existing entitlements are replaced by the new value - i.e. this is not a delta
    /// and it affects all INR types. Setting resource entitlements beyond the resources
    /// held by the parent CA will return an `Error::CaChildExtraResources`.
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


