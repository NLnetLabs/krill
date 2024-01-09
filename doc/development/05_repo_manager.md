Repository Manager
==================

The `RepositoryManager` is the central component that is responsible for managing
access to, and content of the RPKI Repository. It delegates those functions to an
event-sourced component `RepositoryAccess` which is responsible for guarding access,
and the `RepositoryContent` component which manages the current content.


Composition
-----------

There can only be one active repository, but since Krill storage (`KeyValueStore`)
and eventsourcing support is based on the concept of multiple managed entities,
it was convenient to create wrapper types to help access:

```rust
/// RepositoryManager is responsible for:
/// * verifying that a publisher is allowed to publish.
/// * publish content to RRDP and rsync.
pub struct RepositoryManager {
    access: Arc<RepositoryAccessProxy>,
    content: Arc<RepositoryContentProxy>,

    // Shared task queue, use to schedule RRDP updates when content is updated.
    tasks: Arc<TaskQueue>,

    config: Arc<Config>,
    signer: Arc<KrillSigner>,
}
```

```rust
/// We can only have one (1) RepositoryAccess, but it is an event-sourced
/// type which is stored in an AggregateStore which could theoretically
/// serve multiple RepositoryAccess instances. So, we use RepositoryAccessProxy
/// as a wrapper around this so that callers don't need to worry about storage details.
pub struct RepositoryAccessProxy {
    store: AggregateStore<RepositoryAccess>,
    key: MyHandle,
}
```

```rust
/// We can only have one (1) RepositoryContent, but it is stored
/// in a KeyValueStore. So this type provides a wrapper around this
/// so that callers don't need to worry about storage details.
#[derive(Debug)]
pub struct RepositoryContentProxy {
    store: Arc<WalStore<RepositoryContent>>,
    default_handle: MyHandle,
}
```

Initialization
--------------

The `RepositoryManager` is instantiated when Krill starts *if* the Publication
Server function is [enabled](./01_daemon.md):

```rust
/// Builds a RepositoryManager. This will use a disk based KeyValueStore using the
/// the data directory specified in the supplied `Config`.
pub fn build(config: Arc<Config>, signer: Arc<KrillSigner>) -> Result<Self, Error> { ... }
```

When the `RepositoryManager` is created, it still needs to be initialized. This
is done this way, because we cannot change the base URIs of an operational RPKI
repository. There is no way to inform publishing CAs that the location of their
objects has changed. Therefore we have an explicit function for this:

```rust
/// Create the publication server, will fail if it was already created.
pub fn init(&self, uris: PublicationServerUris) -> KrillResult<()> {
    info!("Initializing repository");
    self.access.init(uris.clone(), &self.signer)?;
    self.content.init(&self.config.data_dir, uris)?;
    self.content.write_repository(&self.config.repository_retention)?;

    Ok(())
}
```

Note that it writes the empty repository as part of the initialization process.
We do this, because that gives users an opportunity to verify that the repository
content can be accessed. In particular: expect an RRDP notification.xml and a snapshot.xml
containing 0 entries to be published.

If it is found that the repository is not set up correctly, then it can be 'cleared'
so it can be initialized again:

```rust
/// Clear the publication server. Will fail if it still
/// has publishers. Or if it does not exist
pub fn repository_clear(&self) -> KrillResult<()> {
    self.access.clear()?;
    self.content.clear()
}
```


Adding / Removing Publishers
----------------------------

To add a publisher we have to submit an `rfc8183::PublisherRequest`, and an `Actor`
so that we attribute the change in the history of the `RepositoryAccess` component.
The request type can be created from XML supplied by a remote publisher. The 'handle'
is the local name that we will use for the publisher, and the XML contains a suggestion
set by the remote party. But, it is possible (and perhaps recommended) to override
this 'handle' in the request object with something that is unique to *us*, e.g. a UUID.

```rust
/// Adds a publisher. This will fail if a publisher already exists for the handle in the request.
pub fn create_publisher(&self, req: rfc8183::PublisherRequest, actor: &Actor) -> KrillResult<()> {
    let name = req.publisher_handle().clone();

    self.access.add_publisher(req, actor)?;
    self.content.add_publisher(name)
}
```

The publisher is going to need to get RFC8183 Repository Response XML. We can get
an `rfc8183::RepositoryResponse` which can be printed (`fmt::Display`) as XML:

```rust
/// Returns the RFC8183 Repository Response for the publisher
pub fn repository_response(
    &self,
    rfc8181_uri: uri::Https,
    publisher: &PublisherHandle,
) -> KrillResult<rfc8183::RepositoryResponse> {
    self.access.repository_response(rfc8181_uri, publisher)
}
```

In order to remove a publisher we just need to tell the RepositoryManager its handle (name).
This removes both the access information (handle, RFC8181 ID cert, ..) and all content for
the publisher:

```rust
/// Removes a publisher and all of its content.
pub fn remove_publisher(&self, name: PublisherHandle, actor: &Actor) -> KrillResult<()> {
    let publisher = self.access.get_publisher(&name)?;
    let base_uri = publisher.base_uri();

    self.content.remove_publisher(&name, base_uri, &self.config.repository_retention)?;
    self.access.remove_publisher(name, actor)
}
```


Publisher Stats
---------------

We can get the stats for the complete repository, i.e. with all publishers, as follows:

```rust
pub fn repo_stats(&self) -> KrillResult<RepoStats> {
    self.content.stats()
}
```

The `RepoStats` structure includes the following information, and can be serialized to
JSON:
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepoStats {
    publishers: HashMap<PublisherHandle, PublisherStats>,
    session: RrdpSession,
    serial: u64,
    last_update: Option<Time>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherStats {
    objects: usize,
    size: usize,
    last_update: Option<Time>,
}
```

> NOTE: This includes a map of PublisherHandle -> PublisherStats. In JSON this can look confusing
> because there will be JSON members that are the publisher name in quotes. For other types we
> have been using an array with named items in the JSON representation. So, perhaps we should
> change this as well. We could just have a Vec here, since fast map access is not really a
> concern. The consumer can build their own map if they really want one.


Publishing / RFC 8181
---------------------

Now, for the main purpose of course.. we have a function here that will take bytes
submitted by a publisher, parse it and validate it as an RFC 8181 request and return the
appropriate signed response.

```rust
pub fn rfc8181(&self, publisher_handle: PublisherHandle, msg_bytes: Bytes) -> KrillResult<Bytes>;
```

In case of issues that are part of the protocol (sections 2.4 and 2.5 of RFC 8181) this
will return a signed RFC 8181 error response. In case of issues that we cannot recover
from - e.g. there is I/O error - something is seriously broken in the server - then this
will return an actual *rust* Error. It's up to the caller of this function to take
appropriate action, e.g. give the publisher an HTTP response code, but possibly even
crash this server - if it cannot function anymore.

Under the hood this function will first retrieve the publisher from `RepositoryAccess`
to verify that the sender is known, and get their ID certificate (used for signing)
and base_uri Rsync jail. The content of the query (list or send updates) is then
passed on to `RepositoryContent`.

The `RepositoryContent` type is not event-sourced as it turned out that keeping the
full history of changes from all CAs (especially their manifests and CRL updates)
resulted in keeping way too much data.

Instead this relies on the Write-Ahead-Log support. This is very, very, similar
to the event-sourcing used elsewhere, except that it does not guarantee that all
changes are kept. The `WalStore` (Wal: Write-Ahead-Log) only keeps a snapshot and
the latest 'change set's since that snapshot. As with the `AggregateStore` snapshots
are only updated nightly for performance reasons. In fact, it was the 250MB+ nic.br
repository content entity that triggered this code change.

The locking, retrieval and updating are similar to `AggregateStore`, but uses separate
types for all this for historical reasons. A future improvement could be to merge the
types and make it a per instance type (CertAuth, RepositoryAccess, RepositoryContent etc)
choice whether it's fully event-sourced or only recent changes are kept.