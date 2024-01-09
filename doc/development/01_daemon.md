Krill Daemon Setup
==================

Overview
--------

Here we will explain how the Krill daemon is layered and handles requests. This layering works the
same way whether the daemon is running as a Certification Authority, Publication Server, or both. The
components described here are responsible for:
* Parsing configuration
* Starting Krill
* Triggering and executing data migrations on upgrade
* Handling HTTPS requests
* Handling authorization
* Background jobs

Ultimately the actual requests coming from either the API or background jobs are dispatched to either
the `CaServer` or `RepositoryManager` which are set up using the provided config (e.g. instructing these components
where their data is stored). Theoretically those components could also be wrapped in a different way in
the future, e.g. to support serverless setups using AWS Lambda functions, provided of course that authorization,
configuration, and concurrency are handled.

Binaries
--------

The project includes the following binaries:
* `krill` is used to start a Krill daemon.
* `krillc` is the CLI which uses the daemon's API.
* `krillta` is used for the (offline) TA Signer, and access the TA Proxy through the API.
* `krillup` can be used to test data migrations in isolation.

HTTPS Server
------------

Krill uses [hyper](https://hyper.rs/) as an HTTPS server. The set up for this is done in the `start_krill_daemon`
function in `src/daemon/http/server.rs`. This function performs the following steps:

* Creates the PID file.
* Verifies that the configured data directory is usable.
* Calls 'pre-start' upgrades before state is built. (e.g. migrate data structures).
* Instantiates a `KrillServer`, which will guard all state.
* Calls 'post_start_upgrade' to trigger any upgrade related runtime actions (may be none).
* Gets the shared `Scheduler` from `KrillServer` and runs so it can pick up tasks.
* Creates a self-signed TLS certificate, unless one was prepared earlier.
* Builds a `hyper` server which then connects to the configured port and handles connections.
* This server keeps running until the `KrillServer` or `Scheduler` is terminated.

Note that the `hyper` server itself is stateless. For this it relies on an `Arc<KrillServer>` which can
be cloned cheaply whenever a request is processed. So, we use hyper for the following:
* Get authentication/authorization information from the request (header/cookies dependent on config).
* Serve static content for the Krill UI.
* Map requests to API code in `KrillServer` and serve responses.

> Note that for higher level testing we bypass the Krill binaries, and call the function to start the
> HTTPS server directly, with appropriate configuration settings. Have a look at `tests/functional.rs`
> for an example.


KrillServer
-----------

This is the main daemon component that runs Krill. It won't do actual processing, but it is responsible for running and
mapping calls to the following components (we will describe each component in more detail later):

| Element             | Code Path                     | Responsibility                                              |
| ------------------- | ----------------------------- | ----------------------------------------------------------- |
| `CaManager`         | src/daemon/ca/manager.rs      | Manages Krill CAs.                                          |
| `RepositoryManager` | src/pubd/manager.rs           |  Manages access to and content of the repository.            |
| `Scheduler`         | src/daemon/scheduler.rs       | Schedules and executes background jobs.                     |
| `Authenticator`      | src/daemon/auth/authentication.rs | Verifies authentication for API requests. |
| `BgpAnalyser`       | src/commons/bgp/analyser.rs   | Compares authorizations to BGP, downloads RIS whois dumps.  |

