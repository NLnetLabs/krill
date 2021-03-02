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
the `CaServer` or `PubServer` which are set up using the provided config (e.g. instructing these components
where their data is stored). Theoretically those components could also be wrapped in a different way in
future, e.g. to support serverless setups using lambda functions, provided of course that authorization,
configuration, and concurrency are handled.

Binaries
--------

The project includes two binaries which can be used to start a Krill daemon. These binaries are fairly
thin executables which are responsible for parsing a configuration file, setting the operation mode, and
then starting the `HTTPS Server` which includes the real `KrillServer`.

Typically the `krill` binary is used to start Krill as a Certification Authority server, while `krillpubd`
is used to start it as a dedicated Publication Server. That said, mixed operation is also possible as we
will explain below.


HTTPS Server
------------

Krill uses [hyper](https://hyper.rs/) as an HTTPS server. The set up for this is done in the `start_krill_daemon`
function in `src/daemon/http/server.rs`. This function performs the following steps:

* Creates the PID file.
* Verifies that the configured data directory is usable.
* Calls 'pre-start' upgrades before state is built. (e.g. migrate data structures)
* Instantiates a `KrillServer`, which will guard all state.
* Creates a self-signed TLS certificate, unless one was prepared earlier
* Builds a `hyper` server which then connects to the configured port and handles connections.
* This server keeps running until the Krill binary is terminated.

Note that the `hyper` server itself is stateless. For this it relies on an `Arc<KrillServer>` which can
be cloned cheaply whenever a request ir processed. So, we use hyper for the following:
* Get authentication/authorization information from the request (header/cookies dependent on config)
* Serve static content for the Krill UI.
* Map requests to API code in `KrillServer` and serve responses

> Note that for higher level testing we bypass the Krill binaries, and call the function to start the
> HTTPS server directly, with appropriate configuration settings. Have a look at `tests/functional.rs`
> for an example.


KrillServer
-----------

This is the main daemon component that runs Krill. It won't do actual processing, but it is responsible for running and
mapping calls to the following components (we will describe each component in more detail later):

| Element         | Code Path                        | Responsibility                                                         |
|-----------------|----------------------------------|------------------------------------------------------------------------|
| `CaServer`      | src/daemon/ca/server.rs          | Manages Krill CAs.                                                     |
| `PubServer`     | src/pubd/pubserver.rs            | Publication Server.                                                    |
| `Scheduler`     | src/daemon/scheduler.rs          | Schedules and executes background jobs.                                |
| `Authorizer`    | src/daemon/auth/authorizer.rs    | Verifies authentication and authorization for API requests.            |
| `BgpAnalyser`   | src/commons/bgp/analyser.rs      | Compare authorizations to BGP, download RIS whois dumps.               |


KrillMode
---------

The `KrillServer` elements are initialised based on which ```KrillMode``` is selected. The following modes are possible:

| KrillMode | Operation |
|-|-|
| Pubd | The KrillServer will have Some(PubServer), but no (None) CaServer |
| Ca | The KrillServer will have Some(CaServer), but no (None) PubServer |
| Mixed | The KrillServer will have both a CaServer and a PubServer |
| Testbed | Krill runs in testmode. It will have a PubServer, CaServer **AND** an embedded TA |

If Krill is started with the `krillpubd` binary, then the mode will always be ```KrillMode::Pubd```. If it is started with the
`krill` binary, then the mode will *normally* be ```KrillMode::Ca```. However, for backward compatibility with existing deployments,
the KrillServer will change this mode to ```KrillMode::Mixed``` if it finds that a data directory exists for an initialised
Publication Server with at least one active `Publisher`. ```KrillMode::Testbed``` can be forced is the user sets the URIs for the test
Publication Server rsync and RRDP URI base, using the following two environment variables: `KRILL_TESTBED_RSYNC` and `KRILL_TESTBED_RRDP`.


