# Krill Developper Documentation

> NOTE: If you are looking for Krill user or operational documentation, please have
> a look [here](https://rpki.readthedocs.io/en/latest/krill/index.html).

Here you can find documentation for Krill development.


# HTTPS Server

The folllowing components are responsible running the Krill process:

| Element         | Code Path                        | Responsibility                                                         |
|-----------------|----------------------------------|------------------------------------------------------------------------|
| `krill.rs`      | bin/krill.rs                     | Binary to start Krill in Certification Authority mode.                 |
| `krillpubd.rs`  | bin/krillpubd.rs                 | Binary to start Krill in Publication Server mode.                      |
| `server.rs`     | src/daemon/http/server.rs        | HTTPS, authorization, request routing to API code in KrillServer       |
| `KrillServer`   | src/daemon/krillserver.rs        | Server for the Krill API and background jobs                           |


Generally speaking the binary used to start Krill will make sure that command line options, and the configuration file are
parsed and verified. Then the hyper.rs based server is started, which does the following:
* Creates the PID file.
* Verifys that the configured data directory is usable.
* Calls 'pre-start' upgrades before state is built. (e.g. migrate data structures)
* Instantiates a KrillServer, which will guard all state. (server.rs itself is stateless)
* Creates a self-signed TLS certificate, unless one was prepared earlier
* Connects to the configured port and handles connections.
* The stateful KrillServer is wrapped in an ```Arc``` and copied between requests.

When it comes to handling incoming requests this server will do the following:
* Get authentication/authorization information from the request (header/cookies dependent on config)
* Serve static content for the Krill UI.
* Map requests to API code in KrillServer and serve responses



# KrillServer

This is the main daemon component that runs Krill. It won't do actual processing, but it is responsible for running and
mapping calls to the following components (we will describe each component in more detail later):

| Element         | Code Path                        | Responsibility                                                         |
|-----------------|----------------------------------|------------------------------------------------------------------------|
| `CaServer`      | src/daemon/ca/server.rs          | Manages Krill CAs.                                                     |
| `PubServer`     | src/pubd/pubserver.rs            | RPKI Publication Server.                                               |
| `Scheduler`     | src/daemon/scheduler.rs          | Schedules and executes background jobs.                                |
| `Authorizer`    | src/daemon/auth/authorizer.rs    | Verifies authentication and authorization for API requests.            |
| `BgpAnalyser`   | src/commons/bgp/analyser.rs      | Comparte authorizations to BGP, download RIS whois dumps.              |


## KrillMode

Components are initialised based on which ```KrillMode``` is selected. The following modes are possible:

| KrillMode | Operation |
|-|-|
| Pubd | The KrillServer will have Some(PubServer), but no (None) CaServer |
| Ca | The KrillServer will have Some(CaServer), but no (None) PubServer |
| Mixed | The KrillServer will have both a CaServer and a PubServer |
| Testbed | Krill runs in testmode. It will have a PubServer, CaServer **AND** an embedded TA |

If Krill is started with the `krillpubd` binary, then the mode will always be ```KrillMode::Pubd```. If it is started with the
`krill` binary, then the mode will *normally* be ```KrillMode::Ca```. However, for backward compatibility with existing deployments,
the KrillServer will change this mode to ```KrillMode::Mixed``` if it finds that a data directory exists for an initialised
Publication Server with at least one active `Publisher`. The testmode can be forced is the user sets the URIs for the test
Publication Server rsync and RRDP URI base, using the following two environment variables: `KRILL_TESTBED_RSYNC` and `KRILL_TESTBED_RRDP`.


