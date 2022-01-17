# HSM: Connectivity

Unlike the original OpenSSL based signer in Krill, the PKCS#11 and KMIP signers connect to 
cryptographic token systems that exist outside of Krill. That connection can fail, either
from the start or at some point while Krill is running.

As stated this issue is common to the PKCS#11 and KMIP signers. As much as possible the
overlap in connection handling functionality has been extracted into common code that is
shared by both signer implementations. Some of the code however is very similar but not quite
the same and is thus "duplicated" in both signers but follows the same pattern.

## Executing a request via a "connection"

For KMIP a request to the backend literally involves a TCP connection to the KMIP server.
For PKCS#11 a network connection may or may not be made, Krill has no way of knowing, Krill
only invokes a PKCS#11 library function, but conceptually a connection is still being made
from Krill to the backend.

Both implementations have a `fn with_conn(&self, desc: &str, do_something_with_conn: F)`
function. This function obtains (and sets up if necessary) a connection to the backend and
then passes the "connection" instance to a callback which uses it to execute a request.

Both implementations implement (in the same way but with almost duplicate code) a retry with 
backoff strategy if the request fails and the failure is transient rather than permanent. The
logic to decide which types of failure are transient and which are permanent, and the concept
of what a "connection" is, are specific to each implementation.

## Probe status

Both implementations share the concept of probe "status" and of a backend moving
from one status to another. A backend must be successfully probed before it can be used.
The code for this **is** factored out to the `StatefulProbe` type
defined in the  `probe.rs` module. However, a key function defined in the module,
`fn status(&self, probe: F)`, takes a callback for which the PKCS#11 and KMIP signers each have
their own specific implementation.

A "probe" represents the idea of something used to see if a signer backend is reachable,
usable & ready. As such a `StatefulProbe` is an enum which can be in one of three states: `Probing`, `Unusable` or `Usable`.

Initially a probe is in the `Probing` state which carries with it the details necessary to
establish an initial connection to the signer backend. Whenever the `fn status()` of a probe
in `Probing` status is queried it will "send" a probe and if necessary based on the result of
the probe will move to either the `Usable` or `Unusable` state.

When in the `Probing` state a new "probe" will only be sent at most every N seconds. In between
"probes" a call to `fn status()` will return the last known state of the probe. This is to avoid
repeated rapid attempts to re-probe the signer backend when it has already been determined that
it is not yet available/ready but might soon become so. Probes are only "sent" during the probing
status, they are not sent once the probe moves to the (un)usable status.

A probe in `Unusable` state cannot now or ever be used during the lifetime of the Krill process.
It has probed the signer backend and found it permanently lacking.

A probe in `Usable` state carries with it the details necessary to communicate with the backend
via an established connection and/or to (re)establish connections as necessary, and contains
some metadata describing the backend being connected to which was determined when moving from
the `Probing` to the `Usable` state.

Note that probe status never moves backwards in the lifetime of a single Krill process from (un)usable
to probing.
