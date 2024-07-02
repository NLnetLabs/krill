.. _doc_krill_manage_bgpsec:

Manage BGPSec Router Certificates
=================================

Krill supports signing :RFC:`8209` BGPSec Router Certificates as of
release 0.10.0. These certificates are used publish the router keys for
:RFC:`8205` BGPSec protocol capable routers. Unfortunately, this protocol
is not (yet) supported by many routers. We hope that by adding support
for signing router certificates to the Krill CLI and API we can help
support the future development and deployment of BGPSec. However,
because BGPSec deployment is still lacking we have chosen not to support
this in the UI at this time. But, of course, we are more than willing to
add this in future if BGPSec deployment takes off and / or there is user
demand for this.

The CLI commands are documented :ref:`here<cmd_krillc_bgpsec>`.
