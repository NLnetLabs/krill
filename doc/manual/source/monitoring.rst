.. _doc_krill_monitoring:

Monitoring
==========

Prometheus
----------

The HTTPS server in Krill provides endpoints for monitoring the application. A
data format specifically for `Prometheus <https://prometheus.io/>`_ is available
and `dedicated port 9657
<https://github.com/prometheus/prometheus/wiki/Default-port-allocations>`_ has
been reserved.

On the ``/metrics`` path, Krill will expose a lot of details. Generating these metrics
is not particularly hard on Krill, but in case you have many CAs, children or publishers
under your Krill instance you may still want to disable certain metrics to reduce
the amount of data fetched and stored by Prometheus.

General Metrics
~~~~~~~~~~~~~~~

The following are always enabled:

.. code-block:: text

  # HELP krill_server_start unix timestamp in seconds of last krill server start
  # TYPE krill_server_start gauge
  krill_server_start 1631542209

  # HELP krill_version_major krill server major version number
  # TYPE krill_version_major gauge
  krill_version_major 0

  # HELP krill_version_minor krill server minor version number
  # TYPE krill_version_minor gauge
  krill_version_minor 9

  # HELP krill_version_patch krill server patch version number
  # TYPE krill_version_patch gauge
  krill_version_patch 2

  # HELP krill_auth_session_cache_size total number of cached login session tokens
  # TYPE krill_auth_session_cache_size gauge
  krill_auth_session_cache_size 0

  # HELP krill_cas number of cas in krill
  # TYPE krill_cas gauge
  krill_cas 6


CA Metrics
~~~~~~~~~~

There are a number of metrics which use a label like {ca="ca_name"}. You can disable
all of them by setting the following in your configuration file:

.. code-block:: text

  metrics_hide_ca_details = true

Example:

.. code-block:: text

  # HELP krill_ca_parent_success status of last CA to parent connection (0=issue, 1=success)
  # TYPE krill_ca_parent_success gauge
  krill_ca_parent_success{ca="CA1", parent="testbed"} 1
  krill_ca_parent_success{ca="ca", parent="testbed"} 1
  krill_ca_parent_success{ca="CA2", parent="testbed"} 1
  krill_ca_parent_success{ca="testbed", parent="ta"} 1
  krill_ca_parent_success{ca="dummy_ca", parent="testbed"} 1

  # HELP krill_ca_parent_last_success_time unix timestamp in seconds of last successful CA to parent connection
  # TYPE krill_ca_parent_last_success_time gauge
  krill_ca_parent_last_success_time{ca="CA1", parent="testbed"} 1631542800
  krill_ca_parent_last_success_time{ca="ca", parent="testbed"} 1631542800
  krill_ca_parent_last_success_time{ca="CA2", parent="testbed"} 1631542800
  krill_ca_parent_last_success_time{ca="testbed", parent="ta"} 1631542800

  # HELP krill_ca_ps_success status of last CA to Publication Server connection (0=issue, 1=success)
  # TYPE krill_ca_ps_success gauge
  krill_ca_ps_success{ca="CA1"} 1
  krill_ca_ps_success{ca="ca"} 1
  krill_ca_ps_success{ca="CA2"} 1
  krill_ca_ps_success{ca="ta"} 1
  krill_ca_ps_success{ca="testbed"} 1
  krill_ca_ps_success{ca="dummy_ca"} 0

  # HELP krill_ca_ps_last_success_time unix timestamp in seconds of last successful CA to Publication Server connection
  # TYPE krill_ca_ps_last_success_time gauge
  krill_ca_ps_last_success_time{ca="CA1"} 1631542801
  krill_ca_ps_last_success_time{ca="ca"} 1631542802
  krill_ca_ps_last_success_time{ca="CA2"} 1631542802
  krill_ca_ps_last_success_time{ca="ta"} 1631542801
  krill_ca_ps_last_success_time{ca="testbed"} 1631542802

  # HELP krill_ca_ps_next_planned_time unix timestamp in seconds of next planned CA to Publication Server connection (unless e.g. ROAs are changed)
  # TYPE krill_ca_ps_next_planned_time gauge
  krill_ca_ps_next_planned_time{ca="CA1"} 1631600401
  krill_ca_ps_next_planned_time{ca="ca"} 1631600402
  krill_ca_ps_next_planned_time{ca="CA2"} 1631600402
  krill_ca_ps_next_planned_time{ca="ta"} 1631600401
  krill_ca_ps_next_planned_time{ca="testbed"} 1631600402
  krill_ca_ps_next_planned_time{ca="dummy_ca"} 1631543137

Child metrics
~~~~~~~~~~~~~

NOTE: These metrics are only shown if you have any child CAs under your CA(s) in Krill.

By default Krill will also show metrics on child CAs for each CA. If you left the showing CA details
enabled, but you wish to hide these details then you can do so by setting the following directive in
your configuration file:

.. code-block:: text

  metrics_hide_child_details = true

Example:

.. code-block:: text

  # HELP krill_ca_child_success status of last child to CA connection (0=issue, 1=success)
  # TYPE krill_ca_child_success gauge
  krill_ca_child_success{ca="ta", child="testbed"} 1
  krill_ca_child_success{ca="testbed", child="ca"} 1
  krill_ca_child_success{ca="testbed", child="CA1"} 1
  krill_ca_child_success{ca="testbed", child="CA2"} 1

  # HELP krill_ca_child_state child state (see 'suspend_child_after_inactive_hours' config) (0=suspended, 1=active)
  # TYPE krill_ca_child_state gauge
  krill_ca_child_state{ca="ta", child="testbed"} 0
  krill_ca_child_state{ca="testbed", child="ca"} 0
  krill_ca_child_state{ca="testbed", child="CA1"} 0
  krill_ca_child_state{ca="testbed", child="CA2"} 0

  # HELP krill_ca_child_last_connection unix timestamp in seconds of last child to CA connection
  # TYPE krill_ca_child_last_connection gauge
  krill_ca_child_last_connection{ca="ta", child="testbed"} 1631542800
  krill_ca_child_last_connection{ca="testbed", child="ca"} 1631542800
  krill_ca_child_last_connection{ca="testbed", child="CA1"} 1631542800
  krill_ca_child_last_connection{ca="testbed", child="CA2"} 1631542800

  # HELP krill_ca_child_last_success unix timestamp in seconds of last successful child to CA connection
  # TYPE krill_ca_child_last_success gauge
  krill_ca_child_last_success{ca="ta", child="testbed"} 1631542800
  krill_ca_child_last_success{ca="testbed", child="ca"} 1631542800
  krill_ca_child_last_success{ca="testbed", child="CA1"} 1631542800
  krill_ca_child_last_success{ca="testbed", child="CA2"} 1631542800

  # HELP krill_ca_child_agent_total total children per user agent based on their last connection
  # TYPE krill_ca_child_agent_total gauge
  krill_ca_child_agent_total{ca="ta", user_agent="krill/0.9.2-rc1"} 1
  krill_ca_child_agent_total{ca="testbed", user_agent="krill/0.9.2-rc1"} 3


ROA Metrics
~~~~~~~~~~~

By default Krill will also show metrics on ROAs in relation to known BGP announcements
for each CA. If you left the showing CA details enabled, but you wish to hide these details
then you can do so by setting the following directive in your configuration file:

.. code-block:: text

  metrics_hide_roa_details = true

Example:

.. code-block:: text

  # HELP krill_cas_bgp_announcements_valid number of announcements seen for CA resources with RPKI state VALID
  # TYPE krill_cas_bgp_announcements_valid gauge
  krill_cas_bgp_announcements_valid{ca="CA1"} 0
  krill_cas_bgp_announcements_valid{ca="ca"} 2
  krill_cas_bgp_announcements_valid{ca="CA2"} 0
  krill_cas_bgp_announcements_valid{ca="testbed"} 0
  krill_cas_bgp_announcements_valid{ca="ta"} 0
  krill_cas_bgp_announcements_valid{ca="dummy_ca"} 0

  # HELP krill_cas_bgp_announcements_invalid_asn number of announcements seen for CA resources with RPKI state INVALID (ASN mismatch)
  # TYPE krill_cas_bgp_announcements_invalid_asn gauge
  krill_cas_bgp_announcements_invalid_asn{ca="dummy_ca"} 0
  krill_cas_bgp_announcements_invalid_asn{ca="testbed"} 0
  krill_cas_bgp_announcements_invalid_asn{ca="CA2"} 0
  krill_cas_bgp_announcements_invalid_asn{ca="CA1"} 0
  krill_cas_bgp_announcements_invalid_asn{ca="ta"} 0
  krill_cas_bgp_announcements_invalid_asn{ca="ca"} 1

  # HELP krill_cas_bgp_announcements_invalid_length number of announcements seen for CA resources with RPKI state INVALID (prefix exceeds max length)
  # TYPE krill_cas_bgp_announcements_invalid_length gauge
  krill_cas_bgp_announcements_invalid_length{ca="testbed"} 0
  krill_cas_bgp_announcements_invalid_length{ca="dummy_ca"} 0
  krill_cas_bgp_announcements_invalid_length{ca="ta"} 0
  krill_cas_bgp_announcements_invalid_length{ca="CA2"} 0
  krill_cas_bgp_announcements_invalid_length{ca="ca"} 0
  krill_cas_bgp_announcements_invalid_length{ca="CA1"} 0

  # HELP krill_cas_bgp_announcements_not_found number of announcements seen for CA resources with RPKI state NOT FOUND (none of the CA's ROAs cover this)
  # TYPE krill_cas_bgp_announcements_not_found gauge
  krill_cas_bgp_announcements_not_found{ca="CA2"} 0
  krill_cas_bgp_announcements_not_found{ca="ta"} 0
  krill_cas_bgp_announcements_not_found{ca="ca"} 0
  krill_cas_bgp_announcements_not_found{ca="dummy_ca"} 0
  krill_cas_bgp_announcements_not_found{ca="CA1"} 5
  krill_cas_bgp_announcements_not_found{ca="testbed"} 0

  # HELP krill_cas_bgp_roas_too_permissive number of ROAs for this CA which allow excess announcements (0 may also indicate that no BGP info is available)
  # TYPE krill_cas_bgp_roas_too_permissive gauge
  krill_cas_bgp_roas_too_permissive{ca="ca"} 0
  krill_cas_bgp_roas_too_permissive{ca="testbed"} 0
  krill_cas_bgp_roas_too_permissive{ca="CA1"} 0
  krill_cas_bgp_roas_too_permissive{ca="dummy_ca"} 0
  krill_cas_bgp_roas_too_permissive{ca="ta"} 0
  krill_cas_bgp_roas_too_permissive{ca="CA2"} 0

  # HELP krill_cas_bgp_roas_redundant number of ROAs for this CA which are redundant (0 may also indicate that no BGP info is available)
  # TYPE krill_cas_bgp_roas_redundant gauge
  krill_cas_bgp_roas_redundant{ca="ta"} 0
  krill_cas_bgp_roas_redundant{ca="testbed"} 0
  krill_cas_bgp_roas_redundant{ca="ca"} 0
  krill_cas_bgp_roas_redundant{ca="dummy_ca"} 0
  krill_cas_bgp_roas_redundant{ca="CA1"} 0
  krill_cas_bgp_roas_redundant{ca="CA2"} 0

  # HELP krill_cas_bgp_roas_stale number of ROAs for this CA for which no announcements are seen (0 may also indicate that no BGP info is available)
  # TYPE krill_cas_bgp_roas_stale gauge
  krill_cas_bgp_roas_stale{ca="CA1"} 0
  krill_cas_bgp_roas_stale{ca="CA2"} 0
  krill_cas_bgp_roas_stale{ca="ca"} 0
  krill_cas_bgp_roas_stale{ca="ta"} 0
  krill_cas_bgp_roas_stale{ca="testbed"} 0
  krill_cas_bgp_roas_stale{ca="dummy_ca"} 0

  # HELP krill_cas_bgp_roas_total total number of ROAs for this CA
  # TYPE krill_cas_bgp_roas_stale gauge
  krill_cas_bgp_roas_total{ca="dummy_ca"} 0
  krill_cas_bgp_roas_total{ca="ca"} 3
  krill_cas_bgp_roas_total{ca="CA1"} 0
  krill_cas_bgp_roas_total{ca="ta"} 0
  krill_cas_bgp_roas_total{ca="testbed"} 0
  krill_cas_bgp_roas_total{ca="CA2"} 0


Publication Server Metrics
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following metrics are always enabled if you have an active Publication Server:

.. code-block:: text

  # HELP krill_repo_publisher number of publishers in repository
  # TYPE krill_repo_publisher gauge
  krill_repo_publisher 6

  # HELP krill_repo_rrdp_last_update unix timestamp in seconds of last update by any publisher
  # TYPE krill_repo_rrdp_last_update gauge
  krill_repo_rrdp_last_update 1631542802

  # HELP krill_repo_rrdp_serial RRDP serial
  # TYPE krill_repo_rrdp_serial counter
  krill_repo_rrdp_serial 5

By default per publisher (publishing CA) metrics are also included, this can be
disabled by setting the following directive in your configuration file:

.. code-block:: text

  metrics_hide_publisher_details = true

Example:

.. code-block:: text

  # HELP krill_repo_objects number of objects in repository for publisher
  # TYPE krill_repo_objects gauge
  krill_repo_objects{publisher="ta"} 3
  krill_repo_objects{publisher="mos-eisley"} 4
  krill_repo_objects{publisher="testbed"} 5
  krill_repo_objects{publisher="CA1"} 2
  krill_repo_objects{publisher="CA2"} 2
  krill_repo_objects{publisher="dummy_ca"} 0

  # HELP krill_repo_size size of objects in bytes in repository for publisher
  # TYPE krill_repo_size gauge
  krill_repo_size{publisher="ta"} 7592
  krill_repo_size{publisher="mos-eisley"} 10056
  krill_repo_size{publisher="testbed"} 9988
  krill_repo_size{publisher="CA1"} 3744
  krill_repo_size{publisher="CA2"} 3744
  krill_repo_size{publisher="dummy_ca"} 0

  # HELP krill_repo_last_update unix timestamp in seconds of last update for publisher
  # TYPE krill_repo_last_update gauge
  krill_repo_last_update{publisher="ta"} 1631542801
  krill_repo_last_update{publisher="mos-eisley"} 1631542802
  krill_repo_last_update{publisher="testbed"} 1631542802
  krill_repo_last_update{publisher="CA1"} 1631542801
  krill_repo_last_update{publisher="CA2"} 1631542802
  krill_repo_last_update{publisher="dummy_ca"} 1628062124


Stats Endpoints
---------------

The monitoring service has a number of additional endpoints which can be accessed
without the need for authentication on the following paths:


  :/stats/info:
       Returns the Krill version and timestamp when the daemon was started.

  :/stats/cas:
       Returns stats on your CAs, including an analysis of ROA configurations
       based on known BGP announcements.

  :/stats/repo:
      Returns stats on the repository, if enabled. This includes publisher
      stats: number and size of objects and last connection time.
