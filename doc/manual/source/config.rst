.. _doc_krill_config:
.. highlight:: none

Configuration options
=====================

Introduction
------------

Krill can be tweaked using a lot of options in the config file. The config
file can be found in `/etc/krill.conf`. Default installations of Krill set 
three options: `admin_token`, `storage_uri`, and `log_type`. Changes to the
config file will be applied after Krill is restarted. Most of the time you 
will not need to change any of these configuration variables. The
configuration file format is TOML.

Options
-------


**ip**

IP address(es) Krill listens to. By default Krill listens to 127.0.0.1. 
We recommend that you keep this setting and use a proxy server such as NGINX 
or Apache if you must make your Krill instance accessible remotely.

Can be set to one or more IP addresses, e.g.:

.. code-block:: TOML

    ip = "127.0.0.1"
    ip = ["127.0.0.1", "::1"]

**port**

Port number Krill listens on, by default 3000. This applies to all IP 
addresses.

.. code-block:: TOML

    port = 3000


**https_mode**

Specify the HTTPS mode. Krill supports three modes:

"generate" (DEFAULT)

Krill will generate a key pair and create a self-signed certificate
if no previous key pair or certificate is found. File names used
are data_dir/ssl/key.pem and data_dir/ssl/cert.pem respectively.

"existing"

Krill expects an existing key pair and certificate in the same
locations where it would otherwise store its generated key pair
and self-signed certificate.

"disable"

Krill will use plain HTTP.

This mode is not recommended as HTTPS adds little overhead, and
even with a self-signed certificate provides better security
out of the box. We recommend STRONGLY that you do not use this 
option if your Krill instance is configured to bind to a public 
IP address.

*NOTE*: Even if you use "disable" here, Krill still insists on
        using HTTPS for its service_uri. See below.

.. code-block:: TOML

    https_mode = "generate"


**unix_socket_enabled**

Whether UNIX socket support is enabled. By default this is true, unless you 
are on a non-UNIX system. This is the default way krillc communicates with
Krill. 

.. code-block:: TOML

    unix_socket_enabled = true


**unix_socket**

The path to the UNIX socket. The default path is /run/krill/krill.sock. If not
started using the systemd service, this path may require root access. This
path is also used by default by krillc. 

.. code-block:: TOML

    unix_socket = "/run/krill/krill.sock"


**unix_users**

The mapping of UNIX users to Krill roles. The default maps the root user to
admin. Can use any role defined in Krill, see also **auth_roles**.

.. code-block:: TOML

    unix_users = {"root": "admin"}


**storage_uri**

The path to where Krill stores its data. Must be set. Please ensure only one
Krill instance uses this path. This path should be absolute. The default
for Krill installations is /var/lib/krill/data/

.. code-block:: TOML

    storage_uri = "/var/lib/krill/data/"


**use_history_cache**

Krill keeps meta-information on all past changes for each CA
and the Publication Server. This information is cached by default
to ensure that the history (audit log) API is fast.

However, this data can add up over time, so operators of
instances with many CAs or a lot of historical may choose
to turn this off to save memory. Note that memory will still
be used temporarily in case the history API is accessed.

.. code-block:: TOML

    use_history_cache = true


**tls_keys_dir**

Specify the location of the TLS directory for Krill's built-in HTTPS server. 
By default it maps to $storage_uri/ssl.

.. code-block:: TOML

    tls_keys_dir = "/etc/ssl/krill"


**repo_dir**

This is the directory used by the Krill Publication Server for the publication 
of RPKI objects. By default it maps to $storage_uri/repo.

.. code-block:: TOML

    repo_dir = "/mnt/share/repo"


**ta_support_enabled**

Whether this Krill instance should have support to run as a Trust Anchor (TA).
By default false. You probably don't want to touch this, but if you do, see 
:ref:`_doc_krill_trust_anchor`.

.. code-block:: TOML

    ta_support_enabled = false


**ta_signer_enabled**

Whether this Krill instance can initialise and send Trust Anchor (TA) signer
commands. By default false. You probably don't want to touch this, but if you 
do, see :ref:`_doc_krill_trust_anchor`.

.. code-block:: TOML

    ta_signer_enabled = false


**pid_file**

The path to the PID file for Krill. Defaults to $storage_uri/krill.pid

.. code-block:: TOML

    pid_file = "/run/krill/krill.pid"


**service_uri**


**log_level**


**log_type**


**log_file**


**syslog_facility**


**admin_token**


**auth_type**


**auth_users**


**auth_openidconnect**


**auth_roles**


**default_signer**


**one_off_signer**


**signer_probe_retry_seconds**


**signers**


**ca_refresh_seconds**


**ca_refresh_jitter_seconds**


**ca_refresh_parents_batch_size**


**suspend_child_after_inactive_seconds**


**suspend_child_after_inactive_hours**


**post_limit_api**


**post_limit_rfc8181**


**rfc8181_log_dir**


**post_limit_rfc6492**


**post_protocol_msg_timeout_seconds**


**rfc6492_log_dir**


**bgp_api_enabled**


**bgp_api_uri**


**bgp_api_cache_seconds**


**roa_aggregate_threshold**


**roa_deaggregate_threshold**


.. 
    Start issuance_timing

**timing_publish_next_hours**


**timing_publish_next_jitter_hours**


**timing_publish_hours_before_next**


**timing_child_certificate_valid_weeks**


**timing_child_certificate_reissue_weeks_before**


**timing_roa_valid_weeks**


**timing_roa_reissue_weeks_before**


**timing_aspa_valid_weeks**


**timing_aspa_reissue_weeks_before**


**timing_bgpsec_valid_weeks**


**timing_bgpsec_reissue_weeks_before**


..
    End issuance_timing


..
    Start rrdp_updates_config

**rrdp_delta_files_min_nr**


**rrdp_delta_files_min_seconds**


**rrdp_delta_files_max_nr**


**rrdp_delta_files_max_seconds**


**rrdp_delta_interval_min_seconds**


**rrdp_files_archive**


..
    End rrdp_updates_config


..
    Start metrics

**metrics_hide_ca_details**


**metrics_hide_child_details**


**metrics_hide_publisher_details**


**metrics_hide_roa_details**


..
    End metrics


**testbed**

*ta_aia*


*ta_uri*


*rrdp_base_uri*


*rsync_jail*


**benchmark**

*cas*


*ca_roas*


**ta_timing**

*certificate_validity_years*


*issued_certificate_validity_weeks*


*issued_certificate_reissue_weeks_before*


*mft_next_update_weeks*


*signed_message_validity_days*


