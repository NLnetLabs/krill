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
configuration file format is TOML. In short, it consists of a sequence of 
key-value pairs, each on its own line. Strings are to be enclosed in double 
quotes. Lists can be given by enclosing a comma-separated list of values in 
square brackets.

**Please note:** square brackets in TOML indicate a *table*. If you add e.g.
`[auth_users]` to your configuration, all options below it will be interpreted
as part of *auth_users* until another table is started. Any option that is not
part of a table (which is most options) should be defined before the first
table. Apart from that options are not dependent on their order.


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

"generate" (default)

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

Even if you use "disable" here, Krill still insists on using HTTPS for its 
service_uri. See below.

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
:ref:`doc_krill_trust_anchor`.

.. code-block:: TOML

    ta_support_enabled = false


**ta_signer_enabled**

Whether this Krill instance can initialise and send Trust Anchor (TA) signer
commands. By default false. You probably don't want to touch this, but if you 
do, see :ref:`doc_krill_trust_anchor`.

.. code-block:: TOML

    ta_signer_enabled = false


**pid_file**

The path to the PID file for Krill. Defaults to $storage_uri/krill.pid

.. code-block:: TOML

    pid_file = "/run/krill/krill.pid"


**service_uri**

Specify the base public service URI hostname and port.

The default service URI is set to https://localhost:3000/. This is fine
for setups where you use Krill to run your own CA only. You do not need to
set this to enable remote access to the UI or API (e.g. for using the CLI
remotely). Simply setting up a proxy suffices for this.

However, if you are serving as a parent CA or Publication Server that
needs to be accessible by remote CAs, then you will need to tell your
Krill instance what its public (base) URI will be, so that it can include
the proper URIs in responses to those CAs. HTTPS is required for this.

At present this MUST be an https URI with a hostname and optional port
number only. It is not allowed to use a Krill specific path prefix.

Make sure to include a backslash at the end.

Krill UI, API and service URIs will be derived as follows:

* <service_uri>api/v1/...                (api)  
* <service_uri>rfc6492                   (for remote children)  
* <service_uri>...                       (various UI resources)  

.. code-block:: TOML

    service_uri = "https://localhost:3000/"


**log_level**

The maximum log level to for which to log messages. Defaults to warn.
Options are "off", "error", "warn", "info", "debug", and "trace". We advise
against using "debug" or "trace" in production.

.. code-block:: TOML

    log_level = "warn"


**log_type**

Where to log to. One of "stderr" for stderr, "syslog" for syslog, or "file" 
for a file. If "file" is given, the "log_file" field needs to be given too.
Defaults to syslog on Krill installations.

.. code-block:: TOML

    log_type = "syslog"


**log_file**

The path to the file to log to if file logging is used. This should be an 
absolute path. If the path is relative, it is relative to the current working 
directory from which the binary is executed.

.. code-block:: TOML

    log_file = "/var/lib/krill/krill.log"


**syslog_facility**

The syslog facility to log to if syslog logging is used. Defaults to "daemon".

.. code-block:: TOML

    syslog_facility = "daemon"


**admin_token**

Define an admin token that can be used to interact with the API. This token is
used to access the Krill API and the Krill server when not using UNIX sockets.

If you do not specify a value here, the server will insist that you
provide a token as an environment variable with the key
"KRILL_ADMIN_TOKEN".

Krill installations come with a randomly generated 32 character string as a 
token. Krill does not enforce any password requirements but do think twice
before using "1234" :-)

.. code-block:: TOML

    admin_token = "correct-horse-battery-staple"


**auth_type**

Which kind of authentication to use, primarily for the web interface. The
**admin_token** will always work through the API.

Currently there are three options:

"admin-token" (default)

Use the admin_token only.

"config-file"

Specify the users and their permissions in the **auth_users** in the config 
file. 

"openid-connect"

Use an OpenID connect provider for authentication, see **auth_openidconnect**.

.. code-block:: TOML

    auth_type = "admin-token"


**auth_users**

If **auth_type** is set *config-file*, this provides the list of users that
can authenticate with Krill. These users can be generated using 
`krillc config user`. The role matches that of **auth_roles**. See also
:ref:`doc_krill_multi_user_config_file_provider`.

.. code-block:: TOML

    [auth_users]
    "joe@example.com" = { role="admin", password_hash="...", salt="..." }
    "jill@example.com" = { role="read-ca1", password_hash="...", salt="..." }


**auth_openidconnect**

If **auth_type** is set *openid-connect*, this provides the configuration for
OpenID connect that can then be used for connections. You will want to look at
:ref:`doc_krill_multi_user_openid_connect_provider` for details.

+---------------------+-------------+--------------------------------------------+
| Field               | Mandatory?  | Notes                                      |
+=====================+=============+============================================+
| issuer_url          | Yes         | Provided by your OpenID Connect provider.  |
|                     |             | This is the URL of the provider discovery  |
|                     |             | endpoint. "/.well-known/openid_            |
|                     |             | configuration" will be appended if not     |
|                     |             | present. Krill will fetch the OpenID       |
|                     |             | Connect Discovery 1.0 compliant JSON when  |
|                     |             | starting. Krill will fail to start if the  |
|                     |             | URL does not match the "issuer" value in   |
|                     |             | the discovery response or if the endpoint  |
|                     |             | cannot be contacted.                       |
+---------------------+-------------+--------------------------------------------+
| client_id           | Yes         | Provided by your OpenID Connect provider.  |
+---------------------+-------------+--------------------------------------------+
| client_secret       | Yes         | Provided by your OpenID Connect provider.  |
+---------------------+-------------+--------------------------------------------+
| insecure            | No          | Defaults to false. Setting to true         |
|                     |             | disables verification of signatures from   |
|                     |             | the provider token ID endpoint. Setting    |
|                     |             | this to true may allow attackers to modify |
|                     |             | provider responses undetected. Strongly    |
|                     |             | discouraged.                               |
+---------------------+-------------+--------------------------------------------+
| extra_login_scopes  | No          | Provider specific. Defaults to "". A       |
|                     |             | comma-separated list of OAuth 2.0 scopes   |
|                     |             | passed when directing a user to login.     |
|                     |             | Scopes request additional user details.    |
|                     |             | "profile" commonly enables email and other |
|                     |             | personal details. If the provider supports |
|                     |             | the "email" scope, it is requested         |
|                     |             | automatically.                             |
+---------------------+-------------+--------------------------------------------+
| extra_login_params  | No          | A { key=value, ... } map of extra HTTP     |
|                     |             | query parameters sent with the             |
|                     |             | authorization request. Supported params    |
|                     |             | vary by provider. prompt=login is sent     |
|                     |             | automatically unless disabled via          |
|                     |             | prompt_for_login. May also be specified as |
|                     |             | a TOML table. Example:                     |
|                     |             |                                            |
|                     |             |   [openid_connect.extra_login_params]      |
|                     |             |   display=popup                            |
|                     |             |   ui_locales="fr-CA fr en"                 |
+---------------------+-------------+--------------------------------------------+
| prompt_for_login    | No          | Defaults to true. Setting to false         |
|                     |             | disables sending prompt=login. Allows      |
|                     |             | specifying another prompt value through    |
|                     |             | extra_login_params. Supported values:      |
|                     |             | "none", "login", "consent", "              |
|                     |             | select_account".                           |
+---------------------+-------------+--------------------------------------------+
| logout_url          | No          | A URL to redirect the user to for logout.  |
|                     |             | Usually unnecessary if discovery metadata  |
|                     |             | provides logout details. Otherwise must be |
|                     |             | specified. If discovery shows no supported |
|                     |             | logout mechanism and no logout_url is set, |
|                     |             | Krill redirects users to the UI index page |
|                     |             | to restart login.                          |
+---------------------+-------------+--------------------------------------------+
| id_claims           | No          | A list for extracting the user ID from     |
|                     |             | claim values. Typically provided as TOML   |
|                     |             | array tables. If missing, the "email"      |
|                     |             | claim is used as the user ID.              |
+---------------------+-------------+--------------------------------------------+
| role_claims         | No          | A list for extracting the user role from   |
|                     |             | claim values. Typically provided as TOML   |
|                     |             | array tables. If missing, the "role"       |
|                     |             | claim is used as the user's role.          |
+---------------------+-------------+--------------------------------------------+


.. code-block:: TOML

    [auth_openidconnect]
    issuer_url = "..."
    client_id = "..."
    client_secret = "..."
    insecure = false
    extra_login_scopes = ["..."]
    extra_login_params = ["..."]
    prompt_for_login = false
    logout_url = "..."

    [[auth_openidconnect.id_claims]]
    claim = "email"

    [[auth_openidconnect.role_claims]]
    claim = "email"
    match = "^.+@example\\.org$"
    subst = "admin"


**auth_roles**

Auth roles determine what permissions a role can has. Three are defined by
default:
*admin*: Allows full acess to everything
*readonly*: Allows list and read access to everything.
*readwrite*: Allows read, create, update, and delete access to everything.

These are the fields for a role:

+--------------+-------------+--------------------------------------------------+
| Field        | Mandatory?  | Notes                                            |
+==============+=============+==================================================+
| permissions  | Yes         | A list of permissions to be granted to the role. |
|              |             | The following permissions exist:                 |
|              |             |                                                  |
|              |             |   login                                          |
|              |             |                                                  |
|              |             | Access to the publication server:                |
|              |             |                                                  |
|              |             |   pub-admin, pub-list, pub-read, pub-create,     |
|              |             |   pub-delete                                     |
|              |             |                                                  |
|              |             | Access to CAs:                                   |
|              |             |                                                  |
|              |             |   ca-list, ca-read, ca-create, ca-update,        |
|              |             |   ca-admin, ca-delete                            |
|              |             |                                                  |
|              |             | Access to the ROAs of a CA:                      |
|              |             |                                                  |
|              |             |   routes-read, routes-update, routes-analysis    |
|              |             |                                                  |
|              |             | Access to the ASPAs of a CA:                     |
|              |             |                                                  |
|              |             |   aspas-read, aspas-update, aspas-analysis       |
|              |             |                                                  |
|              |             | Access to the router keys of a CA:               |
|              |             |                                                  |
|              |             |   bgpsec-read, bgpsec-update                     |
+--------------+-------------+--------------------------------------------------+
| cas          | No          | A list of CA handles that the role should grant  |
|              |             | access to. If missing, access is granted to all  |
|              |             | CAs.                                             |
+--------------+-------------+--------------------------------------------------+


.. code-block:: TOML

    [auth_roles]
    "bgpsec" = { permissions = ["bgpsec-read", "bgpsec-update"], cas = ["myca"] }


**default_signer**

The signer will be used to generate new long-term key pairs. Only one signer 
may be designated as the default. If only one signer is defined it will be the 
default. If more than one signer is defined one must be explicitly set as the 
default. The name here refers to the signer configured in **signers**.

.. code-block:: TOML
    default_signer = "My signer"


**one_off_signer**

The signer will be used to generate, sign with and destroy one-off key pairs. 
Only one signer may be designated as the oneoff signer. When not specified an 
OpenSSL signer will be used for this.

.. code-block:: TOML
    default_signer = "My other signer"


**signer_probe_retry_seconds**

When initially connecting to the signer on first use after Krill startup, wait
 at least N seconds between attempts to connect and test the signer for 
 compatibility with Krill. Defaults to 30 seconds.

.. code-block:: TOML
    signer_probe_retry_seconds = 30


**signers**

Krill supports three types of signer. See also :ref:`doc_krill_hsm`:

* *OpenSSL*: Uses the OpenSSL library installed on the host O/S. On older
operating systems it might be that a newer version of OpenSSL than is supported
by the host O/S has been compiled into Krill itself and will be used instead.
* *PKCS#11*: Uses a PKCS#11 v2.20 conformant library file from the filesystem.
How the library handles the requests on behalf of Krill is library specific. A
library such as SoftHSMv2 contains all of the code needed to handle the request
and stores generated keys on the host filesystem. Libraries provided by well
known HSM vendors will dispatch requests to one or a cluster of hardware 
security modules connected either physically or by network connection to the
host on which Krill is running.
* *KMIP*: Makes TLS encrypted TCP connections to an operator specified server
running a KMIP v1.2 conformant service.


.. code-block:: TOML
    [[signers]]
    type = "OpenSSL"
    name = "Signer 1"

    [[signers]]
    type = "OpenSSL"
    name = "Signer 2"
    keys_path = "/tmp/keys"

    [[signers]]
    type = "PKCS#11"
    name = "Kryptus via PKCS#11"
    lib_path = "/usr/local/lib/kryptus/libknetpkcs11_64/libkNETPKCS11.so"
    user_pin = "xxxxxx"
    slot = 313129207

    [[signers]]
    type = "PKCS#11"
    name = "SoftHSMv2 via PKCS#11"
    lib_path = "/usr/local/lib/softhsm/libsofthsm2.so"
    user_pin = "xxxx"
    slot = 0x12a9f8f7
    public_key_attributes = {
    CKA_PRIVATE = false
    }

    [[signers]]
    type = "KMIP"
    name = "Kryptus via KMIP"
    host = "my.hsm.example.com"
    port = 5696
    server_ca_cert_path = "/path/to/some/ca.pem"
    username = "user1"
    password = "xxxxxx"


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


