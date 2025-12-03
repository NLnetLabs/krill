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

.. code-block:: toml

    ip = "127.0.0.1"
    ip = ["127.0.0.1", "::1"]

**port**

Port number Krill listens on, by default 3000. This applies to all IP 
addresses.

.. code-block:: toml

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

.. code-block:: toml

    https_mode = "generate"


**unix_socket_enabled**

Whether UNIX socket support is enabled. By default this is true, unless you 
are on a non-UNIX system. This is the default way krillc communicates with
Krill. 

.. code-block:: toml

    unix_socket_enabled = true


**unix_socket**

The path to the UNIX socket. The default path is /run/krill/krill.sock. If not
started using the systemd service, this path may require root access. This
path is also used by default by krillc. 

.. code-block:: toml

    unix_socket = "/run/krill/krill.sock"


**unix_users**

The mapping of UNIX users to Krill roles. The default maps the root user to
admin. Can use any role defined in Krill, see also **auth_roles**.

.. code-block:: toml

    unix_users = {root = "admin"}


**storage_uri**

The path to where Krill stores its data. Must be set. Please ensure only one
Krill instance uses this path. This path should be absolute. The default
for Krill installations is /var/lib/krill/data/

.. code-block:: toml

    storage_uri = "/var/lib/krill/data/"


**use_history_cache**

Krill keeps meta-information on all past changes for each CA
and the Publication Server. This information is cached by default
to ensure that the history (audit log) API is fast.

However, this data can add up over time, so operators of
instances with many CAs or a lot of historical may choose
to turn this off to save memory. Note that memory will still
be used temporarily in case the history API is accessed.

.. code-block:: toml

    use_history_cache = true


**tls_keys_dir**

Specify the location of the TLS directory for Krill's built-in HTTPS server. 
By default it maps to $storage_uri/ssl.

.. code-block:: toml

    tls_keys_dir = "/etc/ssl/krill"


**repo_dir**

This is the directory used by the Krill Publication Server for the publication 
of RPKI objects. By default it maps to $storage_uri/repo.

.. code-block:: toml

    repo_dir = "/mnt/share/repo"


**ta_support_enabled**

Whether this Krill instance should have support to run as a Trust Anchor (TA).
By default false. You probably don't want to touch this, but if you do, see 
:ref:`doc_krill_trust_anchor`.

.. code-block:: toml

    ta_support_enabled = false


**ta_signer_enabled**

Whether this Krill instance can initialise and send Trust Anchor (TA) signer
commands. By default false. You probably don't want to touch this, but if you 
do, see :ref:`doc_krill_trust_anchor`.

.. code-block:: toml

    ta_signer_enabled = false


**pid_file**

The path to the PID file for Krill. Defaults to $storage_uri/krill.pid

.. code-block:: toml

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

* <service_uri>api/v1/                   (api)  
* <service_uri>rfc6492                   (for remote children)  
* <service_uri>                          (various UI resources)  

.. code-block:: toml

    service_uri = "https://localhost:3000/"


**log_level**

The maximum log level to for which to log messages. Defaults to warn.
Options are "off", "error", "warn", "info", "debug", and "trace". We advise
against using "debug" or "trace" in production.

.. code-block:: toml

    log_level = "warn"


**log_type**

Where to log to. One of "stderr" for stderr, "syslog" for syslog, or "file" 
for a file. If "file" is given, the "log_file" field needs to be given too.
Defaults to syslog on Krill installations.

.. code-block:: toml

    log_type = "syslog"


**log_file**

The path to the file to log to if file logging is used. This should be an 
absolute path. If the path is relative, it is relative to the current working 
directory from which the binary is executed.

.. code-block:: toml

    log_file = "/var/lib/krill/krill.log"


**syslog_facility**

The syslog facility to log to if syslog logging is used. Defaults to "daemon".

.. code-block:: toml

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

.. code-block:: toml

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

.. code-block:: toml

    auth_type = "admin-token"


**auth_users**

If **auth_type** is set *config-file*, this provides the list of users that
can authenticate with Krill. These users can be generated using 
`krillc config user`. The role matches that of **auth_roles**. See also
:ref:`doc_krill_multi_user_config_file_provider`.

.. code-block:: toml

    [auth_users]
    "joe@example.com" = { role="admin", password_hash="...", salt="..." }
    "jill@example.com" = { role="read-ca1", password_hash="...", salt="..." }


**auth_openidconnect**

If **auth_type** is set to "openid-connect", this provides the configuration for
OpenID connect that can then be used for connections. You will want to look at
:ref:`doc_krill_multi_user_openid_connect_provider` for details.

It provides the following fields:

*issuer_url* (Mandatory)

Provided by your OpenID Connect provider. This is the URL of the provider
discovery endpoint. "/.well-known/openid_configuration" will be appended if not
present. Krill will fetch the OpenID Connect Discovery 1.0 compliant JSON when
starting. Krill will fail to start if the URL does not match the "issuer" value
in the discovery response or if the endpoint cannot be contacted.


*client_id* (Mandatory)

Provided by your OpenID Connect provider.


*client_secret* (Mandatory)

Provided by your OpenID Connect provider.


*insecure*

Defaults to false. Setting to true disables verification of signatures from the
provider token ID endpoint. Setting this to true may allow attackers to modify
provider responses undetected. Strongly discouraged.


*extra_login_scopes*

Provider specific. Defaults to "". A comma-separated list of OAuth 2.0 scopes
passed when directing a user to login. Scopes request additional user details.
"profile" commonly enables email and other personal details. If the provider
supports the "email" scope, it is requested automatically.


*extra_login_params*

A `{ key=value, ... }` map of extra HTTP query parameters sent with the
authorization request. Supported params vary by provider. `prompt=login` is
sent automatically unless disabled via `prompt_for_login`. May also be
specified as a TOML table. Example:

.. code-block::

  [openid_connect.extra_login_params]
  display=popup
  ui_locales="fr-CA fr en"


*prompt_for_login*

Defaults to true. Setting to false disables sending `prompt=login`. Allows
specifying another prompt value through `extra_login_params`. Supported
values: `none`, `login`, `consent`, `select_account`.


*logout_url*

A URL to redirect the user to for logout. Usually unnecessary if discovery
metadata provides logout details. Otherwise must be specified. If discovery
shows no supported logout mechanism and no `logout_url` is set, Krill
redirects users to the UI index page to restart login.


*id_claims*

A list for extracting the user ID from claim values. Typically provided as TOML
array tables. If missing, the `email` claim is used as the user ID.


*role_claims*

A list for extracting the user role from claim values. Typically provided as
TOML array tables. If missing, the `role` claim is used as the user's role.


.. code-block:: toml

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

* *admin*: Allows full acess to everything.
* *readonly*: Allows list and read access to everything.
* *readwrite*: Allows read, create, update, and delete access to everything.

These are the fields for a role:

*permissions* (Mandatory)

A list of permissions to be granted to the role. The following permissions 
exist:

Access to log in:

  login                                         
                                                
Access to the publication server:               
                                                
  pub-admin, pub-list, pub-read, pub-create, pub-delete                                    
                                                
Access to CAs:                                  
                                                
  ca-list, ca-read, ca-create, ca-update, ca-admin, ca-delete                           
                                                
Access to the ROAs of a CA:                     
                                                
  routes-read, routes-update, routes-analysis   
                                                
Access to the ASPAs of a CA:                    
                                                
  aspas-read, aspas-update, aspas-analysis      
                                                
Access to the router keys of a CA:              
                                                
  bgpsec-read, bgpsec-update

*cas*

A list of CA handles that the role should grant access to. If missing, access 
is granted to all CAs. 


.. code-block:: toml

    [auth_roles]
    "bgpsec" = { permissions = ["bgpsec-read", "bgpsec-update"], cas = ["myca"] }


**default_signer**

The signer will be used to generate new long-term key pairs. Only one signer 
may be designated as the default. If only one signer is defined it will be the 
default. If more than one signer is defined one must be explicitly set as the 
default. The name here refers to the signer configured in **signers**.

.. code-block:: toml

    default_signer = "My signer"


**one_off_signer**

The signer will be used to generate, sign with and destroy one-off key pairs. 
Only one signer may be designated as the oneoff signer. When not specified an 
OpenSSL signer will be used for this.

.. code-block:: toml

    default_signer = "My other signer"


**signer_probe_retry_seconds**

When initially connecting to the signer on first use after Krill startup, wait
at least N seconds between attempts to connect and test the signer for 
compatibility with Krill. Defaults to 30 seconds.

.. code-block:: toml

    signer_probe_retry_seconds = 30


**signers**

Krill supports three types of signer. See also :ref:`doc_krill_hsm`:

* | *OpenSSL*: Uses the OpenSSL library installed on the host O/S. On older
  | operating systems it might be that a newer version of OpenSSL than is 
  | supported by the host O/S has been compiled into Krill itself and will be 
  | used instead.

* | *PKCS#11*: Uses a PKCS#11 v2.20 conformant library file from the filesystem.
  | How the library handles the requests on behalf of Krill is library specific. A
  | library such as SoftHSMv2 contains all of the code needed to handle the request
  | and stores generated keys on the host filesystem. Libraries provided by well
  | known HSM vendors will dispatch requests to one or a cluster of hardware 
  | security modules connected either physically or by network connection to the
  | host on which Krill is running.

* | *KMIP*: Makes TLS encrypted TCP connections to an operator specified server
  | running a KMIP v1.2 conformant service.


.. code-block:: toml

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
    public_key_attributes = { CKA_PRIVATE = false }

    [[signers]]
    type = "KMIP"
    name = "Kryptus via KMIP"
    host = "my.hsm.example.com"
    port = 5696
    server_ca_cert_path = "/path/to/some/ca.pem"
    username = "user1"
    password = "xxxxxx"


**ca_refresh_seconds**

This defines the rate, in seconds, for Krill CAs to to contact their
parent CA via the RFC 6492 up-down protocol and query for updates in
resource entitlements.

Minimum value is 1 hour (3600 seconds), maximum is 3 days. Values below of
this range are set to the minimum, values above this range are capped at
the maximum.

Defaults to 24 hours: 86400 seconds

.. code-block:: toml

    ca_refresh_seconds = 86400


**ca_refresh_jitter_seconds**

In order to avoid that many child CAs contact their parent at the same time
Krill adds a random extra 'jitter' time between 0 and the number of seconds.

Defaults to 12 hours: 43200 seconds.

Values are capped to a maximum of: 50% of **ca_refresh_seconds**

.. code-block:: toml

    ca_refresh_jitter_seconds = 43200


**ca_refresh_parents_batch_size**

The amount of parents to synchronise at once. By default 25.

.. code-block:: toml

    ca_refresh_parents_batch_size = 25



**suspend_child_after_inactive_seconds**

Suspend children if they have not contacted the parent for longer than N
seconds. By default not set, making it that children are never suspended.

Same as **suspend_child_after_inactive_hours** but in seconds. Do not set 
both at the same time.

.. code-block:: toml

    suspend_child_after_inactive_seconds = 604800


**suspend_child_after_inactive_hours**

Suspend children if they have not contacted the parent for longer than N
hours. By default not set, making it that children are never suspended.

Same as **suspend_child_after_inactive_seconds** but in hours. Do not set 
both at the same time.

.. code-block:: toml

    suspend_child_after_inactive_hours = 168


**post_limit_api**

Restrict size of messages sent to the API. Default is 256 kB.

.. code-block:: toml

    post_limit_api = 262144


**post_limit_rfc8181**

Restrict size of messages sent to the RFC 8181 publication protocol. Default 
is 32MB (enough for a keyroll with about 8000 issued certificates).

.. code-block:: toml

    post_limit_rfc8181 = 33554432


**rfc8181_log_dir**

Specify a log directory for logging RFC 8181 (publication protocol)
exchanges. If this directive is set Krill will log all meaningful
RFC 8181 exchanges in this directory, meaning exchanges that resulted
in a change or an error.

If this directive is not specified, Krill will NOT log these exchanges.

Defaults to no logging.

.. code-block:: toml

    rfc8181_log_dir = "/usr/share/krill/rfc8181"


**post_limit_rfc6492**

Restrict size of messages sent to the RFC 6492 up-down protocol. Only
relevant if you operate Krill as a parent to other CAs.

Default 1MB (enough for a keyroll with certs of ~400kb, the biggest known cert 
is 220kB)

.. code-block:: toml

    post_limit_rfc6492 = 1048576


**post_protocol_msg_timeout_seconds**

Set the timeout for a complete RFC 6492 and RFC 8181 client HTTP
request-response round-trip to the parent or publisher, excluding the time
required to establish the connection.

Defaults to 4 minutes

.. code-block:: toml

    post_protocol_msg_timeout_seconds = 240


**rfc6492_log_dir**

Specify a log directory for logging RFC 6942 (provisioning protocol)
exchanges. If this directive is set Krill will log all meaningful
RFC 6492 exchanges in this directory, meaning exchanges that resulted
in a change or an error.

If this directive is not specified, Krill will NOT log these exchanges.

Defaults to no logging.

.. code-block:: toml

    rfc6492_log_dir = "/usr/share/krill/rfc6492"


**roa_aggregate_threshold**

It is recommended that separate ROAs are used for each authorized prefix,
even though the RFC allows for multiple prefixes for the same ASN to be
combined on a single ROA object. The reason for this is that the ROA will
become invalid if any of the listed prefixes no longer appears on your
CA's certificate. Note that Krill will automatically clean up
over-claiming ROAs when it finds that its resources have been shrunk, but
there is a possible time window where ROAs can be invalid before Krill
discovers the shrinkage.

This value sets at how many separate ROAs Krill will start aggregating them
into one big ROA. By default 100.

Also see **roa_deaggregate_threshold**.

.. code-block:: toml

    roa_aggregate_threshold = 100


**roa_deaggregate_threshold**

Similar to **roa_aggregate_threshold**, this value sets at how many ROAs a
big ROA will be split up into smaller ROAs again. By default 90.

.. code-block:: toml

    roa_deaggregate_threshold = 90


.. 
    Start issuance_timing

**timing_publish_next_hours**

How long to set the validity period in manifests (without jitter) in hours.
By default 24.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_publish_next_hours = 24


**timing_publish_next_jitter_hours**

How many hours of jitter to potentially add to the manifest validity period to 
ensure the load is spread out. By default 4.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_publish_next_jitter_hours = 4


**timing_publish_hours_before_next**

How many hours before the validity expires to renew the manifest object. By
default 8.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_publish_hours_before_next = 8


**timing_child_certificate_valid_weeks**

How many weeks a child certificate is valid for. By default 1 year (52 weeks).

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_child_certificate_valid_weeks = 52


**timing_child_certificate_reissue_weeks_before**

How many weeks before a child certificate expires to renew the certificate.
By default 4 weeks.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_child_certificate_reissue_weeks_before = 4


**timing_roa_valid_weeks**

How many weeks a ROA is valid. Default is 52.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_roa_valid_weeks = 52


**timing_roa_reissue_weeks_before**

How many weeks before a ROA expires to renew the ROA. By default 4 weeks.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_roa_reissue_weeks_before = 4


**timing_aspa_valid_weeks**

How many weeks a ASPA is valid. Default is 52.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_aspa_valid_weeks = 52


**timing_aspa_reissue_weeks_before**

How many weeks before a ASPA expires to renew the ASPA. By default 4 weeks.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_aspa_reissue_weeks_before = 4



**timing_bgpsec_valid_weeks**

How many weeks a BGPsec certificate is valid. Default is 52.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_bgpsec_valid_weeks = 52


**timing_bgpsec_reissue_weeks_before**

How many weeks before a BGPsec certificate expires to renew the certificate. 
By default 4 weeks.

Do not change this unless you know what you are doing.

.. code-block:: toml

    timing_bgpsec_reissue_weeks_before = 4



..
    End issuance_timing


..
    Start rrdp_updates_config

**rrdp_delta_files_min_nr**

Minimum number of RRDP delta files to keep. By default 5.

.. code-block:: toml

    rrdp_delta_files_min_nr = 5


**rrdp_delta_files_min_seconds**

The minimum number of RRDP delta files to keep in seconds, so that a
relying party can always fetch the deltas rather than having to fetch
the snapshot.

By default set to 20 minutes.

.. code-block:: toml

    rrdp_delta_files_min_seconds = 1200


**rrdp_delta_files_max_nr**

The maximum number of RRDP deltas to keep. Older deltas will be removed when
the number of deltas exceeds this number.

By default set to 50.

.. code-block:: toml

    rrdp_delta_files_max_nr = 50


**rrdp_delta_files_max_seconds**

The maximum number of seconds an RRDP delta will be available for. If it is 
older than this it will be removed. 

By default set to 2 hours.

.. code-block:: toml

    rrdp_delta_files_max_seconds = 7200


**rrdp_delta_interval_min_seconds**

By default every change gets its own delta. This value can reduce the number
of deltas generated and bundle deltas within an interval. 

The default value is 0.

.. code-block:: toml

    rrdp_delta_interval_min_seconds = 0


**rrdp_files_archive**

Archive old snapshot and delta files. They can then be backed up and/deleted 
at the repository operator's discretion. This may be particularly useful for
audit or research.

If set to true files will be archived in a directory under 
`$storage_uri/repo/archive`.

By default false.

.. code-block:: toml

    rrdp_files_archive = false


..
    End rrdp_updates_config


..
    Start metrics

**metrics_hide_ca_details**

There are a number of metrics which use a label like {ca="ca_name"}. This
setting disables all of them.

By default false.

.. code-block::

    metrics_hide_ca_details = false


**metrics_hide_child_details**

Krill shows metrics on child CAs for each CA. This setting hides those if 
**metrics_hide_ca_details** is false.

By default false.

.. code-block::

    metrics_hide_child_details = false


**metrics_hide_publisher_details**

Krill shows metrics for every publisher. This setting hides those.

By default false.

.. code-block::

    metrics_hide_publisher_details = false


**metrics_hide_roa_details**

Krill shows metrics on ROAs in relation to known BGP announcements for each CA. 
This setting hides those if **metrics_hide_ca_details** is false.

By default false.

.. code-block::

    metrics_hide_roa_details = false


..
    End metrics


**testbed**

All these settings concern the Krill testbed. See :ref:`doc_krill_testbed` for
more about how to run the Krill testbed.

*ta_aia*

Set the rsync location for your testbed trust anchor certificate.

You need to configure an rsync server to expose another module for the
TA certificate. Don't use the module for the repository as its
content will be overwritten.

Manually retrieve the TA certificate from Krill and copy it over.
You can download it at https://<yourkrill>/ta/ta.cer

*ta_uri*

Set the HTTPS location for your testbed trust anchor certificate.

Manually retrieve the TA certificate from Krill and copy it over.
You can download it at https://<yourkrill>/ta/ta.cer

*rrdp_base_uri*

Set the base RRDP uri for the testbed repository server.

It is highly recommended to use a proxy in front of Krill.

To expose the RRDP files you can actually proxy back to your testbed
Krill server (https://<yourkrill>/rrdp/), or you can expose the
files as they are written to disk ($storage_uri/repo/rrdp/)

Set *rrdp_base_uri* to your public proxy hostname and path.

*rsync_jail*

Set the base rsync URI (jail) for the testbed repository server.

Make sure that you have an rsyncd running and a module which is
configured to expose the rsync repository files. By default these
files would be saved to: $storage_uri/repo/rsync/current/

.. code-block::

    [testbed]
    ta_aia = "rsync://testbed.example.com/ta/ta.cer"
    ta_uri = "https://testbed.example.com/ta/ta.cer"
    rrdp_base_uri = "https://testbed.example.com/rrdp/"
    rsync_jail = "rsync://testbed.example.com/repo/"


**benchmark**

These settings can be used for benchmarking Krill. Do not use in production.

*cas*

The number of CAs to create. 

*ca_roas*

The number of ROAs to create per CA.

.. code-block:: toml

    [benchmark]
    cas = 1337
    ca_roas = 9001


**ta_timing**

All these settings concert the Trust Anchor timing. See 
:ref:`doc_krill_trust_anchor` for more about running Krill as a Trust Anchor.

*certificate_validity_years*

How long the TA certificate is valid for. By default 100 years.

*issued_certificate_validity_weeks*

How long the certificate issued by the TA is valid in weeks. By default 1 year
(52 weeks).

*issued_certificate_reissue_weeks_before*

How many weeks before the certificate issued by the TA expiration date it
should be renewed. By default 26.

*mft_next_update_weeks*

How many weeks the manifest issued by the certificate issued by the TA is
valid. By default 12 weeks.

*signed_message_validity_days*

How many days a signed message by the proxy for the signer is valid. By
default two weeks (14 days).

.. code-block:: toml

    [ta_timing]
    certificate_validity_years = 100
    issued_certificate_validity_weeks = 52
    issued_certificate_reissue_weeks_before = 26
    mft_next_update_weeks = 12
    signed_message_validity_days = 14