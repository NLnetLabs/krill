.. _doc_krill_upgrade:

Upgrading Krill
===============

Upgrade
-------

Krill upgrades may sometimes require that existing data is migrated
to a new format used by the new release. Krill will perform these
migrations automatically in case you install a new version of Krill
and restart it.

As the first step of this upgrade, any data that needs to be migrated
is prepared under a new directory called :file:`upgrade-data` under the
:file:`data_dir` you configured. If you used a package to install Krill
then the latter would be :file:`/var/lib/krill/data`.

If all is well then Krill will rename directories under the :file:`data_dir`
and archive your old data structures under directories called
:samp:`arch_cas_{version}` and/or :samp:`arch_pubd_{version}`. You can
safely remove these directories in order to save space later.

It is unlikely that a data migration should fail. We use automated and
manual testing to make sure that these migrations work. But, of course
even with testing things can still go wrong. If the preparation step
fails then krill will exit with an error and refuse to start the new
version.

If this happens, then you can abort the upgrade by re-installing your
previous version of krill and starting that. And, please do let us know
by `making an issue <https://github.com/NLnetLabs/krill/issues>`_.


Prepare Upgrade with krillup
----------------------------

If the fully automated upgrade process seems a bit too scary to you,
then we recommend that you perform this step manually *before* upgrading
krill itself.

Starting with Krill 0.9.5 we have introduced a new command line tool
that can be used to help prepare for krill migrations.

If you built Krill using Cargo then you will find that a new binary
called :command:`krillup` is installed alongside with krill. But, if you are
using the packages that we provide then you can install and upgrade
this binary separately. For example on a Debian system:

.. code-block:: bash

  sudo apt install krillup

If you install and/or upgrade :command:`krillup` first, before upgrading
Krill itself then you will be able to prepare and verify an upgrade while
Krill is running. This is especially useful for large operations because
some of these upgrades can take a while. By using the separate tool any
downtime is limited. Furthermore, if the preparation should unexpectedly
fail, then there will be no need to reinstall a previous version of
Krill. You can simply abort the upgrade.

:command:`krillup` only needs to be told where your config file lives.
Here we use it to prepare an upgrade, where no actual data migration is
needed. This is not an error, so it will just report that the upgrade
does not require preparation:

.. code-block:: text

  $ krillup -c ./defaults/krill.conf
  2022-02-18 16:51:26 [INFO] Prepare upgrade using configuration file: ./defaults/krill.conf
  2022-02-18 16:51:26 [INFO] Processing data from: ./data
  2022-02-18 16:51:26 [INFO] Saving prepared data to: ./data/upgrade-data
  2022-02-18 16:51:26 [INFO] No preparation is needed for the upgrade from 0.9.3-rc1 to 0.9.5-rc1.


.. Important:: Once migrated data cannot be rolled back to the format
               of a previous Krill version. So, while an upgrade can
               be aborted, it cannot be undone — other than by restoring
               data from the point before the upgrade and accepting that
               any changes since then will have been lost.

               So, please read up on :ref:`important
               changes<doc_krill_important_changes>` to see if you would be
               affected by functionality or API changes before you upgrade.

Important Changes
-----------------

.. _doc_krill_important_changes:

v0.12.0
~~~~~~~

RRDP Deltas
^^^^^^^^^^^

In this release we renamed the advanced Publication Server configuration
settings from "retention_*" to "rrdp_*" to reflect better what these
settings are actually used for.

We removed "retention_old_notification_files_seconds" altogether. From
this release onwards Krill will not try to keep old RRDP and rsync files
around. This helped to simplify the Krill code significantly. It's still
a good idea to ensure that such old files can still be served to RPs, but
this is handled, and handled better, by krill-sync.

We added a new setting "rrdp_delta_interval_min_seconds" which can be
used to limit the interval between publishing consecutive RRDP deltas.
A limit helps to reduce the load on the server, and reduces the number
of deltas that RP software would need to fetch. Small delays in publishing
new RRDP deltas are acceptable as most RP software implementations use
an interval of at least 10 minutes between validation runs. We recommend
a value between 60 and 300 seconds for large repositories.

Other Changes
^^^^^^^^^^^^^

Krill can now be configured to listen on multiple IP addresses. To use
this specify an "array" of addresses in the configuration file. E.g.:

.. code-block:: text

   ip = [ "127.0.0.1", "::1" ]


v0.11.0
~~~~~~~

ROA API Changes
^^^^^^^^^^^^^^^

- Comments

ROA configurations now support an optional 'comment' field. You can
omit this field when submitting updates (additions) of ROA configurations,
but you will see this field in response. The value will be ``null`` in
case a ROA configuration has no comment.

- ROA Objects

Krill will now also report which ROA object(s) have been issued for each
of your ROA configurations.

These changes should not affect you, as long as you are ignoring the new
additional JSON fields. For a full description of the updated JSON
responses see the :ref:`krillc roas <cmd_krillc_roas>` command.

v0.10.0
~~~~~~~

JSON Field Name Changes
^^^^^^^^^^^^^^^^^^^^^^^

When migrating support for RFC 6492, 8181 and 8183 into the base library
`rpki-rs` (issue #765) we renamed some fields which are also used in the
JSON structures of the Krill API:

+-------------+-----------------------+------------------------------+
| pre-0.10.0  | 0.10.0                | reason                       |
+=============+=======================+==============================+
| v4          | ipv4                  | More decscriptive            |
+-------------+-----------------------+------------------------------+
| v6          | ipv6                  | More decscriptive            |
+-------------+-----------------------+------------------------------+
| base_uri    | sia_base              | Term used in RFC 8183        |
+-------------+-----------------------+------------------------------+
| rpki_notify | rrdp_notification_uri | Term used in RFC 8183        |
+-------------+-----------------------+------------------------------+

We still accept the old names as aliases on input, but if you are parsing
JSON responses yourself then you will need to update your code to accept
the new names.

Parent Status Reporting
^^^^^^^^^^^^^^^^^^^^^^^

The parent status API and CLI text response now include the last known
full :rfc:`6492` "Resource Class List Response" content that your CA
received.

The json structure of the parent statuses response changed from:

.. code-block:: json

  {
    "my_parent": {
    "last_exchange": {
      "timestamp": 1617881400,
      "uri": "https://localhost:3000/rfc8181/localname/",
      "result": "Success"
    },
    "next_exchange_before": 1617882000,
    "all_resources": {
      "asn": "AS65000",
      "v4": "10.0.0.0/8",
      "v6": "2001:db8::/32"
    },
    "entitlements": {
      "0": {
        "parent_cert": {
          "uri": "rsync://localhost/repo/ta/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.cer",
          "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIHKDCCBhCgAwIBAgIUAgyEh9bfPbsXmR1LTAPsL045+tYwDQYJKoZIhvcNAQELBQAwggItMYICKTCCAiUGA1UEAxOCAhwzMDgyMDEwQTAyODIwMTAxMDBEODAxQzQzQ0U4NkYyQjI5MEM1QUVENEE0QjAxMTIwMjNBMjQzRTgzQjkzMkUyOTREMTc0Nzk5MTFFNUU5QTEwNURFREEzN0ZBQkEwNDFFRjYwRjA2QjE5NDAxMTIyMzY0QkI4RjYwRTQ1OUQ3RDYxM0UzNzQ1NzI1MkZDQjk3QUVBNzBGM0YxREI2NzIyQjkzNEIxREVBNTBGMDM2Q0FEOTc3QTBGMjhBNTA4QzY4NjM2OEI3QzQ1Qzc4MERGREZFQkNCNUU4MTBCODk0QkRFMzM5ODNCMjI1RjM5RDJCQTRGMzdEOUI5MjU2MjZFMkUyN0Y1RUJGRDJGMzc3MzY2MTEyREExNzdFQUY4RDdDMTY3NDQwNTgxQkMzNjY4N0Y2MjM3MkZGRDNCQ0NCODlCRjNDQkJBNzJBN0U0NEEwNkZDMUM1RDMwRUU2ODYxMjZCNjhEOENFRDczQkJFREUxN0M5RTJDMTNDRDIyNTYzMzI0NzgwMjVFMUYyMTdEMEREMzI2MzhDRDU1OENEMzZBRjcxMTlDOTJDQ0JFMUE0M0VGRjAyMDFEQjdGRTY4OTZCQzFGNkMwNzZFN0JGN0ZDNzAxRTc2NTVFMENBQ0I4RDk5OTlERkNBMzc2NkEzMkMzRUFCQTVGMTczMTlDQTg5QUZCNDlEQkU3MTZDNjYwMzAyMDMwMTAwMDEwHhcNMjEwMzI5MDc1ODQ2WhcNMjIwMzI4MDgwMzQ2WjAzMTEwLwYDVQQDEygwQkE1QzEzMkI5NDg5MUNCMkQzQTg5RURFMTJGMDFBQ0E0QkNEM0RDMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArKUiUmy4gbuaafgIP/q4q9w/gwwsAjoIP+cTm0FSmqhvqsc1GVI4DQ4mspjZ+O7esFqQywmcnU9MphnGq4EJwYKqT417fU8OQj/WbiCfFhnTrVTiz/LdLdDB4+VaypGfDwPuHb8pavj2dysKiGjLcF8zdon7a/xErHqOdetKlbY20TlvVvmLUeVVKfcnDkT8nsu2k+P+5BHBrb6oQoG4IhZ/w5n65m/ozLsq7pfLrsLgFe2b4zTXhu8KdJ/W1vsshM73jkpUdkvKxif6+H4mBrlMnWg7Jo0bRuff/C0dOAWdiPMXUs53Nw3+SBUjRxhXVWdbcHflkje58pcMkGKSBwIDAQABo4ICNjCCAjIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUC6XBMrlIkcstOont4S8BrKS809wwHwYDVR0jBBgwFoAUS9B/WEM89XrPSCIpOOkwBxZdNKQwDgYDVR0PAQH/BAQDAgEGMFkGA1UdHwRSMFAwTqBMoEqGSHJzeW5jOi8vbG9jYWxob3N0L3JlcG8vdGEvMC80QkQwN0Y1ODQzM0NGNTdBQ0Y0ODIyMjkzOEU5MzAwNzE2NUQzNEE0LmNybDA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUHMAKGG3JzeW5jOi8vbG9jYWxob3N0L3RhL3RhLmNlcjCB1AYIKwYBBQUHAQsEgccwgcQwLQYIKwYBBQUHMAWGIXJzeW5jOi8vbG9jYWxob3N0L3JlcG8vdGVzdGJlZC8wLzBZBggrBgEFBQcwCoZNcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90ZXN0YmVkLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5tZnQwOAYIKwYBBQUHMA2GLGh0dHBzOi8vbG9jYWxob3N0OjMwMDAvcnJkcC9ub3RpZmljYXRpb24ueG1sMBgGA1UdIAEB/wQOMAwwCgYIKwYBBQUHDgIwJwYIKwYBBQUHAQcBAf8EGDAWMAkEAgABMAMDAQAwCQQCAAIwAwMBADAhBggrBgEFBQcBCAEB/wQSMBCgDjAMMAoCAQACBQD/////MA0GCSqGSIb3DQEBCwUAA4IBAQA3rQv0h6x5zX6iGfUZsH0wFSbQQrZgWoql8PsHANokm+Kaxeq3waemrp1/LCzdsMF4+74m6ijDmdbDbHlPyiQwpu3L1vZafj4eBPMdI7xFYgEgabddAGR60b272BgVIO6yND3B6UMeT56NzcCOtOcPtjlgucU3pufaCwup9p9AqRpJOTKfeuiLOw0a5c/yLU1zu3TmDP65+7zaIJebUxOpJ9/4HSG7HsKEU9NHXr414vknGUr8XXiQ0/7f8DrpecGEK2fKu87kBYlewj4zNxJOeQ4heQ4/hJtEeS6dLKz+/VwaUbudlN9/c5QF5ow2bAsNM//ieEWWRL+B0Srr9uNr\n-----END CERTIFICATE-----\n"
        },
        "received": [
          {
            "uri": "rsync://localhost/repo/testbed/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.cer",
            "resources": {
              "asn": "AS65000",
              "v4": "10.0.0.0/8",
              "v6": "2001:db8::/32"
            },
            "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIFYDCCBEigAwIBAgIUN5PzATTKVrjgual4CpJMaggW2EIwDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQzAeFw0yMTA0MDgwOTQ4MjVaFw0yMjA0MDcwOTUzMjVaMDMxMTAvBgNVBAMTKDE2QjMxQzkyRUIxMTZCQzYwMDI2QzUwOTQ0QUQ0NDIwNUREOUFDQkQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsBouGWEPhWg+XsRDGZyuFLDPiIExy7p4b3bjNPBfHeSqHCeOwiVIVS2xiIAGO2NBcv+hL2OFKNCAnpd71hOXMBNXW/7OHN8TU6crIu1/w1gkf6UCXFrv+poW9EJHnLonMa4ZFLSFsvQACIGUpxIuiQjaSYFltTbb+o2c9KWoKsX0kZqt5zOrgAP8cke8SFGHdqqenPInXKTgyss9kCs9pFtMk6BIa6KjRvqFVZIf6xG53ytJ3JqsGjvEo8qoHYxkvkMtbjhjlmW097i6DeC1241X3SG64DSMk1CNv1xt5MSXubLzWOD+2lLId/ngql4OV0bLkbb63J/26c8FZOThZAgMBAAGjggJqMIICZjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQWsxyS6xFrxgAmxQlErUQgXdmsvTAfBgNVHSMEGDAWgBQLpcEyuUiRyy06ie3hLwGspLzT3DAOBgNVHQ8BAf8EBAMCAQYwXgYDVR0fBFcwVTBToFGgT4ZNcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90ZXN0YmVkLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jcmwwZAYIKwYBBQUHAQEEWDBWMFQGCCsGAQUFBzAChkhyc3luYzovL2xvY2FsaG9zdC9yZXBvL3RhLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jZXIwgdgGCCsGAQUFBwELBIHLMIHIMC8GCCsGAQUFBzAFhiNyc3luYzovL2xvY2FsaG9zdC9yZXBvL2xvY2FsbmFtZS8wLzBbBggrBgEFBQcwCoZPcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby9sb2NhbG5hbWUvMC8xNkIzMUM5MkVCMTE2QkM2MDAyNkM1MDk0NEFENDQyMDVERDlBQ0JELm1mdDA4BggrBgEFBQcwDYYsaHR0cHM6Ly9sb2NhbGhvc3Q6MzAwMC9ycmRwL25vdGlmaWNhdGlvbi54bWwwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAsBggrBgEFBQcBBwEB/wQdMBswCgQCAAEwBAMCAAowDQQCAAIwBwMFACABDbgwGgYIKwYBBQUHAQgBAf8ECzAJoAcwBQIDAP3oMA0GCSqGSIb3DQEBCwUAA4IBAQB8hxBbJjvgVRMfXsotTNwKCc2Q0QO92xmZlV19Uh0/Yja+sYhyg/pG1/ZTvhOLIxGWap8JmqOnYa9XgX8uUlsV8LgJoEH3Gde3txcGtfLO99ugvbnKKGOcPxB8AX5hAhhfdiSnt3V06dEz3HUoTYdUKTV0bZr3dhRIBa94esAS7lsP2vhHEQ8gVjZGWVvS7lGju+kuwm9H3PBscW/K8349vN0QJUZGm3gAUsM5PlnAqbkM7VFIyu8g2Yp9g+M/iwaHar8CqABKxLBThYgqrPLLv6CsZD3mjk5BkXVZh6R9dBcR7sPbSfGBWPWCv8SwLknyQDOvsWTho1Ga6AibjUQp\n-----END CERTIFICATE-----\n"
          }
        ]
      }
    }
  }


To:

.. code-block:: json

  {
    "my_parent": {
      "last_exchange": {
        "timestamp": 1617881400,
        "uri": "https://localhost:3000/rfc8181/localname/",
        "result": "Success"
      },
      "last_success": 1617881400,
      "all_resources": {
        "asn": "AS65000",
        "ipv4": "10.0.0.0/8",
        "ipv6": "2001:db8::/32"
      },
      "classes": [
        {
          "class_name": "0",
          "resource_set": {
            "asn": "AS65000",
            "ipv4": "10.0.0.0/8",
            "ipv6": "2001:db8::/32"
          },
          "not_after": "2023-03-15T14:23:57Z",
          "issued_certs": [
            {
              "uri": "rsync://localhost/repo/testbed/0/16B31C92EB116BC60026C50944AD44205DD9ACBD.cer",
              "req_limit": {},
              "cert": "MII..."
            }
          ],
          "signing_cert": {
            "url": "rsync://localhost/repo/ta/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.cer",
            "cert": "MII..."
          }
        }
      ]
    }
  }



v0.9.3 to v0.9.5
~~~~~~~~~~~~~~~~

There are no API changes or data migrations.

After upgrading the Publication Server (if you run one) will use ``1`` as
the first RRDP serial number, instead of ``0``. Furthermore, you will now
be able to configure the timeout for a complete :RFC:`6492` and :RFC:`8181`
client HTTP request-response round-trip to the parent or publisher,
excluding the time required to establish the connection, using
`post_protocol_msg_timeout_seconds`.

v0.9.0/1/2 to v0.9.3
~~~~~~~~~~~~~~~~~~~~

There are no API changes, but users may want to be aware that the
'next update' time for manifests and CRLs has been changed from a
fixed 24 hours (by default) to 24 hours and a random amount of extra
time between 0 and 240 minutes (4 hours). This does not affect the
validity of objects, but may lead to surprises if you are monitoring
that republication would happen withing 17 hours after last publication
(8 hours before objects would expire). This can now take up to 21 hours
(using defaults).

Furthermore experimental ASPA support was added, but it's hidden in
the CLI until the ASPA standards reach stability in the IETF. If you
want to read more about the experimental ASPA support in Krill then
have a look here:

https://krill.docs.nlnetlabs.nl/en/prototype-aspa-support/manage-aspas.html


v0.9.0/1 to v0.9.2
~~~~~~~~~~~~~~~~~~

The Prometheus metrics have been updated. The metric ``krill_cas_roas``
has been renamed to ``krill_cas_bgp_roas_total`` for consistency. Please
have a look at the updated :ref:`monitoring page<doc_krill_monitoring>`
for more details.

v0.8.2 and below to v0.9.x
~~~~~~~~~~~~~~~~~~~~~~~~~~

There are a number of API changes between v0.9.0 and previous versions.
The main reasons for these changes are:

1. Krill no longer has the concept of embedded CA parent-child or
   repo-ca relations. If you have multiple CAs in a single Krill
   instance and/or a Publication Server, then Krill will now always
   use the official RFC protocol - even if both entities live in the
   same Krill instance.
2. We wanted to make the API consistent.

But most importantly: **We wanted to make the API stable so we can
work towards Krill 1.0**

Here we will list all CLI commands and API calls that were changed
between Krill 0.8.2 and this version. This list should be complete, so
old CLI commands not listed here should not have changed.

In case you do find something that we overlooked please let us know!

krillc parents update
^^^^^^^^^^^^^^^^^^^^^

The :command:`update` command has been removed and is now folded in to
:command:`krillc parents add`.

krillc parents add
^^^^^^^^^^^^^^^^^^

If you add a parent which already exists for your CA, then this will
act as an 'update' instead. I.e. the previously known :rfc:`8183`
Parent Response for the parent will be replaced.

The CLI command is unchanged:

.. code-block:: text

  $ krillc parents add --ca newca --parent testbed --response ./parent-response.xml

But there were changes to the API.

Adding a parent can be done by posting XML or JSON to on of the
following paths:

.. code-block:: text

  /api/v1/cas/<ca>/parents
  /api/v1/cas/<ca>/parents/<handle>

The ``<handle>`` is the LOCAL name that your CA will use for this parent.
Regardless of how they like to call themselves. If it is omitted then
it will be extracted from the XML ``parent_handle``. If it is specified
for a JSON POST but _differs_ from the ``handle`` in the JSON body, then
an error is returned.

The server will verify in all cases that the parent can be reached. If
there was no parent for the name a parent will be added, otherwise the
parent contact details will be updated.

The JSON body has to include the local name by which the CA will refer
to its parent, this is also the name shown to the user in the UI. The
local name maps to the handle field in the JSON below. The second
component is the contact. Krill used to support an embedded type, but
this is no longer supported.

Instead of a JSON member under ``contact`` we now have ``"type": "rfc6492"``
here. We still have this type because this allows for the notion of
Trust Anchor - which we use in test setups - and it keeps the door open
to future additions (eg if there ever is an RFC 6492 bis). The remainder
of the structure is unchanged, and maps to the :RFC:`8183` Parent Response
XML, but then in JSON format. Note that the parent_handle is the handle
that the parent wants the CA to use in messages sent to it - and it may
be different from the local name stored in handle.

OLD JSON:

.. code-block:: json

  {
    "handle": "testbed",
    "contact": {
      "rfc6492": {
        "tag": null,
        "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5N0VEOUFCMUQ4Q0JBNzFBMTJEQjE2MTU4OTA3Njk4QUI0QTAzMUQ5MB4XDTIwMDkxNjA5MTAxMloXDTM1MDkxNjA5MTUxMlowMzExMC8GA1UEAxMoOTdFRDlBQjFEOENCQTcxQTEyREIxNjE1ODkwNzY5OEFCNEEwMzFEOTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnEJkDvrR7iY0VoRGvajDWxo2krplOnZynM1kgXtN8L3StS6YE7/sXvoG1C1pRPs/SBZ7gK6WvFlqdScZ6kbTVH51e+pLUV9Q7Uxqm4lSzWTmnjT/CmRRXqmcPlcPcAm8rhUW6GrZQ2mllil4pkZ+JNGugSQUJJb1bGg5+Et/YdIEDEO1stAIsNkfkAyELAeFULLhs0MuXpSKp/ZKu+IgMSt+Z/7is+qFt4cgMuiZRuADw8hTDoMuZpoxIqXeh4Nf3bUU06MXGgrpabVzArs11UVyXDC4ZG4oOsYDTNgIL5VYaBjiHtw+s+FWHYI3iTzwV8th2C1JI6LOOBkxZdxQUCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUl+2asdjLpxoS2xYViQdpirSgMdkwHwYDVR0jBBgwFoAUl+2asdjLpxoS2xYViQdpirSgMdkwDQYJKoZIhvcNAQELBQADggEBAB34RLGHufEpypzvDFzffkS7Oet9TUZSV1nB7EPGA7BJLvUnJt2SAv+0LhFRup518oQMpeM8HxA7vcRMt6JNTWydW/bYp/NnAk+u+Hw5AIwxuoGWgwyHXZh1xJFhwD35SqjMhxbo15J090+22zwAa8t6aqQAZhvACs2Jst1aHnnJEduQzGVZYLIYvGv5/K0t0i0eE5hINhtAy0hFGwteXms8/qA/mExsrjubC69SudPlMA3q8p2RmuwqmjSlwDjU1XrJ1j5wMCqeBoh8EnaMe+HVduQGHm0nHJbF3klz9mz3Tc6CILT4XA5mJq1g0LXypJ9c6KxZFoC10ce/enulLYw=",
        "parent_handle": "testbed",
        "child_handle": "newca",
        "service_uri": "https://testbed.krill.cloud/rfc6492/testbed"
      }
    }
  }

Was changed to:

.. code-block:: json

  {
    "handle": "my_parent",
    "contact": {
      "type": "rfc6492",
      "tag": null,
      "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFOTBDMjE3MzRDMkMzNzBBOTFBODQ3NUNCNEYwRTc1REE0RDBGMEJGMB4XDTIxMDMyOTA3NTg0NFoXDTM2MDMyOTA4MDM0NFowMzExMC8GA1UEAxMoRTkwQzIxNzM0QzJDMzcwQTkxQTg0NzVDQjRGMEU3NURBNEQwRjBCRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcL8DFS3AQyI8HewRH2Xkh6RNIfCSb7mJDaS6dHwp2Dns0VZ07SjA/vVYxq1F1w2yQ/VoTr1dvEHxJ+SDayMcFVktWCObiY8tcPhvWG+OdaX9ckDJhsOEEvdVEogwiGacNs7yXJPbqDBptJtbR8/CauF9OqMqjkB/8xkGmBoY5OI/V2832jkp7LPsbyET0RMQN7fgSpGbewvkaZVxGU3pHh5kT1nzPTXrwjxNMXgpunSEY7zR20vYCvsYYbxnSwFNbSMSL+Jgpa+HWPUc0ydqk2Dn3XneHqClu3O37URxcvI+th4+rECNp6/qlqlZK+tkppI2LkSBhTV5+n7cGA8ZsCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wHwYDVR0jBBgwFoAU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wDQYJKoZIhvcNAQELBQADggEBAG9DNu26d2S9b15NzzaArLg3Ac/nVmqDlK/1sWZNUXFWP4dt1wLTjDWnceyS8mI7Yx8dH/Fez60m4lp4dD45eeaXfbjP2cWnh3n/PLGE70Nj+G0AnUhUmwiTl0H6Px1xn8fZouhv9MEheaZJA+M4NF77+Nmkp2P3WI4cvIS7Te7R/7XpwSr29lVNtYjmRlrBDXx/bMFSgFL61mrtj/l6G8OB40w+sAwO0XKUj1vUUpfIXc3ISCo0LNT9JSPcgy1SZWfmLb98q4HuvxekhkIPRzW7vlb/NBXGarZmKc+HQjE2aXcIewhen2OoTSNda2jSSuEWZuWzZu0aMCKwFBNHLqs=",
      "parent_handle": "testbed",
      "child_handle": "newca",
      "service_uri": "https://localhost:3000/rfc6492/testbed"
    }
  }

krillc parents contact
^^^^^^^^^^^^^^^^^^^^^^

The CLI command was unchanged:

.. code-block:: text

  $ krillc parents contact --parent testbed

And the default text response is still the :rfc:`8183` Parent Response
XML for the parent. But, the JSON response body was changed, and now
includes an explicit ``"type": "rfc6492"``:

OLD:

.. code-block:: text

  {
    "rfc6492": {
      "tag": null,
      "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5N0VEOUFCMUQ4Q0JBNzFBMTJEQjE2MTU4OTA3Njk4QUI0QTAzMUQ5MB4XDTIwMDkxNjA5MTAxMloXDTM1MDkxNjA5MTUxMlowMzExMC8GA1UEAxMoOTdFRDlBQjFEOENCQTcxQTEyREIxNjE1ODkwNzY5OEFCNEEwMzFEOTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnEJkDvrR7iY0VoRGvajDWxo2krplOnZynM1kgXtN8L3StS6YE7/sXvoG1C1pRPs/SBZ7gK6WvFlqdScZ6kbTVH51e+pLUV9Q7Uxqm4lSzWTmnjT/CmRRXqmcPlcPcAm8rhUW6GrZQ2mllil4pkZ+JNGugSQUJJb1bGg5+Et/YdIEDEO1stAIsNkfkAyELAeFULLhs0MuXpSKp/ZKu+IgMSt+Z/7is+qFt4cgMuiZRuADw8hTDoMuZpoxIqXeh4Nf3bUU06MXGgrpabVzArs11UVyXDC4ZG4oOsYDTNgIL5VYaBjiHtw+s+FWHYI3iTzwV8th2C1JI6LOOBkxZdxQUCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUl+2asdjLpxoS2xYViQdpirSgMdkwHwYDVR0jBBgwFoAUl+2asdjLpxoS2xYViQdpirSgMdkwDQYJKoZIhvcNAQELBQADggEBAB34RLGHufEpypzvDFzffkS7Oet9TUZSV1nB7EPGA7BJLvUnJt2SAv+0LhFRup518oQMpeM8HxA7vcRMt6JNTWydW/bYp/NnAk+u+Hw5AIwxuoGWgwyHXZh1xJFhwD35SqjMhxbo15J090+22zwAa8t6aqQAZhvACs2Jst1aHnnJEduQzGVZYLIYvGv5/K0t0i0eE5hINhtAy0hFGwteXms8/qA/mExsrjubC69SudPlMA3q8p2RmuwqmjSlwDjU1XrJ1j5wMCqeBoh8EnaMe+HVduQGHm0nHJbF3klz9mz3Tc6CILT4XA5mJq1g0LXypJ9c6KxZFoC10ce/enulLYw=",
      "parent_handle": "testbed",
      "child_handle": "newca",
      "service_uri": "https://testbed.krill.cloud/rfc6492/testbed"
    }
  }

NEW:

.. code-block:: text

  {
    "type": "rfc6492",
    "tag": null,
    "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg5N0VEOUFCMUQ4Q0JBNzFBMTJEQjE2MTU4OTA3Njk4QUI0QTAzMUQ5MB4XDTIwMDkxNjA5MTAxMloXDTM1MDkxNjA5MTUxMlowMzExMC8GA1UEAxMoOTdFRDlBQjFEOENCQTcxQTEyREIxNjE1ODkwNzY5OEFCNEEwMzFEOTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnEJkDvrR7iY0VoRGvajDWxo2krplOnZynM1kgXtN8L3StS6YE7/sXvoG1C1pRPs/SBZ7gK6WvFlqdScZ6kbTVH51e+pLUV9Q7Uxqm4lSzWTmnjT/CmRRXqmcPlcPcAm8rhUW6GrZQ2mllil4pkZ+JNGugSQUJJb1bGg5+Et/YdIEDEO1stAIsNkfkAyELAeFULLhs0MuXpSKp/ZKu+IgMSt+Z/7is+qFt4cgMuiZRuADw8hTDoMuZpoxIqXeh4Nf3bUU06MXGgrpabVzArs11UVyXDC4ZG4oOsYDTNgIL5VYaBjiHtw+s+FWHYI3iTzwV8th2C1JI6LOOBkxZdxQUCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUl+2asdjLpxoS2xYViQdpirSgMdkwHwYDVR0jBBgwFoAUl+2asdjLpxoS2xYViQdpirSgMdkwDQYJKoZIhvcNAQELBQADggEBAB34RLGHufEpypzvDFzffkS7Oet9TUZSV1nB7EPGA7BJLvUnJt2SAv+0LhFRup518oQMpeM8HxA7vcRMt6JNTWydW/bYp/NnAk+u+Hw5AIwxuoGWgwyHXZh1xJFhwD35SqjMhxbo15J090+22zwAa8t6aqQAZhvACs2Jst1aHnnJEduQzGVZYLIYvGv5/K0t0i0eE5hINhtAy0hFGwteXms8/qA/mExsrjubC69SudPlMA3q8p2RmuwqmjSlwDjU1XrJ1j5wMCqeBoh8EnaMe+HVduQGHm0nHJbF3klz9mz3Tc6CILT4XA5mJq1g0LXypJ9c6KxZFoC10ce/enulLYw=",
    "parent_handle": "testbed",
    "child_handle": "newca",
    "service_uri": "https://testbed.krill.cloud/rfc6492/testbed"
  }

krillc repo request
^^^^^^^^^^^^^^^^^^^

The CLI is unchanged, but the endpoints for getting the :rfc:`8183`
Publisher Request XML and JSON have moved from :file:`repo`, and are now
under :file:`id`:

.. code-block:: text

  /api/v1/cas/<name>/repo/request.xml  -> /api/v1/cas/<name>/id/publisher_request.xml
  /api/v1/cas/<name>/repo/request.json -> /api/v1/cas/<name>/id/publisher_request.json


krillc repo update
^^^^^^^^^^^^^^^^^^

This command has been renamed to :command:`krillc repo configure`:

.. code-block:: text

  $ krillc repo configure --ca newca --response ./data/new-ca-repository-response.xml

The API has also changed. The path is unchanged, but the following to
add an "embedded" repository is **no longer supported**:

.. code-block:: text

  {
    "tag": "string",
    "id_cert": "string",
    "child_handle": "string"
  }

The API end-point will accept either plain :rfc:`8183` Repository
Response XML, or a JSON equivalent. In comparison to previous versions
of Krill `rfc8181` was renamed to `repository_response`:

.. code-block:: text

  {
    "repository_response": {
      "tag": null,
      "publisher_handle": "publisher",
      "id_cert": "MIID..6g==",
      "service_uri": "https://repo.example.com/rfc8181/publisher/",
      "repo_info": {
        "base_uri": "rsync://localhost/repo/ca/",
        "rpki_notify": "https://localhost:3000/rrdp/notification.xml"
      }
    }
  }

krillc repo show
^^^^^^^^^^^^^^^^

The CLI command and API path are unchanged, but ``rfc8181`` was renamed
to ``repository_response`` in the JSON response.


krillc children add
^^^^^^^^^^^^^^^^^^^

The CLI is unchanged, but because 'embedded' children are no longer
supported we were able to simplify the JSON from:

.. code-block:: text

  {
    "handle": "ca",
    "resources": {
      "asn": "AS1",
      "v4": "10.0.0.0/8",
      "v6": "::"
    },
    "auth": {
      "rfc8183": {
        "tag": null,
        "child_handle": "ca",
        "id_cert": "<base64>"
      }
    }
  }

To this:

.. code-block:: text

  {
    "handle": "ca",
    "resources": {
      "asn": "AS1",
      "v4": "10.0.0.0/8",
      "v6": "::"
    },
    "id_cert": "<base64>"
  }


krillc history and krillc action
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The API and JSON are unchanged, but these commands have now been
renamed to ``krillc history commands`` and ``krillc history details``.
