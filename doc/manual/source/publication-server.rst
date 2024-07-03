.. _doc_krill_publication_server:

Running a Publication Server
============================

.. Important:: It is highly recommended to use an RPKI publication server
               provided by your parent CA, if available. This relieves you of
               the responsibility to keep a public rsync and web server
               available at all times.

               **RIPE NCC, ARIN, APNIC and NIC.br provide publication as a 
               service to their members.**

Why run your own?
-----------------

If your parent CA does not offer publication as a service, then you will need
to run your own server. But another reason why you may want to run your own
Publication Server is that it will allow you to delegate your CA's resources
to your own child CAs - e.g. for business units - and allow your children to
publish at your central repository as well.

In this model you will need to set up your CA as a :ref:`child under your parent<doc_krill_using_ui_parent_setup>`,
and :ref:`set it up to publish<doc_krill_using_ui_repository_setup>` at your
local Publication Server:

.. figure:: img/parent-child-repo.*
    :align: center
    :width: 100%
    :alt: Running your own publication server

    Running a publication server for yourself and your children


Install
-------

Krill comes with an embedded Publication Server. You can use this to offer
an `rfc`:8181 Publication Protocol service to your own CA, as well as
remote CAs - for example CAs for relations that you delegated Internet
Number Resources to.

In principle you can enable the Publication Server on the same Krill instance
that you use to operate your CAs. But, it may be better to use a separate
instance for this purpose. This will allow more fine grained access control
to either instance, and it makes it somewhat easier to parse the log files
in case of issues.

Here we will document a setup using a separate Publication Server instance.

Configure
---------

Your Publication Server can use a very minimal configuration file, similar
in style to the one used by the Krill CA server. You should configure the
following settings:

.. code-block:: text

  # Choose your own secret for the authorization token for the CLI and API
  admin_token =

  # If you installed krill using a package, then the default data directory
  # and pid options are probably fine.
  #
  # If you installed krill by hand then you may wish to set the following:
  data_dir = "/path/to/your/krillpubd/data/"
  pid_file = "/path/to/your/krillpubd/krill.pid"

  # Similarly, if you installed krill as a package it will use syslog, and
  # this is probably desirable. If you want to use file logging you can
  # configure this as follows, but note that there is no built-in log rotation
  # in Krill.
  log_type = "file"
  log_file = "/path/to/your/krill.log"

  # We recommend that you let the Krill daemon listen on localhost
  # only, and use a proxy with proper HTTPS set up in front of it.
  # However, you should configure the 'service_uri' property in your
  # configuration file, so that your CAs will be able to connect to
  # your server to publish. You should provide the 'base' hostname
  # and optional port only. The actual URI that your CAs will connect
  # to is: $service_uri/rfc8181
  #
  # NOTE: This can be a different base URI from the one used to
  #       to serve the content of your repository - that URI is
  #       is configured when you initialise your Publication Server
  #       through the CLI.
  service_uri = "https://krill-repo-server.example.com/"

  # Disable the download of BGP information. Unless you are also using
  # this server to host your CAs there is no need to keep this information
  # in memory.
  bgp_risdumps_enabled = false

If you want to review all options, you can download the :download:`default config file<examples/krillpubd.conf>`.


Proxy for Remote Publishers
---------------------------

Krill runs the RFC8181 Publication Server. Remote publishers, CAs which use your
Publication Server, will need to connect to this under the `/rfc8181` path under
the `service_uri` that you specified in your server.

Make sure that you set up a proxy server such as NGINX, Apache, etc. which uses
a valid HTTPS certificate, and which proxies `/rfc8181` to Krill.

Note that you should not add any additional authentication mechanisms to this
location. RFC 8181 uses cryptographically signed messages sent over HTTP and is
secure. Note that verifying messages and signing responses can be computationally
heavy, so if you know the source IP addresses of your publisher CAs, you may
wish to restrict access based on this.

Proxy for CLI and API
---------------------

If you are okay with only using the ``krillc`` CLI on the machine where you run
your Publication Server, then your safest option is to **not** proxy access to
the API.

However, if you need to use the CLI or API from other machines, then you should
proxy access to the path '/api' to Krill.

Example NGINX configuration
---------------------------

As introduced above krill has two paths that contain the endpoints. `/api` for the
krill API that you may want to restrict. `/rfc8181` is used for publication. A
configuration that allows `192.0.2.0/24` and the IPv6 documentation prefix access to
the API, and all clients to publish is below.

It is recommended to publish the RRDP content on a different hostname.

`/etc/nginx/sites-enabled/krill.example.org`

.. code-block:: text

  server {
      listen 443 ssl http2;
      listen [::]:443 ssl http2;
      server_name $hostname;
      charset UTF-8;

      #
      # Access and error logs help you distinguish where a request failed:
      # did the error come from krill? Or did NGINX fail to reach the upstream
      # server?
      #
      access_log "/var/log/nginx/[hostname]-access.log";
      error_log "/var/log/nginx/[hostname]-error.log";

      #
      # SSL setup is missing - for recommended settings see https://ssl-config.mozilla.org
      #

      #
      # allow clients to publish up to 128mb of data (before overhead) in one
      # request: needed to publish big repositories.
      #
      client_max_body_size 128m;

      #
      # The paths are split:
      #   * /rfc8181 should be open to all child CAs
      #   * /api has an allow-list of origins that can access it.
      #
      location /rfc8181 {
          proxy_pass https://127.0.0.1:3000/rfc8181;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;

          # krill does not use a valid certificate/tls is handled by nginx
          proxy_ssl_verify off;
      }

      location /api {
          proxy_pass https://127.0.0.1:3000/api;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;

          # allow IPv4 and IPv6 documentation ranges
          allow 192.0.2.0/24;
          allow 2001:0db8::/32;
          deny  all;

          # krill does not use a valid certificate/tls is handled by nginx
          proxy_ssl_verify off;
      }
  }

Configure the Repository
------------------------

.. Note:: We use the term **Publication Server** to describe the (Krill) server
          that CAs will connect to over the RFC 8181 protocol in order to publish
          their content. We use the term **Repository Server** to describe a server
          which makes this content available to RPKI Validators.



Synchronise Repository Data
"""""""""""""""""""""""""""

To actually serve the published content to Rsync and RRDP clients you will need
to run your own *repository* servers using tools such as Rsyncd and NGINX.

The Krill **Publication Server** will write the repository files under the data
directory specified in its configuration file:

.. code-block:: text

   $DATA_DIR/repo/rsync/current/    Contains the files for Rsync
   $DATA_DIR/repo/rrdp/             Contains the files for HTTPS (RRDP)

You can share the contents of these directories with your repository servers in
various ways.

**Krill Sync**

The preferred approach is to synchronise the data written by the Publication Server to your
Repository Servers in a background process. A simple rsync command in crontab would
work most of the time, but unfortunately that approach will lead to regular issues where
inconsistent, or incomplete, data will be served to RPKI validators.

However, we have developed a separate tool `krill-sync <https://github.com/NLnetLabs/krill-sync>`_
which can be used for this purpose. Krill-sync essentially works by retrieving consistent
RRDP deltas from your back-end Publication Server to ensure that it can write consistent
sets of data to disk for use by your Repository Servers.

**Shared Data**

Another option is to use some kind of shared file system (NFS, clustered filesystem, network
storage) where the **Krill Publication Server** can write, and your **Repository Servers** can read.

If you go down this path, then make sure that the entire `$DATA_DIR/repo` is on a share.
In particular: don't use a mount point at `$DATA_DIR/repo/rsync/current` as this directory
is recreated by Krill whenever it publishes new data.

There can be issues with this approach with regards to availability and atomicity of updates
to files on disk. The Krill Publication Server takes care to write files in the right order
to avoid issues like Relying Parties retrieving a new notification.xml file *before* the snapshot
or deltas are available. It will also write new files to temporary files and then rename them
to avoid that partially written files are shown to users. However, dependent on the implementation
details of the shared data these strategies may not work.



Rsync
"""""

The next step is to configure your rsync daemons to expose a 'module' for your
files. Make sure that the Rsync URI including the 'module' matches the
:file:`rsync_base` in your Krill configuration file. Basic configuration can
then be as simple as:

.. code-block:: text

  $ cat /etc/rsyncd.conf
  uid = nobody
  gid = nogroup
  max connections = 50
  socket options = SO_KEEPALIVE

  [repo]
  path = /var/lib/krill/data/repo/rsync/current/
  comment = RPKI repository
  read only = yes

Note: we recommend that you use a limit for 'max connections'. Which value
works best for you depends on your local situation, so you may want to monitor
and tune this to your needs. Generally speaking though, it is better to limit
the number of connections because RPKI validators will simply try to reconnect,
rather then end up in a situation where your rsync server is unable to handle
requests.

RRDP
""""

For RRDP you will need to set up a web server of your choice and ensure that it
has a valid TLS certificate. Next, you can make the files found under, or copied
from :file:`$DATA_DIR/repo/rrdp` available here.

.. Note:: If desired, you can also use a **CDN** or your own caching infrastructure
          to reduce load. You could set it up to serve 'stale' content if your
          back-end system is unavailable to reduce the impact of short outages of
          your server. If you cache content make sure that you do not cache the
          main 'notification.xml' file (see more below) for longer than one minute
          (unless the back-end is unavailable). Other RRDP files will use unique
          names and can be cached for as long as you please.



Initialise Publication Server
"""""""""""""""""""""""""""""

You need to initialise your **Publication Server** using the base URIs as exposed
by your **Repository Servers**. Use the following command, well, make sure the
URIs reflect **your** setup of course:

Example CLI:

.. code-block:: text

   $ krillc pubserver server init --rrdp https://krillrepo.example.com/rrdp/ --rsync rsync://krillrepo.example.com/repo/

There is probably no reason to use the API directly for this initialisation process,
except perhaps for automation of test environments:

.. code-block:: text

   $ krillc pubserver server init --rrdp https://krillrepo.example.com/rrdp/ --rsync rsync://krillrepo.example.com/repo/ --api
   POST:
     https://krill-ui-dev.do.nlnetlabs.nl/api/v1/pubd/init
  Headers:
    content-type: application/json
    Authorization: Bearer secret
  Body:
  {
    "rrdp_base_uri": "https://krillrepo.example.com/rrdp/",
    "rsync_jail": "rsync://krillrepo.example.com/repo/"
  }

Provided that you also set up your Repository Servers, and that they are in sync,
you can now verify that the set up works. Try to get the 'notification.xml' file
under your base URI, e.g. https://krillrepo.example.com/rrdp/notification.xml. Verify that
access to your rsync server works by doing:

.. code-block:: text

  $ rsync --list-only rsync://krillrepo.example.com/repo/

If you are satisfied that things work, you can proceed to add publishers for your
CAs. If not, then this is the moment to clear your Publication Server instance so
that it can be re-initialised:

.. code-block:: text

   $ krillc pubserver server clear

Or through the API:

.. code-block:: text

   $ krillc pubserver server clear --api
   DELETE:
     https://localhost:3000/api/v1/pubd/init
   Headers:
     Authorization: Bearer secret

Note that you can NOT clear a Publication Server instance if it has any active
publishers. Those CAs would not be aware that they would need to use new URIs
on their certificates.

If you should end up in this situation, then you could set up a new Publication
Server instead, and then migrate your existing CAs to that server, and then
remove your current server altogether. Alternatively, you can remove all
publishers from your server first, then clear and re-inialise it, and then
add your CAs again and migrate them to this newly initialised version.

In short: it is best to avoid this and ensure that your are happy with the
URIs used before adding publishers.


Repository Stats
""""""""""""""""

You can review Publication Server stats, including the number of files and space
used by publishers, and the base URIs that were used to initialise the
server.

Example CLI:

.. code-block:: text

  $ krillc pubserver server stats
  Server URIs:
    rrdp:    https://localhost:3000/rrdp/
    rsync:   rsync://localhost/repo/

  RRDP updated:      2022-09-20T09:50:12.564604+00:00
  RRDP session:      0102f89f-3639-40cb-a967-68789c7da891
  RRDP serial:       34

  Publisher, Objects, Size, Last Updated
  ca, 5, 8247, 2022-09-20T09:45:11+00:00
  ta, 3, 3663, 2022-09-20T09:45:11+00:00
  testbed, 3, 3762, 2022-09-20T09:45:11+00:00

Example JSON response:

.. code-block:: text

  $ krillc pubserver server stats --format json
  {
    "publishers": {
      "ca": {
        "objects": 5,
        "size": 8247,
        "manifests": [
          {
            "uri": "rsync://localhost/repo/ca/0/CC2487CF3A9C774BFAE2DCE4DD8368441C75C720.mft",
            "this_update": "2022-09-20T09:45:11Z",
            "next_update": "2022-09-21T09:57:11Z"
          }
        ]
      },
      "ta": {
        "objects": 3,
        "size": 3663,
        "manifests": [
          {
            "uri": "rsync://localhost/repo/ta/0/0A6EA673F04AAA345D605A38E7710A2D8413B56C.mft",
            "this_update": "2022-09-20T09:45:11Z",
            "next_update": "2022-09-21T11:50:11Z"
          }
        ]
      },
      "testbed": {
        "objects": 3,
        "size": 3762,
        "manifests": [
          {
            "uri": "rsync://localhost/repo/testbed/0/217876AA966B965A6EDFDED43C469B90ED11AC6D.mft",
            "this_update": "2022-09-20T09:45:11Z",
            "next_update": "2022-09-21T13:39:11Z"
          }
        ]
      }
    },
    "session": "0102f89f-3639-40cb-a967-68789c7da891",
    "serial": 34,
    "last_update": "2022-09-20T09:50:12.564604Z",
    "rsync_base": "rsync://localhost/repo/",
    "rrdp_base": "https://localhost:3000/rrdp/"
  }

Example API:

.. code-block:: text

   $ krillc pubserver server stats --api
   GET:
     https://localhost:3000/stats/repo
   Headers:
     Authorization: Bearer secret


Manage Publishers
-----------------

Add a Publisher
"""""""""""""""

In order to add a CA as a publisher you will need to get its :rfc:`8183` Publisher
Request XML. If you had no repository defined in your CA, you can get this XML
from the UI, as described :ref:`here<doc_krill_using_ui_repository_setup>`.

The XML will include a so-called 'handle' - essentially the name that the CA likes
to use for itself. This handle needs to be unique on the server side - we can't
have all CAs calling themselves `mr-black`. For this reason the CLI offers an
optional argument ``--publisher`` that allows overriding the handle in the reqeust
with a locally unique value - e.g. a UUID.

After adding a publisher the server will respond with the unique :rfc:`8183` Repository
Response XML for this publisher. You can also retrieve this response again later
(see below).

Example CLI:

.. code-block:: text

   $ krillc pubserver publishers add --publisher localname --request ./data/new-ca-publisher-request.xml
   <repository_response xmlns="http://www.hactrn.net/uris/rpki/rpki-setup/" version="1" publisher_handle="localname" service_uri="https://localhost:3000/rfc8181/localname/" sia_base="rsync://localhost/repo/localname/" rrdp_notification_uri="https://localhost:3000/rrdp/notification.xml">
     <repository_bpki_ta>MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyg4OEJBMzA2QkMzMUVFRkU3NzRDNzYzRUY1N0VBNUZEQzdBMTlERTI1MB4XDTIxMDMyOTA3NTg0M1oXDTM2MDMyOTA4MDM0M1owMzExMC8GA1UEAxMoODhCQTMwNkJDMzFFRUZFNzc0Qzc2M0VGNTdFQTVGREM3QTE5REUyNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAORLpfOKS8M2QGBto1OdnDYdrgjxJeF+uU7mJLgqTT3l5NbkOXxgPClUqbbbfp/c7x5sy3JbmUWaQHtkl6N9l8vcRlQQfhk0vwlVCHcQQrcMViJ5GmGtEjo7+Uf9e0TDA+rrkdqOkpOLcGRKjs1SZNqCRktubQU7Ndc0ICLo6KsQ5VYvw0p6YJcsL33+jcOWsFe6D4dhYlQkw5QHXn5c0Eenvz1SQqE96pcXJ57gmnzO9iVjY9RqPoLWXSRub0pG3Q6x8naOq16uaJZyk8kVjYOayx5umR73fI9iyMG0YOF8H5vy6/gYAnYssX26kObXan0fD9rgv4aWK0Xzp5hwz1ECAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUiLowa8Me7+d0x2PvV+pf3HoZ3iUwHwYDVR0jBBgwFoAUiLowa8Me7+d0x2PvV+pf3HoZ3iUwDQYJKoZIhvcNAQELBQADggEBAMtieNiamax1gUeSeGuA72NucPCZIdx2JrTIDhCAjLmPpvnXu1djGSa07YpgLiosnbtMMfsQO2O/Yz1VkQUTjLn2x7DKwuL9A8+IrYELSth4aCNSgPkhZfDL238MflAxptNRAoIeRGn8l3oSg4AUzBuScErwvBbHWShO66nV0wzVFb+mLvNas3Wd/GMiZHI/MwGZpj86Q/8wvyyw2C0b0ddWaoXwDyJjuxja0nHPDHVriJ8/xsOfBk144n1zyP++apQXmXorCy4hs9GPyr+HGeoL6kNydDxdwzJLCqWW7u3wSnxjCJk+hfGq82qNm90ALv5PaOb58fDgWwBwuvTP0AA=</repository_bpki_ta>
   </repository_response>

Note that the API expects the JSON equivalent of the Publisher Request. But if there
is demand then we can extend this in future to also accept the plain XML.

Example API:

.. code-block:: text

   $ krillc pubserver publishers add --publisher localname --request ./data/new-ca-publisher-request.xml --api
   POST:
     https://localhost:3000/api/v1/pubd/publishers
   Headers:
     content-type: application/json
     Authorization: Bearer secret
   Body:
   {
     "tag": null,
     "publisher_handle": "localname",
     "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFRjJENzgwRkNCRkU1QjZBMkExMjA1OUM0MDlDN0M5Mjc3NTQxOTU2MB4XDTIxMDQwNzE0MzUxNFoXDTM2MDQwNzE0NDAxNFowMzExMC8GA1UEAxMoRUYyRDc4MEZDQkZFNUI2QTJBMTIwNTlDNDA5QzdDOTI3NzU0MTk1NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANuBsEO4C9n7PlYcDT0PTeZntR5l778lZQDsgxiB7ofLrg8lKcf8ugFiYI4vRqR+gDMHhR3t/X3Ho5gC7uuKf4LYqbJj+Z9ltr/236/hDYJfWMXZVcEuL+wUble1zhe2NKrgnAkpReVMSdiugoqZ9ICK2Fwkj5jCGc/qHiWOba7T78zfij8OlB/dGlJvkAY8b/XTNKsTrLozi1uVAC8GqDrV5MEgY/NfzUvgA024yxx/rC6QBDEoBjnP7wDFiaZ2lwvL2beVYu6/hVcXQzsVN+ijy7cGdkE6zi0meXJLTHPEpoA88hi3Pi+pIDBIQ3wTcpQIOqAq/SZuh4dbZK7BV8MCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7y14D8v+W2oqEgWcQJx8kndUGVYwHwYDVR0jBBgwFoAU7y14D8v+W2oqEgWcQJx8kndUGVYwDQYJKoZIhvcNAQELBQADggEBAArqsa/gpJtONdgIWV1EqwEzhKKA2EP6tLDF9ejsdMFNYrYr+2hVWaoLsSuarfwfLFSgKDFqR6sh3ljYq6mIz9gdkjBOJsR9JyHFEtsDsRpf8Hs1WlbIb8bWb73Cp/YPMPVBpmG15Z9iKantzC1tck+E1xYW5awvj+YZqGVqyFdPJOZWmaYoS83kWvg4g4IucXTH6wwy23MQ7+0gyoK4wxfXRQmWjlXpLueCOsJo7ZXopsDAmXHLoFKZVEXn1ocQNc91l521BEQ6t/d7srQA4IxZCRGh9B+JdAIOKuXBA0nncmMJLQN8Qpxlz2bxKKAgXBLdoDqjbTDVbXTPM8YLRgc="
   }

List Publishers
"""""""""""""""

You can list all current publishers using the following command:

Example CLI:

.. code-block:: text

   $ krillc pubserver publishers list
   Publishers: testbed, ta

JSON reponse:

.. code-block:: text

   $ krillc pubserver publishers list --format json
   {
     "publishers": [
       {
         "handle": "testbed"
       },
       {
         "handle": "ta"
       }
     ]
   }

Example API:

.. code-block:: text

   $ krillc pubserver publishers list --api
   GET:
     https://localhost:3000/api/v1/pubd/publishers
   Headers:
     Authorization: Bearer secret

List Stale Publishers
"""""""""""""""""""""

You can list all publishers which have not published in a while. This
may help to identify 3rd party publishers which are no longer active.

Example CLI:

.. code-block:: text

   $ krillc pubserver publishers stale --seconds 60
   Publishers: testbed, ta

Example JSON response:

.. code-block:: text

   $ krillc pubserver publishers stale --seconds 60 --format json
   {
     "publishers": [
       {
         "handle": "ta"
       },
       {
         "handle": "testbed"
       }
     ]
   }

Example API:

.. code-block:: text

   $ krillc pubserver publishers stale --seconds 60 --api
   GET:
     https://localhost:3000/api/v1/pubd/stale/60
   Headers:
     Authorization: Bearer secret

Show a Publisher
""""""""""""""""

Show details for a publisher, including the files that they published.

Example CLI:

.. code-block:: text

   $ krillc pubserver publishers show --publisher testbed
   handle: testbed
   id: E90C21734C2C370A91A8475CB4F0E75DA4D0F0BF
   base uri: rsync://localhost/repo/testbed/
   objects:
     rsync://localhost/repo/testbed/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.crl
     rsync://localhost/repo/testbed/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.mft

The JSON response also includes the full base64 encoded objects:

.. code-block:: text

   {
     "handle": "testbed",
     "id_cert": "MIIDNDCCAhygAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEyhFOTBDMjE3MzRDMkMzNzBBOTFBODQ3NUNCNEYwRTc1REE0RDBGMEJGMB4XDTIxMDMyOTA3NTg0NFoXDTM2MDMyOTA4MDM0NFowMzExMC8GA1UEAxMoRTkwQzIxNzM0QzJDMzcwQTkxQTg0NzVDQjRGMEU3NURBNEQwRjBCRjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcL8DFS3AQyI8HewRH2Xkh6RNIfCSb7mJDaS6dHwp2Dns0VZ07SjA/vVYxq1F1w2yQ/VoTr1dvEHxJ+SDayMcFVktWCObiY8tcPhvWG+OdaX9ckDJhsOEEvdVEogwiGacNs7yXJPbqDBptJtbR8/CauF9OqMqjkB/8xkGmBoY5OI/V2832jkp7LPsbyET0RMQN7fgSpGbewvkaZVxGU3pHh5kT1nzPTXrwjxNMXgpunSEY7zR20vYCvsYYbxnSwFNbSMSL+Jgpa+HWPUc0ydqk2Dn3XneHqClu3O37URxcvI+th4+rECNp6/qlqlZK+tkppI2LkSBhTV5+n7cGA8ZsCAwEAAaNTMFEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wHwYDVR0jBBgwFoAU6Qwhc0wsNwqRqEdctPDnXaTQ8L8wDQYJKoZIhvcNAQELBQADggEBAG9DNu26d2S9b15NzzaArLg3Ac/nVmqDlK/1sWZNUXFWP4dt1wLTjDWnceyS8mI7Yx8dH/Fez60m4lp4dD45eeaXfbjP2cWnh3n/PLGE70Nj+G0AnUhUmwiTl0H6Px1xn8fZouhv9MEheaZJA+M4NF77+Nmkp2P3WI4cvIS7Te7R/7XpwSr29lVNtYjmRlrBDXx/bMFSgFL61mrtj/l6G8OB40w+sAwO0XKUj1vUUpfIXc3ISCo0LNT9JSPcgy1SZWfmLb98q4HuvxekhkIPRzW7vlb/NBXGarZmKc+HQjE2aXcIewhen2OoTSNda2jSSuEWZuWzZu0aMCKwFBNHLqs=",
     "base_uri": "rsync://localhost/repo/testbed/",
     "current_files": [
       {
         "base64": "MIIJRAYJKoZIhvcNAQcCoIIJNTCCCTECAQMxDTALBglghkgBZQMEAgEwgZsGCyqGSIb3DQEJEAEaoIGLBIGIMIGFAgEJGA8yMDIxMDQwODA2MzUwMFoYDzIwMjEwNDA5MDY0MDAwWgYJYIZIAWUDBAIBMFMwURYsMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5jcmwDIQCQzenNsskk3l2aTO31/Q8DtMdiFbVnO0AEdDZM4plkBKCCBs8wggbLMIIFs6ADAgECAhR4g6/Gg/M8Ht3YdIxWaF5a54TZ4TANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQDEygwQkE1QzEzMkI5NDg5MUNCMkQzQTg5RURFMTJGMDFBQ0E0QkNEM0RDMB4XDTIxMDQwODA2MzUwMFoXDTIxMDQxNTA2NDAwMFowggItMYICKTCCAiUGA1UEAxOCAhwzMDgyMDEwQTAyODIwMTAxMDBDODE4QjdGQ0NFMEVDNkNCNDkxMjlFNEMwQjc0RjY2OTI4NTQ2QTEwRDc5NDI1RDIzODhGNTI2NzEzQzkwNkJDRTU1QjM5RjI3RUFEQTA5RDVBQTRFQjVCRjFEN0NBNjQ2OUMwRjJDOTlGRDNFOERCNTBEQUJCNDNDMkQwM0QwRTY2Rjg4NDgwRDlBOUE1OEYyMTcyQUMwNEM3MjVENzgxODMzNUNFNEVERkNBQjkzRjM2NEYwMEVFRTdCNEY0MjlBMTQ0MDNFODgyMkMwNTQyQjNEMDczQkYwRTRENjU3NkVDMTZGNjYzMkU2RDNDMzIyNkRGOEIxMTM5Q0M0MDJBRjgxNjlERTNGQzY4RTFBRjQ5NjEyQjBGNkY0QzU2N0YwQ0Q3NzgwQzdEMjkzMjZBODlBN0E1RUUzNzQxNTIxOUZCOTNDNkFGODYyQjk2RDQyNTYxMUI4MzE0QzhDMjAyRkI5MEE3NTAyRTBCNUMwNUM2MUM3ODVGRkY1OEU0NEUzREJCNkFFOTE0NTE2N0ZDQjFGMzIxQkI1NUZDMDZDQTZEOEI5RUI2MjVERjVGMEVBQjEwNUM2QUI4OUE2NjAzODk5RjNFNkZEQzQ2NEE0MTMyNTAwNkRBMTVCOTk0OTNBMDY0RkM2MEQyNUM2ODlCMzQ3MENFNTc1NDQ3Njg0RjAyMDMwMTAwMDEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIGLf8zg7Gy0kSnkwLdPZpKFRqENeUJdI4j1JnE8kGvOVbOfJ+raCdWqTrW/HXymRpwPLJn9Po21Dau0PC0D0OZviEgNmppY8hcqwExyXXgYM1zk7fyrk/Nk8A7ue09CmhRAPogiwFQrPQc78OTWV27Bb2Yy5tPDIm34sROcxAKvgWneP8aOGvSWErD29MVn8M13gMfSkyaomnpe43QVIZ+5PGr4YrltQlYRuDFMjCAvuQp1AuC1wFxhx4X/9Y5E49u2rpFFFn/LHzIbtV/AbKbYuetiXfXw6rEFxquJpmA4mfPm/cRkpBMlAG2hW5lJOgZPxg0lxomzRwzldUR2hPAgMBAAGjggHZMIIB1TAdBgNVHQ4EFgQUhYGH74F3iP2GU+dFg556T4ehi88wHwYDVR0jBBgwFoAUC6XBMrlIkcstOont4S8BrKS809wwDgYDVR0PAQH/BAQDAgeAMF4GA1UdHwRXMFUwU6BRoE+GTXJzeW5jOi8vbG9jYWxob3N0L3JlcG8vdGVzdGJlZC8wLzBCQTVDMTMyQjk0ODkxQ0IyRDNBODlFREUxMkYwMUFDQTRCQ0QzREMuY3JsMGQGCCsGAQUFBwEBBFgwVjBUBggrBgEFBQcwAoZIcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90YS8wLzBCQTVDMTMyQjk0ODkxQ0IyRDNBODlFREUxMkYwMUFDQTRCQ0QzREMuY2VyMGkGCCsGAQUFBwELBF0wWzBZBggrBgEFBQcwC4ZNcnN5bmM6Ly9sb2NhbGhvc3QvcmVwby90ZXN0YmVkLzAvMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQy5tZnQwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAhBggrBgEFBQcBBwEB/wQSMBAwBgQCAAEFADAGBAIAAgUAMBUGCCsGAQUFBwEIAQH/BAYwBKACBQAwDQYJKoZIhvcNAQELBQADggEBAGEA7uZJ0/OEo9cifRH5NMm8NETfk2fNIId6PMqjZKJym5j4D3EnuU72FgDuXSQuI/ncOelq0Y0ABUzCjGYx41UhPYNzBLznw1WXgSDq7DviXx6hm60cpuIP++srMAWPR5yrBuX3WtJhDPmZMkOb9Z5OLs1A1It0Om1n9Sv8KCBzFG7vUjXQkQem90qnVydKp0PszRjq87lQmhJc7glRBnULkx+ydik24LDZw8+EfuYN6j2hL8nuGaREkuAHmmKwEqccSOSR4K80Obp+jHyFoWeM+rU78NrrCnKn6GWgVtIB8+XiTFJL4Pnri8ibMGaj+8aYznch3DJ8zu9T1w2r3SUxggGqMIIBpgIBA4AUhYGH74F3iP2GU+dFg556T4ehi88wCwYJYIZIAWUDBAIBoGswGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEaMBwGCSqGSIb3DQEJBTEPFw0yMTA0MDgwNjQwMDBaMC8GCSqGSIb3DQEJBDEiBCC6KQ0o84Yypkl7r0EKQaJr2g5FLRfGBlMp+vXtvA8RgDANBgkqhkiG9w0BAQEFAASCAQBaN5kzaVRD/aQHQ+EWYZMP7CFULqVEY8qPMp1GDNUhI83YdGGmbbBNy0hSfY0CJio58v/aPYRuUEcfBJQL0fi3O6PdFHF5I5hQFKzT6XX+09+UdxmAYd7TRidqIr3mBs5TbLd+e7eWwUdcut/cUxd9mjWbrCBpHKDADT3KGpe6G4TSO9BFzU51zlKP9bJos7NfpJFyu75G7NyM1ebLD+2U2PImZaAnbyyVlGyXxUd8cmEO/fweAzYk4eGvjtQIpnXpgtztdCkDE740KmYEn3XaVyNVvOk2oCyzRjkaKIPK70vRZ1HAW6IYSELLUbaFb6oSZJ9OfnVMq3Qragk/Mo6Z",
         "uri": "rsync://localhost/repo/testbed/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.mft"
       },
       {
         "base64": "MIICJTCCAQ0CAQEwDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoMEJBNUMxMzJCOTQ4OTFDQjJEM0E4OUVERTEyRjAxQUNBNEJDRDNEQxcNMjEwNDA4MDYzNTAwWhcNMjEwNDA5MDY0MDAwWjB1MCUCFByAJz7D3sHeqKPBfGyff/biiV6VFw0yMjA0MDYxMTUxMTNaMCUCFGSYKUXTAY0eHzm8+Q1j0UZa4f36Fw0yMjA0MDYxMTUxMzFaMCUCFEU/b+tRv1ToUuMk3g3kEbEFv2PIFw0yMjA0MDYxMTUxMTZaoC8wLTAfBgNVHSMEGDAWgBQLpcEyuUiRyy06ie3hLwGspLzT3DAKBgNVHRQEAwIBCTANBgkqhkiG9w0BAQsFAAOCAQEAB8dqSAjJ71YKJ106bSntFqEhHEIJ6wzbFkwe2hJJtbKe8KsM+OWyQPOXG2QJ85sNLPwTctFzNTT1efWUgof1fM9EPM5pi7GbY0EBflkSsX/qhiDAVWooDuqqUmdZNrSebYiIUOuLnuhARcWXoIOAU2UwalGX1Wbn3wPaQJ/60PMd5FWEf1JHYp8mUeSWu76E13WEtfDZYszZEGnwyLMt2vEcUauhbzVh4pxf4Yv18PWWqM5xDexc7MjADAwP5Ud8VSjPCs/Cr5M3fv2hLMLqyiyB47i+5fEewmh2IC3PDpo5rpHd5rV2M//BhJrs58a50MKZha43cT7q7qhhPQXXlg==",
         "uri": "rsync://localhost/repo/testbed/0/0BA5C132B94891CB2D3A89EDE12F01ACA4BCD3DC.crl"
       }
     ]
   }

Example API:

.. code-block:: text

   $ krillc pubserver publishers show --publisher testbed --api
   GET:
     https://localhost:3000/api/v1/pubd/publishers/testbed
   Headers:
     Authorization: Bearer secret


Remove a Publisher
""""""""""""""""""

You can remove a publisher altogether. Doing so will also remove all their
current content.

Example CLI:

.. code-block:: text

   % krillc pubserver publishers remove --publisher publisher

Example API:

.. code-block:: text

   $ krillc pubserver publishers remove --publisher publisher --api
   DELETE:
     https://localhost:3000/api/v1/pubd/publishers/publisher
   Headers:
     Authorization: Bearer secret

If you try to remove an unknown publisher, you will get an error:

.. code-block:: text

   $ krillc pubserver publishers remove --publisher publisher --format json
   Http client error: Status: 404 Not Found, ErrorResponse: {"label":"pub-unknown","msg":"Unknown publisher 'publisher'","args":{"publisher":"publisher"}}


Migrate existing Krill CAs
--------------------------

If you have an existing Krill CA that is currently publishing under another
publication server, then you can :ref:`migrate it to using a new repository<doc_krill_ca_migrate_repo>`.
