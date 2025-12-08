Krill man page
==============

Synopsis
--------

.. code-block:: bash

    -c, --config <CONFIG>  Override the path to the config file [default: /etc/krill.conf]
    -h, --help             Print help
    -V, --version          Print version

Krill is a free, open source RPKI Certificate Authority that lets you
run delegated RPKI under one or multiple Regional Internet Registries
(RIRs). Through its built-in publication server, Krill can publish
Route Origin Authorizations (ROAs) on your own servers or with a third
party.

This manual page documents the krill daemon.

For more information please consult the online documentation at:
https://krill.docs.nlnetlabs.nl/en/stable/

Krill is normally started as systemd service. The status can be shown with:

.. code-block:: bash

    systemctl status krill

The default config file lives in `/etc/krill.conf`. A config file needs at
least a `storage_uri` and `admin_token`. See **krill.conf**\ (5) for more.

See also
--------

**krill**\ (1), **krill.conf**\ (5), **krillc**\ (1), **krillta**\ (1), **krillup**\ (1)

