Krill man page
==============

Synopsis
--------

.. code-block:: bash

:program:`krill` [``options``]

Description
-----------

Krill is a free, open source RPKI Certificate Authority that lets you
run delegated RPKI under one or multiple Regional Internet Registries
(RIRs). Through its built-in publication server, Krill can publish
Route Origin Authorizations (ROAs) on your own servers or with a third
party.

Options
-------

The available options are:

.. option:: -c path, --config=path

        Provides the path to a file containing basic configuration. If this
        option is not given, Krill will try to use :file:`/etc/krill.conf`.
        See **krill.conf**\ (5) for more about the format of the configuration
        file.

.. option:: -h, --help

        Print some help information.

.. option:: -V, --version

        Print version information.


See also
--------

**krill.conf**\ (5), **krillc**\ (1), **krillta**\ (1), **krillup**\ (1)

