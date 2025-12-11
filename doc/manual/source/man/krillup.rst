Krill update man page
=====================

Synopsis
--------

.. code-block:: bash

:program:`krillup` [``global-options``] ``SUBCOMMAND`` [``options``]

Description
-----------

krillup is the Krill data migration tool.

Global options
--------------

The available global options are:

.. option:: -c <CONFIG>, --config <CONFIG>

        Provides the path to a file containing basic configuration. If this
        option is not given, Krill will try to use :file:`/etc/krill.conf`.
        See **krill.conf**\ (5) for more about the format of the configuration
        file.

.. option:: -h, --help

        Print some help information.

.. option:: -V, --version

        Print version information.

Subcommands
-----------

.. subcmd:: prepare

Prepare a migration, leave current data unmodified

.. subcmd:: migrate

Migrate data to different storage. Stop Krill before use!


*OPTIONS*

    .. option:: -t <TARGET>, --target=<TARGET>

    The storage target as a URI string

See also
--------

**krill**\ (1), **krill.conf**\ (5), **krillc**\ (1), **krillta**\ (1)

