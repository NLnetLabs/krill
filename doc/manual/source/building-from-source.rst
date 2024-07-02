.. _doc_krill_install_from_source:

Building From Source
---------------------

There are three things you need for Krill: Rust, a C toolchain and OpenSSL.
You can install Krill on any Operating System where you can fulfil these
requirements, but we will assume that you will run this on a UNIX-like OS.

Rust
""""

The Rust compiler runs on, and compiles to, a great number of platforms,
though not all of them are equally supported. The official `Rust
Platform Support <https://forge.rust-lang.org/platform-support.html>`_
page provides an overview of the various support levels.

While some system distributions include Rust as system packages,
Krill relies on a relatively new version of Rust, currently 1.56 or
newer. We therefore suggest to use the canonical Rust installation via a
tool called :command:`rustup`.

To install :command:`rustup` and Rust, simply do:

.. code-block:: bash

   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `official Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

You can update your Rust installation later by running:

.. code-block:: bash

   rustup update

For some platforms, :command:`rustup` cannot provide binary releases to install
directly. The `Rust Platform Support
<https://forge.rust-lang.org/platform-support.html>`_ page lists
several platforms where official binary releases are not available,
but Rust is still guaranteed to build. For these platforms, automated
tests are not run so it’s not guaranteed to produce a working build, but
they often work to quite a good degree.

One such example that is especially relevant for the routing community
is OpenBSD. On this platform, `patches
<https://github.com/openbsd/ports/tree/master/lang/rust/patches>`_ are
required to get Rust running correctly, but these are well maintained
and offer the latest version of Rust quite quickly.

Rust can be installed on OpenBSD by running:

.. code-block:: bash

   pkg_add rust

Another example where the standard installation method does not work is
CentOS 6, where you will end up with a long list of error messages about
missing assembler instructions. This is because the assembler shipped with
CentOS 6 is too old.

You can get the necessary version by installing the `Developer Toolset 6
<https://www.softwarecollections.org/en/scls/rhscl/devtoolset-6/>`_ from the
`Software Collections
<https://wiki.centos.org/AdditionalResources/Repositories/SCL>`_ repository. On
a virgin system, you can install Rust using these steps:

.. code-block:: bash

   sudo yum install centos-release-scl
   sudo yum install devtoolset-6
   scl enable devtoolset-6 bash
   curl https://sh.rustup.rs -sSf | sh
   source $HOME/.cargo/env

C Toolchain
"""""""""""

Some of the libraries Krill depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum
set of packages to build from C sources. For example,
:command:`apt install build-essential` will install everything you need on
Debian/Ubuntu.

If you are unsure, try to run :command:`cc` on a command line and if there’s a
complaint about missing input files, you are probably good to go.

OpenSSL
"""""""

Your system will likely have a package manager that will allow you to install
OpenSSL in a few easy steps. For Krill, you will need :command:`libssl-dev`,
sometimes called :command:`openssl-dev`. On Debian-like Linux distributions,
this should be as simple as running:

.. code-block:: bash

    apt install libssl-dev openssl pkg-config


Building with Cargo
"""""""""""""""""""

Rust uses its own build tool, called ```cargo```.

https://github.com/NLnetLabs/krill

You can clone the
`Krill GitHub repository <https://github.com/NLnetLabs/krill/>`_ , checkout
a release and then use ```cargo build --release --locked``` to build the code.

An easier way to build a specific release with the need to clone the
repository first is to leave it to ```cargo```. Krill releases and tags
are listed `here <https://github.com/NLnetLabs/krill/releases>`_

You can install a tagged github release using cargo by saying:

.. code-block:: bash

   cargo install krill --git https://github.com/NLnetLabs/krill \
                       --tag v0.12.0-rc1 \
                       --locked

If you want to update an installed version, you run the same command but
add the ``-f`` flag, a.k.a. force, to approve overwriting the installed
version.

The command will build Krill and install it in the same directory
that cargo itself lives in, likely :file:`$HOME/.cargo/bin`. This means
Krill will be in your path, too.


Generate Configuration File
"""""""""""""""""""""""""""

After the installation has completed, there are just two things you need to
configure before you can start using Krill. First, you will need a data
directory, which will store everything Krill needs to run. Secondly, you will
need to create a basic configuration file, specifying a secret token and the
location of your data directory.

The first step is to choose where your data directory is going to live and to
create it. In this example we are simply creating it in our home directory.

.. code-block:: bash

  mkdir ~/data

Krill can generate a basic configuration file for you. We are going to specify
the two required directives, a secret token and the path to the data directory,
and then store it in this directory.

.. parsed-literal::

  :ref:`krillc config simple<cmd_krillc_config_simple>` --token correct-horse-battery-staple --data ~/data/ > ~/data/krill.conf

.. Note:: If you wish to run a self-hosted RPKI repository with Krill you will
          need to use a different ``krillc config`` command. See :ref:`doc_krill_publication_server`
          for more details.

You can find a full example configuration file with defaults in `the
GitHub repository
<https://github.com/NLnetLabs/krill/blob/main/defaults/krill.conf>`_.


Start and Stop the Daemon
"""""""""""""""""""""""""

There is currently no standard script to start and stop Krill. You could use the
following example script to start Krill. Make sure to update the
``DATA_DIR`` variable to your real data directory, and make sure you saved
your :file:`krill.conf` file there.

.. code-block:: bash

  #!/bin/bash
  KRILL="krill"
  DATA_DIR="/path/to/data"
  KRILL_PID="$DATA_DIR/krill.pid"
  CONF="$DATA_DIR/krill.conf"
  SCRIPT_OUT="$DATA_DIR/krill.log"

  nohup $KRILL -c $CONF >$SCRIPT_OUT 2>&1 &
  echo $! > $KRILL_PID

You can use the following sample script to stop Krill:

.. code-block:: bash

  #!/bin/bash
  DATA_DIR="/path/to/data"
  KRILL_PID="$DATA_DIR/krill.pid"

  kill `cat $KRILL_PID`
