.. _doc_krill_install_and_run:

Install and Run
===============

Before you can start to use Krill you will need to install, configure and run
the Krill application somewhere. Please follow the steps below and you will be
ready to :ref:`get started<doc_krill_get_started>`.

Quick Start
-----------

Getting started with Krill is really easy by either installing a binary package
for Debian and Ubuntu or for Red Hat Enterprise Linux and CentOS. You can also
run with :ref:`Docker<doc_krill_running_docker>` or build from Cargo, Rust's
build system and package manager.

In case you intend to serve your RPKI certificate and ROAs to the world yourself
or you want to offer this as a service to others, you will also need to have a
public rsyncd and HTTPS web server available.

.. Note:: For the oldest platforms, Ubuntu 16.04 LTS and Debian 9, the packaged
          Krill binary is statically linked with OpenSSL 1.1.0 as this is the
          minimum version required by Krill and is higher than available in the
          official package repositories for those platforms.

.. tabs::

   .. group-tab:: Debian

       If you have a machine with an amd64/x86_64 architecture running Debian 9,
       10 or 11, you can install Krill from our `software package
       repository <https://packages.nlnetlabs.nl>`_.

       If your machine uses an ARM architecture we also provide (via the same
       repository) ARMv6 & ARM64 packages for Debian 10 and an ARMv7 package for
       Debian 11, intended to support Raspberry Pi 1b, Rock64 and Raspberry Pi 4b
       respectively.

       First update the ``apt`` package index:

       .. code-block:: bash

          sudo apt update

       Then install packages to allow ``apt`` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *main* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null

       After updating the ``apt`` package index you can install Krill:

       .. code-block:: bash

          sudo apt update
          sudo apt install krill

       Review the generated configuration file at ``/etc/krill.conf``. **Pay
       particular attention** to the ``service_uri`` and ``admin_token``
       settings. Tip: The configuration file was generated for you using the
       ``krillc config simple`` command.

       .. Warning:: If you modify the default ``data_dir``, or if you decide
          to symlink its default directory ``/var/lib/krill/data`` to another
          location or volume, you will need to:

           1) ensure the user ``krill`` has write permissions
           2) configure systemd to give the krill process access

           The easiest way to achieve the latter is by using
           ``systemctl edit krill`` and adding the following:

           ```
           [Service]
           ReadWritePaths=/your/path/to/data
           ```

      Once happy with the settings use ``sudo systemctl enable --now krill`` to
      instruct systemd to enable the Krill service at boot and to start it
      immediately. The krill daemon runs as user ``krill`` and stores its data
      in ``/var/lib/krill/data``, unless you modified the `data_dir` setting.

       You can check the status of Krill with:

       .. code-block:: bash

          sudo systemctl status krill

       You can view the logs with:

       .. code-block:: bash

          sudo journalctl --unit=krill

   .. group-tab:: Ubuntu

       If you have a machine with an amd64/x86_64 architecture running Ubuntu
       16.x, 18.x, 20.x or 22.x, you can install Krill from our `software
       package repository <https://packages.nlnetlabs.nl>`_.

       First update the ``apt`` package index:

       .. code-block:: bash

          sudo apt update

       Then install packages to allow ``apt`` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *main* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null

       After updating the ``apt`` package index you can install Krill:

       .. code-block:: bash

          sudo apt update
          sudo apt install krill

       Review the generated configuration file at ``/etc/krill.conf``. **Pay
       particular attention** to the ``service_uri`` and ``admin_token``
       settings. Tip: The configuration file was generated for you using the
       ``krillc config simple`` command.

       .. Warning:: If you modify the default ``data_dir``, or if you decide
          to symlink its default directory ``/var/lib/krill/data`` to another
          location or volume, you will need to:

           1) ensure the user ``krill`` has write permissions
           2) configure systemd to give the krill process access

           The easiest way to achieve the latter is by using
           ``systemctl edit krill`` and adding the following:

           ```
           [Service]
           ReadWritePaths=/your/path/to/data
           ```

      Once happy with the settings use ``sudo systemctl enable --now krill`` to
      instruct systemd to enable the Krill service at boot and to start it
      immediately. The krill daemon runs as user ``krill`` and stores its data
      in ``/var/lib/krill/data``, unless you modified the `data_dir` setting.

       You can check the status of Krill with:

       .. code-block:: bash

          sudo systemctl status krill

       You can view the logs with:

       .. code-block:: bash

          sudo journalctl --unit=krill

   .. group-tab:: RHEL/CentOS

       If you have a machine with an amd64/x86_64 architecture running a
       :abbr:`RHEL (Red Hat Enterprise Linux)`/CentOS 7 or 8 distribution, or a
       compatible OS such as Rocky Linux, you can install Krill from our
       `software package repository <https://packages.nlnetlabs.nl>`_.

       To use this repository, create a file named
       :file:`/etc/yum.repos.d/nlnetlabs.repo`, enter this configuration and
       save it:

       .. code-block:: text

          [nlnetlabs]
          name=NLnet Labs
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/main/$basearch
          enabled=1

       Then run the following command to add the public key:

       .. code-block:: bash

          sudo rpm --import https://packages.nlnetlabs.nl/aptkey.asc

       You can then install Krill by running:

       .. code-block:: bash

          sudo yum install -y krill

       Review the generated configuration file at ``/etc/krill.conf``. **Pay
       particular attention** to the ``service_uri`` and ``admin_token``
       settings. Tip: The configuration file was generated for you using the
       ``krillc config simple`` command.

       .. Warning:: If you modify the default ``data_dir``, or if you decide
          to symlink its default directory ``/var/lib/krill/data`` to another
          location or volume, you will need to:

           1) ensure the user ``krill`` has write permissions
           2) configure systemd to give the krill process access

           The easiest way to achieve the latter is by using
           ``systemctl edit krill`` and adding the following:

           ```
           [Service]
           ReadWritePaths=/your/path/to/data
           ```

      Once happy with the settings use ``sudo systemctl enable --now krill`` to
      instruct systemd to enable the Krill service at boot and to start it
      immediately. The krill daemon runs as user ``krill`` and stores its data
      in ``/var/lib/krill/data``, unless you modified the `data_dir` setting.

       You can check the status of Krill with:

       .. code-block:: bash

          sudo systemctl status krill

       You can view the logs with:

       .. code-block:: bash

          sudo journalctl --unit=krill

   .. group-tab:: Cargo

       Assuming you have a newly installed Debian or Ubuntu machine, you will
       need to install the C toolchain, OpenSSL and Rust. You can then install
       Krill using:

       .. code-block:: bash

          sudo apt install curl build-essential libssl-dev openssl pkg-config
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
          source ~/.cargo/env
          cargo install --locked krill

Updating
--------

.. tabs::

   .. group-tab:: Debian

       To update an existing Krill installation, first update the repository
       using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy krill

       You can upgrade an existing Krill installation to the latest version
       using:

       .. code-block:: text

          sudo apt --only-upgrade install krill

   .. group-tab:: Ubuntu

       To update an existing Krill installation, first update the repository
       using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy krill

       You can upgrade an existing Krill installation to the latest version
       using:

       .. code-block:: text

          sudo apt --only-upgrade install krill

   .. group-tab:: RHEL/CentOS

       To update an existing Krill installation, you can use this command
       to get an overview of the available versions:

       .. code-block:: bash

          sudo yum --showduplicates list krill

       You can update to the latest version using:

       .. code-block:: bash

          sudo yum update -y krill

   .. group-tab:: Cargo

       If you want to install the latest version of Krill using Cargo, it's
       recommended to also update Rust to the latest version first. Use the
       ``--force`` option to  overwrite an existing version with the latest
       release:

       .. code-block:: text

          rustup update
          cargo install --locked --force krill

Rollback
--------

If you experience issues after an upgrade you may want to roll back to
the previous Krill version you had installed. A rollback is somewhat
risky so it should not be attempted unless there is no other choice.

Also note that you may lose any changes you made since upgrading, so
you may have to re-do ROA changes for example. Do not try to rollback
in case you delegated CA certificates to any child CA, as loosing changes
may then result in issues that are hard to debug.

First make sure that Krill is no longer running. Then go into your Krill
data directory and list the directories. You may see a number of
``arch-*-<version>`` directories that Krill left in case it needed to do
a data migration from your previous version. For example:

.. code-block:: bash

   /var/lib/krill/data/arch-ca_objects-0.11.0/
   /var/lib/krill/data/arch-cas-0.11.0/
   /var/lib/krill/data/arch-pubd-0.11.0/
   /var/lib/krill/data/arch-pubd_objects-0.11.0/

You should also see the corresponding *current* directories:

.. code-block:: bash

   /var/lib/krill/data/ca_objects/
   /var/lib/krill/data/cas/
   /var/lib/krill/data/pubd/
   /var/lib/krill/data/pubd_objects/

Note that you may NOT see all these directories for your previous version.
Krill only keeps these backups in case a data migration was needed for
the upgrade.

To rollback backup any current directories for which an ``arch-..-<version>``
directory exists that matches your previous Krill version. Then rename
that directory to its "current" name: i.e. strip the arch- prefix and
version suffix. Then re-install the previous version of Krill.

Installing Release Candidates
-----------------------------

Before every new release of Krill, one or more release candidates are
provided for testing through every installation method. You can also install
a specific version, if needed.

.. Note:: As a rule we test every release candidate ourselves in our own
       production environment and only do the actual release for a new
       version when we are confident that there are no issues.

       But, we really appreciate it if Krill users test out release
       candidates and let us know if they have any questions, comments,
       or run into any issues.

       We recommend that you install release candidates on test systems
       only. If you set it up as a child under our :ref:`testbed<doc_krill_testbed>`
       you can test all functions without risking issues in your production
       environment.

.. tabs::

   .. group-tab:: Debian

       If you would like to try out release candidates of Krill you can add
       the *proposed* repository to the existing *main* repository described
       earlier.

       Assuming you already have followed the steps to install regular releases,
       run this command to add the additional repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Make sure to update the ``apt`` package index:

       .. code-block:: bash

          sudo apt update

       You can now use this command to get an overview of the available
       versions:

       .. code-block:: bash

          sudo apt policy krill

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: bash

          sudo apt install krill=0.9.0~rc2-1buster

   .. group-tab:: Ubuntu

       If you would like to try out release candidates of Krill you can add
       the *proposed* repository to the existing *main* repository described
       earlier.

       Assuming you already have followed the steps to install regular releases,
       run this command to add the additional repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Make sure to update the ``apt`` package index:

       .. code-block:: bash

          sudo apt update

       You can now use this command to get an overview of the available
       versions:

       .. code-block:: bash

          sudo apt policy krill

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: bash

          sudo apt install krill=0.9.0~rc2-1bionic

   .. group-tab:: RHEL/CentOS

       To install release candidates of Krill, create an additional repo
       file named :file:`/etc/yum.repos.d/nlnetlabs-testing.repo`, enter this
       configuration and save it:

       .. code-block:: text

          [nlnetlabs-testing]
          name=NLnet Labs Testing
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/proposed/$basearch
          enabled=1

       You can use this command to get an overview of the available versions:

       .. code-block:: bash

          sudo yum --showduplicates list krill

       You can install a specific version using
       ``<package name>-<version info>``, e.g.:

       .. code-block:: bash

          sudo yum install -y krill-0.9.0~rc2

   .. group-tab:: Cargo

       All release versions of Krill, as well as release candidates, are
       available on `crates.io <https://crates.io/crates/krill/versions>`_,
       the Rust package registry. If you want to install a specific version of
       Krill using Cargo, explicitly use the ``--version`` option. If
       needed, use the ``--force`` option to overwrite an existing version:

       .. code-block:: text

          cargo install --locked --force krill --version 0.9.0-rc2

       All new features of Krill are built on a branch and merged via a
       `pull request <https://github.com/NLnetLabs/krill/pulls>`_, allowing
       you to easily try them out using Cargo. If you want to try the a specific
       branch from the repository you can use the ``--git`` and ``--branch``
       options:

       .. code-block:: text

          cargo install --git https://github.com/NLnetLabs/krill.git --branch main

       For more installation options refer to the `Cargo book
       <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.
