.. _doc_krill_running_docker:

Running with Docker
===================

This page explains the additional features and differences compared to running
Krill with Cargo that you need to be aware of when running Krill with Docker.

Get Docker
----------

If you do not already have Docker installed, follow the platform specific
installation instructions via the links in the Docker official `"Supported
platforms" documentation
<https://docs.docker.com/install/#supported-platforms>`_.

Fetching and Running Krill
--------------------------

The :command:`docker run` command will automatically fetch the Krill image for
your CPU architecture the first time you use it, and so there is no installation
step in the traditional sense. The :command:`docker run` command can take `many
arguments <https://docs.docker.com/engine/reference/run/>`_ and can be a bit
overwhelming at first.

.. Note:: The CPU architectures supported by the Krill Docker image are shown
   on the `Docker Hub Krill page <https://hub.docker.com/r/nlnetlabs/krill/tags>`_
   per Krill version (aka Docker "tag") in the `OS/ARCH` column.

The command below runs Krill in the background and shows how to configure a few
extra things like log level and volume mounts (more on this below).

.. code-block:: bash

   $ docker run -d --name krill -p 127.0.0.1:3000:3000 \
     -e KRILL_LOG_LEVEL=debug \
     -e KRILL_FQDN=rpki.example.net \
     -e KRILL_AUTH_TOKEN=correct-horse-battery-staple \
     -e TZ=Europe/Amsterdam \
     -v krill_data:/var/krill/data/ \
     -v /tmp/krill_rsync/:/var/krill/data/repo/rsync/ \
     nlnetlabs/krill

.. Note::
   The Docker container by default uses UTC time. If you need to use a
   different time zone you can set this using the TZ environment variable as
   shown in the example above.

Admin Token
-----------

By default Docker Krill secures itself with an automatically generated admin
token. You will need to obtain this token from the Docker logs in order to
manage Krill via the API or the :command:`krillc` CLI tool.

.. code-block:: bash

    $ docker logs krill 2>&1 | fgrep token
    docker-krill: Securing Krill daemon with token <SOME_TOKEN>

You can pre-configure the token via the ``auth_token`` Krill config file
setting, or if you don't want to provide a config file you can also use the
Docker environment variable ``KRILL_AUTH_TOKEN`` as  shown above.

Running the Krill CLI
---------------------

Local
"""""

Using a Bash alias with ``<SOME_TOKEN>`` you can easily interact with the
locally running Krill daemon via its command-line interface (CLI):

.. parsed-literal::

    $ alias krillc='docker exec \\
      -e KRILL_CLI_SERVER=https://127.0.0.1:3000/ \\
      -e KRILL_CLI_TOKEN=correct-horse-battery-staple \\
      nlnetlabs/krill krillc'

    $ :ref:`krillc list<cmd_krillc_list>` -f json
    {
      "cas": []
    }

Remote
""""""

The Docker image can also be used to run :command:`krillc` to manage remote
Krill servers. Using a shell alias simplifies this considerably:

.. parsed-literal::

    $ alias krillc='docker run --rm \\
      -e KRILL_CLI_SERVER=https://rpki.example.net/ \\
      -e KRILL_CLI_TOKEN=correct-horse-battery-staple \\
      -v /tmp/ka:/tmp/ka nlnetlabs/krill krillc'

   $ :ref:`krillc list<cmd_krillc_list>` -f json
   {
      "cas": []
   }

Note: The ``-v`` volume mount is optional, but without it you will not be able
to pass files to :command:`krillc` which some subcommands require, e.g.

.. parsed-literal::

   $ :ref:`krillc roas update<cmd_krillc_roas_update>` --ca my_ca --delta /tmp/delta.in

Service and Certificate URIs
----------------------------

The Krill ``service_uri`` and ``rsync_base`` config file settings can be
configured via the Docker environment variable ``KRILL_FQDN`` as shown in
the example above. Providing ``KRILL_FQDN`` will set **both** ``service_uri``
and ``rsync_base``.

Data
----

Krill writes state and data files to a data directory which in Docker Krill is
hidden inside the Docker container and is lost when the Docker container is
destroyed.

Persistence
"""""""""""

To protect the data you can write it to a persistent `Docker volume
<https://docs.docker.com/storage/volumes/>`_ which is preserved even if the
Krill Docker container is destroyed. The following fragment from the example
above shows how to configure this:

.. code-block:: bash

   docker run -v krill_data:/var/krill/data/

Access
""""""

Some of the data files written by Krill to its data directory are intended to
be shared with external clients via the rsync protocol. To make this possible
with Docker Krill you can either:

- Mount the rsync data directory in the host and run rsyncd on the host, *OR*
- Share the rsync data with another `Docker container which runs rsyncd <https://hub.docker.com/search?q=rsyncd&type=image>`_

Mounting the data in a host directory:

.. code-block:: bash

   docker run -v /tmp/krill_rsync:/var/krill/data/repo/rsync

Sharing via a named volume:

.. code-block:: bash

   docker run -v krill_rsync:/var/krill/data/repo/rsync

Logging
-------

Krill logs to a file by default. Docker Krill however logs by default to stderr
so that you can see the output using the :command:`docker logs` command.

At the default ``warn`` log level Krill doesn't output anything unless there is
something to warn about. Docker Krill however comes with some additional
logging which appears with the prefix ``docker-krill:``. On startup you will
see something like the following in the logs:

.. code-block:: bash

   docker-krill: Securing Krill daemon with token ba473bac-021c-4fc9-9946-6ec109befec3
   docker-krill: Configuring /var/krill/data/krill.conf ..
   docker-krill: Dumping /var/krill/data/krill.conf config file
   ...
   docker-krill: End of dump

Environment Variables
---------------------

The Krill Docker image supports the following Docker environment variables
which map to the following :file:`krill.conf` settings:

+----------------------+------------------------------------+
| Environment variable | Equivalent Krill config setting    |
+======================+====================================+
| ``KRILL_AUTH_TOKEN`` | ``auth_token``                     |
+----------------------+------------------------------------+
| ``KRILL_FQDN``       | ``service_uri`` and ``rsync_base`` |
+----------------------+------------------------------------+
| ``KRILL_LOG_LEVEL``  | ``log_level``                      |
+----------------------+------------------------------------+
| ``KRILL_USE_TA``     | ``use_ta``                         |
+----------------------+------------------------------------+

To set these environment variables use ``-e`` when invoking :command:`docker`,
e.g.:

.. code-block:: bash

   docker run -e KRILL_FQDN=https://rpki.example.net/

Using a Config File
-------------------

Via a volume mount you can replace the Docker Krill config file with your
own and take complete control:

.. code-block:: bash

   docker run -v /tmp/krill.conf:/var/krill/data/krill.conf

This will instruct Docker to replace the default config file used by Docker
Krill with the file :file:`/tmp/krill.conf` on your host computer.

Running as a non-root user
--------------------------

The Krill Docker image supports running Krill as the non-root user "krill"
(UID 1012, GID 1012) but for backward compatibility runs by default as user
"root".

One can specify that Krill should run as user "krill" like so:

.. code-block:: bash

   docker run -u krill

Running as a different username, UID and/or GID requires building the Docker
image yourself, e.g.:

.. code-block:: bash

   cd path/to/krill/git/clone
   docker build -t mykrill \
     --build-arg RUN_USER=myuser \
     --build-arg RUN_USER_UID=1234 \
     --build-arg RUN_USER_GID=5678 \
     .

.. note:: If running Krill inside the container as a non-root user and mounting
          the host filesystem or a Docker volume under the Krill data directory
          you must ensure that the Krill data directory and subdirectories are
          writable by Krill.
