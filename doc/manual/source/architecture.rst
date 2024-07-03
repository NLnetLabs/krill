.. _doc_krill_architecture:

Architecture
============

This section is intended to give you an overview of the architecture of Krill,
which is important to keep in mind when deploying the application in your
infrastructure. It will give you an understanding how and where data is stored,
how to make your setup redundant and how to save and restore backups.

.. Warning:: Krill does NOT support clustering at this time. You can achieve
             high availability by doing a fail-over to a standby *inactive*
             installation using the same data and configuration. However, you
             cannot have multiple active instances. This
             `feature <https://github.com/NLnetLabs/krill/issues/20>`_ is on our
             long term roadmap.

Used Disk Space
---------------

Krill stores all of its data under the ``DATA_DIR``. For users who will operate
a CA under an RIR / NIR parent the following sub-directories are relevant:

+-----------------+------------------------------------------------------------+
| Directory       | Contents                                                   |
+=================+============================================================+
| data_dir/ssl    | The HTTPS key and certificate used by Krill                |
+-----------------+------------------------------------------------------------+
| data_dir/cas    | The history of your CA(s) in raw JSON format               |
+-----------------+------------------------------------------------------------+
| data_dir/pubd   | If used, the history of your Publication Server            |
+-----------------+------------------------------------------------------------+

.. Note::  Note that old versions of Krill also used the directories
           ``data_dir/rfc8181`` and ``data_dir/rfc6492`` for storing all
           protocol messages exchanged between your CAs and their parent
           and repository. If they are still present on your system, you
           can safely remove them and save space - potentially quite a bit
           of space.

Archiving
"""""""""

Krill offers the option to archive old, less relevant, historical information
related to publication. You can enable this by setting the option
``archive_threshold_days`` in your configuration file. If set Krill will move
all publication events older than the specified number of days to a subdirectory
called ``archived`` under the relevant data directory, i.e.
``data_dir/pubd/0/archived`` if you are using the Krill Publication Server and
``data_dir/cas/<your-ca-name>/archived`` for each of your CAs.

You can set up a cronjob to delete these events once and for all, but we
recommend that you save them in long term storage if you can. The reason is that
if (and only if) you have this data, you will be able to rebuild the complete
Krill state based on its *audit* log of events, and irrevocably prove that no
changes were made to Krill other than the changes recorded in the audit trail.
We have no tooling for this yet, but we have an `issue
<https://github.com/NLnetLabs/krill/issues/331>`_ on our backlog.

Saving State Changes
--------------------

You can skip this section if you're not interested in the gory details. However,
understanding this section will help to explain how backup and restore works in
Krill, and why a standby fail-over node can be used, but Krill's locking and
storage mechanism needs to be changed in order to make
`multiple active nodes <https://github.com/NLnetLabs/krill/issues/20>`_
work.

State changes in Krill are tracked using *events*. Krill CA(s) and Publication
Servers are versioned. They can only be changed by applying an *event* for a
specific version. An *event* just contains the data that needs to be changed.
Crucially, they cannot cause any side effects. As such, the overall state can
always be reconstituted by applying all past events. This concept is called
*event-sourcing*, and in this context the CAs and Publication Servers are
so-called *aggregates*.

Events are not applied directly. Rather, users of Krill and background jobs will
send their intent to make a change through the API, which then translates
this into a so-called *command*. Krill will then *lock* the target aggregate
and send the command to it. This locking mechanism is not aware of any
clustering, and it's a primary reason why Krill cannot run as an active-active
cluster yet.

Upon receiving a command the aggregate (your CA etc.) will do some work. In some
cases a command can have a side-effect. For example it may instruct your CA to
create a new key pair, after receiving entitlements from its parent. The key pair
is random — applying a command again would result in a new random key pair.
Remember that commands are not re-applied to aggregates, only their resulting
events are. Thus in this example there would be an event caused that contains
the resulting key pair.

After receiving the command, the aggregate will return one of the following:

1. An error
     Usually this means that the command is not applicable to the aggregate
     state. For example, you may have tried to remove a ROA which does not
     exist.

     When Krill encounters such an error, it will store the command with some
     meta-information like the time the command was issued, and a summary of the
     error, so that it can be seen in the history. It will then unlock the
     aggregate, so that the next command can be sent to it.
2. No error, zero events
     In this case the command turned out to be a *no-op*, and Krill just unlocks
     the aggregate. The command sequence counter is not updated, and the command
     is not saved. This is used as a feature whenever the 'republish' background
     job kicks in. A 'republish' command is sent, but it will only have an
     actual effect if there was a need to republish — e.g. a manifest would need
     to be re-issued before it would expire.
3. One or more events
     In this case there *is* a desired state change in a Krill aggregate. Krill
     will now apply and persist the changes in the following order:

      * Each event is stored. If an event already exists for a version, then
        then the update is aborted. Because Krill cannot run as a cluster, and
        it uses locking to ensure that updates are done in sequence, this will
        only fail on the first event if a user tried to issue concurrent updates
        to the same CA.
      * On every fifth event a snapshot of the state is saved to a new file. If
        this is successful then the old snapshot (if there is one) is renamed
        and kept as a backup snapshot. The new snapshot is then renamed to the
        'current' snapshot.
      * When all events are saved, the command is saved enumerating all
        resulting events, and including meta-information such as the time that
        the time that the command was executed. And when `multiple users
        <https://github.com/NLnetLabs/krill/issues/294>`_ will be supported,
        this will also include *who* made a change.
      * Finally the version information file for the aggregate is updated to
        indicate its current version, and command sequence counter.

.. Warning:: Krill will crash, **by design**, if there is any failure in saving
             any of the above files to disk. If Krill cannot persist its state
             it should not try to carry on. It could lead to disjoints between
             in-memory and on-disk state that are impossible to fix. Therefore,
             crashing and forcing an operator to look at the system is the only
             sensible thing Krill can now do. Fortunately, this should not
             happen unless there is a serious system failure.

Loading State at Startup
------------------------

Krill will rebuild its internal state whenever it starts. If it finds that there
are surplus events or commands compared to the latest information state for any
of the aggregates, then it will assume that they are present because, either
Krill stopped in the middle of writing a transaction of changes to disk, or your
backup was taken in the middle of a transaction. Such surplus files are backed
up to a subdirectory called ``surplus`` under the relevant data directory, i.e.
``data_dir/pubd/0/surplus`` if you are using the Krill Publication Server and
``data_dir/cas/<your-ca-name>/surplus`` for each of your CAs.


Recover State at Startup
------------------------

When Krill starts, it will try to go back to the last possible **recoverable**
state if:

* it cannot rebuild its state at startup due to data corruption
* the environment variable: ``KRILL_FORCE_RECOVER`` is set
* the configuration file contains ``always_recover_data = true``

Under normal circumstances, i.e. when there is no data corruption, performing
this recovery will not be necessary. It can also take significant time due to
all the checks performed. So, we do **not recommend** forcing this.

Krill will try the following checks and recovery attempts:

* Verify each recorded command and its effects (events) in their historical
  order.
* If any command or event file is corrupt it will be moved to a subdirectory
  called ``corrupt`` under the relevant data directory, and all subsequent
  commands and events will be moved to a subdirectory called ``surplus`` under
  the relevant data directory.
* Verify that each snapshot file can be parsed. If it can't then this file is
  moved to the relevant ``corrupt`` sub-directory.
* If a snapshot file could not be parsed, try to parse the backup snapshot. If
  this file can't be parsed, move it to the relevant ``corrupt`` sub-directory.
* Try to rebuild the state to the last recoverable state, i.e. the last known
  good event. Note that if this pre-dates the available snapshots, or, if no
  snapshots are available this means that Krill will try to rebuild state by
  replaying all events. If you had enabled archiving of events, it will not be
  able rebuild state.
* If rebuilding state failed, Krill will now exit with an error.

Note that in case of data corruption Krill may be able to fall back to an
earlier recoverable state, but this state may be far in the past. You should
always verify your ROAs and/or delegations to child CAs in such cases.

Of course, it's best to avoid data corruption in the first place. Please monitor
available disk space, and make regular backups.

Backup / Restore
----------------

Backing up Krill is as simple as backing up its data directory. There is no need
to stop Krill during the backup. To restore put back your data directory and
make sure that you refer to it in the configuration file that you use for your
Krill instance. As described above, if Krill finds that the backup contain an
incomplete transaction, it will just fall back to the state prior to it.

.. Warning:: You may want to **encrypt** your backup, because the
             ``data_dir/ssl`` directory contains your private keys in clear
             text. Encrypting your backup will help protect these, but of course
             also implies that you can only restore if you have the ability to
             decrypt.

Krill Upgrades
--------------

All Krill versions 0.4.1 and upwards can be automatically upgraded to the
current version. Any required data migrations will be performed automatically.
To do so we recommend that you:

* backup your krill data directories
* install the new version of Krill
* stop the running Krill instance
* start Krill again, using the new binary, and the same configuration

If you want to test if data migrations will work correctly for your data,
you can do the following:

* copy your data directory to another system
* set the env variable ``KRILL_UPGRADE_ONLY=1``
* create a configuration file, and set ``data_dir=/path/to/your/copy``
* start up Krill

Krill will then perform the data migrations, rebuild its state, and then exit
before doing anything else.

Krill Downgrades
----------------

Downgrading Krill data is not supported. So, downgrading can only be achieved
by installing a previous version of Krill and restoring a backup from before
your upgrade.

.. _proxy_and_https:

Proxy and HTTPS
---------------

HTTPS Mode
""""""""""

Krill uses HTTPS by default, and will generate a key pair and create a
self-signed certificate if no previous key pair or certificate is found.
Files are stored under the data directory as :file:`ssl/key.pem` and
:file:`ssl/cert.pem` respectively.

Alternatively you make Krill configure krill to not generate these files
but use existing files at the same file locations. This should work, but
has not been tested extensively. To use this mode you can use
```https_mode = "existing"``` in your krill configuration file.

It also possible to force Krill to disable HTTPS and use plain HTTP. We
do not recommend this set up, but it may be useful in certain setups.
Arguably, as long as Krill listens on 127.0.0.1 only (as is the default),
and an HTTPS enabled proxy server is used for public access, then having
plain HTTP traffic between the proxy and Krill over the loopback interface
is not necessarily problematic. To use this mode set
```https_mode = "disable"``` in your configuration file.

If you need to access the Krill UI or API (also used by the CLI) from
another machine, then we highly recommend that you use a proxy server
such as NGINX or Apache. This proxy can then also use a proper HTTPS
certificate signed by a web TA, and production grade TLS support.

Proxy Krill UI
""""""""""""""

The Krill UI and assets are hosted directly under the base path ``/``. So, in
order to proxy to the Krill UI you should proxy ALL requests under ``/`` to the
Krill back-end.

Note that although the UI and API are protected by a token, you should consider
further restrictions in your proxy setup, such as restrictions on source IP or
adding your own authentication.

Proxy Krill as Parent
"""""""""""""""""""""

If you delegated resources to child CAs then you will need to ensure that these
children can reach your Krill. Child requests for resource certificates are
directed to the ``/rfc6492`` directory under the ``service_uri`` that you
defined in your configuration file.

Note that contrary to the UI you should not add any additional authentication
mechanisms to this location. :RFC:`6492` uses cryptographically signed messages
sent over HTTP and is secure. However, verifying messages and signing responses
can be computationally heavy, so if you know the source IP addresses of your
child CAs, you may wish to restrict access based on this.

Proxy Krill as Publication Server
"""""""""""""""""""""""""""""""""

If you are running Krill as a Publication Server, then you should read
:ref:`here<doc_krill_publication_server>` how to do the Publication Server
specific set up.

.. Warning:: We recommend that you do **not** make Krill available to the public
             internet unless you really need remote access to the UI or API, or
             you are serving as parent CA or Publication Server for other CAs.
