.. _doc_krill_ca_migrate_repo:

Migrate to a new Repository
---------------------------

There may be times when you need to migrate your CA(s) to a new Repository.
For example, you may want to do this if you were running your own Publication
Server to provide a Repository, but you can now use a service provided by
another organisation, e.g. your RIR. Another reason may be that you are
running your own server, but you decided that you need to change your server
setup.

Whatever your reason may be Krill supports migration to a new Repository by
doing a specialised key rollover. Essentially it will allow you to configure
a new Publication Server for your CA, at which point your CA will create a
new key that will use the new server, and the base URIs it got from that server.
Then you need to complete the key rollover (activate the new key), to remove
the old key and the dependency on the old server.

There is no web UI support for this (yet), but you can do this using the CLI.

First, get the so-called :rfc:`8183` Publisher Request XML for your CA:

.. code-block:: text

   krillc repo request

Then provide this XML to your new Publication Server (e.g. through a web portal).
They should return an :rfc:`8183` Repository Response XML file. Configure
your CA to use this by running:

.. code-block:: text

   krillc repo configure --response </path/to/repo-response.xml>

Note: Krill will verify that it can successfully connect to the new server and
perform an :rfc:`8181` 'list' query to see its currently published objects,
before accepting it. If this query fails you will get an error message and
nothing will change for your CA.

As with normal key rollovers :rfc:`6489` demands that you wait 24 hours before
activating the new key, and removing the old one. However, there may be reasons
why you need to move more quickly. In particular, if your old Publication Server
or its Repository is unreachable. Run the following command to complete the process
when you are ready:

.. code-block:: text

   krillc keyroll activate


.. Note:: Krill will try to remove objects published at the old repository on
     completion of this process. This is a best effort attempt. If the old server
     is unresponsive, which may well have been the reason for migration, then it
     will not try again. Furthermore, while :rfc:`8181` supports that a CA asks
     to withdraw all objects, it does not support that a CA informs a server that
     they no longer wish to be publish with them ever. I.e. it would be polite if
     you told your server to remove your CA as a publisher through another channel.

.. Note:: There is no way to cancel the migration once it has been initiated. You
     will need to complete it, but then you can migrate again. Furthermore, because
     this relies on the key rollover process you cannot do this migration if there
     is a key rollover in progress. Krill will check for this, and refuse to do
     the repository migration in this case.
