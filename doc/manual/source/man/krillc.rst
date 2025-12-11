Krill CLI man page
==================

Synopsis
--------

.. code-block:: bash

:program:`krillc` [``global-options``] ``SUBCOMMAND`` [``options``]

Description
-----------

krillc is the command line interface for the krill daemon.

Global options
--------------

The available global options are:

.. option:: -s server, --server=server

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

.. subcmd:: config

Creates a configuration file for Krill and prints it to stdout
    
    .. subcmd:: user
    
    Generate a user authentication configuration file fragment
    
    
    *OPTIONS*
    
        .. option:: --id=<ID>

        ID (e.g., username, email) to generate configuration for
    
        .. option:: -a <ATTR>, --attr=<ATTR>

        Attributes for the user

.. subcmd:: health

Perform an authenticated health check

.. subcmd:: info

Show server info

.. subcmd:: list

List the current CAs

.. subcmd:: show

Show details of a CA


*OPTIONS*

    .. option:: -c <CA>, --ca=<CA>

    Name of the CA to control

.. subcmd:: history

Show the history of a CA
    
    .. subcmd:: commands
    
    Show the commands sent to a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --rows=<ROWS>

        Number of rows (max 250)
    
        .. option:: --offset=<OFFSET>

        Number of results to skip
    
        .. option:: --after=<AFTER>

        Show commands issued after date/time
    
        .. option:: --before=<BEFORE>

        Show commands issued before date/time
    
    .. subcmd:: details
    
    Show details for a command in the history of a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --key=<KEY>

        The command key as shown in 'history commands'"

.. subcmd:: add

Add a new CA


*OPTIONS*

    .. option:: -c <CA>, --ca=<CA>

    Name of the CA to control

.. subcmd:: delete

Delete a CA and let it withdraw its objects and request revocation. WARNING: Irreversible!


*OPTIONS*

    .. option:: -c <CA>, --ca=<CA>

    Name of the CA to control

.. subcmd:: issues

Show issues


*OPTIONS*

    .. option:: -c <CA>, --ca=<CA>

    Name of the CA to check for issues

.. subcmd:: children

Manage children of a CA
    
    .. subcmd:: add
    
    Add a child to a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control
    
        .. option:: -a <ASN>, --asn=<ASN>

        The AS resources to be included
    
        .. option:: -4 <IPV4>, --ipv4=<IPV4>

        The IPv4 resources to be included
    
        .. option:: -6 <IPV6>, --ipv6=<IPV6>

        The IPv6 resources to be included
    
        .. option:: -r <REQUEST>, --request=<REQUEST>

        Path to the RFC 8183 Child Request XML file
    
    .. subcmd:: update
    
    Update an existing child of a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control
    
        .. option:: -a <ASN>, --asn=<ASN>

        The AS resources to be included
    
        .. option:: -4 <IPV4>, --ipv4=<IPV4>

        The IPv4 resources to be included
    
        .. option:: -6 <IPV6>, --ipv6=<IPV6>

        The IPv6 resources to be included
    
        .. option:: -r <REQUEST>, --request=<REQUEST>

        Path to the RFC 8183 Child Request XML file
    
    .. subcmd:: info
    
    Show info for a child
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control
    
    .. subcmd:: remove
    
    Remove an existing child from a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control
    
    .. subcmd:: response
    
    Show the RFC 8183 Parent Response XML
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control
    
    .. subcmd:: connections
    
    Show connections stats for children of a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: suspend
    
    Suspend a child CA: un-publish certificate(s) issued to child
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control
    
    .. subcmd:: unsuspend
    
    Unsuspend a child CA: publish certificate(s) issued to child
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --child=<CHILD>

        The name of the child CA you wish to control

.. subcmd:: parents

Manage parents for a CA
    
    .. subcmd:: request
    
    Show RFC 8183 Child Request XML
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: add
    
    Add a parent to, or update a parent of a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --parent=<PARENT>

        The name of the parent CA you wish to control
    
        .. option:: -r <RESPONSE>, --response=<RESPONSE>

        Path to the RFC 8183 Child Request XML file
    
    .. subcmd:: contact
    
    Show contact information for a parent of a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --parent=<PARENT>

        The name of the parent CA you wish to control
    
    .. subcmd:: statuses
    
    Show overview of all parent statuses of a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: remove
    
    Remove an existing parent from a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --parent=<PARENT>

        The name of the parent CA you wish to control

.. subcmd:: keyroll

Perform a manual key rollover for a CA
    
    .. subcmd:: init
    
    Initialize roll for all keys held by a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: activate
    
    Finish roll for all keys held by a CA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control

.. subcmd:: repo

Manage the repository of a CA
    
    .. subcmd:: request
    
    Show RFC 8183 Publisher Request XML
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: show
    
    Show current repo configuration
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: status
    
    Show current repo status
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: configure
    
    Configure which repository a CA uses
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: -r <RESPONSE>, --response=<RESPONSE>

        Path to the RFC 8183 Publisher Response XML file

.. subcmd:: roas

Manage the ROAs of a CA
    
    .. subcmd:: list
    
    List current ROAs
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: update
    
    Add and remove ROAs
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --delta=<DELTA>

        Path to a file with added and removed ROAs
    
        .. option:: --add=<ADD>

        One or more ROAs to add
    
        .. option:: --remove=<REMOVE>

        One or more ROAs to remove
    
        .. option:: --dryrun=<DRYRUN>

        Perform a dry run of the update, return the BGP analysis
    
        .. option:: --try=<TRY_UPDATE>

        Try to perform the update, advice for errors or invalids
    
    .. subcmd:: bgp
    
    Show current authorizations in relation to known announcements
        
        .. subcmd:: analyze
        
        Show full report of ROAs vs known BGP announcements
        
        
        *OPTIONS*
        
            .. option:: -c <CA>, --ca=<CA>

            Name of the CA to control
        
        .. subcmd:: suggest
        
        Show ROA suggestions based on known BGP announcements
        
        
        *OPTIONS*
        
            .. option:: -c <CA>, --ca=<CA>

            Name of the CA to control
        
            .. option:: -4 <IPV4>, --ipv4=<IPV4>

            Scope to these IPv4 resources
        
            .. option:: -6 <IPV6>, --ipv6=<IPV6>

            Scope to these IPv6 resources

.. subcmd:: bgpsec

Manage the BGPsec router keys of a CA
    
    .. subcmd:: list
    
    Show current BGPsec router keys
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: add
    
    Add a BGPsec router key
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: -a <ASN>, --asn=<ASN>

        The ASN to authorize the router key for
    
        .. option:: --csr=<CSR>

        Path to the DER-encoded certificate signing request
    
    .. subcmd:: remove
    
    Remove a BGPsec router key
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: -a <ASN>, --asn=<ASN>

        The ASN of router key to be removed
    
        .. option:: --key=<KEY>

        The hex encoded key identifier of the router key

.. subcmd:: aspas

Manage the ASPAs of a CA
    
    .. subcmd:: list
    
    Show current ASPAs
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
    .. subcmd:: add
    
    Add or replace an ASPA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --aspa=<ASPA>

        The ASPA formatted like: 65000 => 65001, 65002, 65003
    
    .. subcmd:: remove
    
    Remove the ASPA for a customer ASN
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --customer=<CUSTOMER>

        Customer ASN of the ASPA to remove
    
    .. subcmd:: update
    
    Update an existing ASPA
    
    
    *OPTIONS*
    
        .. option:: -c <CA>, --ca=<CA>

        Name of the CA to control
    
        .. option:: --customer=<CUSTOMER>

        Customer ASN of an existing ASPA
    
        .. option:: --add=<ADD>

        Provider ASN to add
    
        .. option:: --remove=<REMOVE>

        Provider ASN to remove

.. subcmd:: pubserver

Manage the Publication Server
    
    .. subcmd:: publishers
    
    Manage the publishers of the publication server
        
        .. subcmd:: list
        
        List all publishers
        
        .. subcmd:: stale
        
        List all publishers which have not published in a while
        
        
        *OPTIONS*
        
            .. option:: --seconds=<SECONDS>

            Number of seconds since last publication
        
        .. subcmd:: add
        
        Add a publisher
        
        
        *OPTIONS*
        
            .. option:: --request=<REQUEST>

            Path to the RFC 8183 Publisher Request XML file
        
            .. option:: -p <PUBLISHER>, --publisher=<PUBLISHER>

            Override the publisher handle in the XML
        
        .. subcmd:: response
        
        Show RFC 8183 Repository Response XML
        
        
        *OPTIONS*
        
            .. option:: -p <PUBLISHER>, --publisher=<PUBLISHER>

            Name of the publisher
        
        .. subcmd:: show
        
        Show details for a publisher
        
        
        *OPTIONS*
        
            .. option:: -p <PUBLISHER>, --publisher=<PUBLISHER>

            Name of the publisher
        
        .. subcmd:: remove
        
        Remove a publisher
        
        
        *OPTIONS*
        
            .. option:: -p <PUBLISHER>, --publisher=<PUBLISHER>

            Name of the publisher
    
    .. subcmd:: delete
    
    Delete specific files from the publication server
    
    .. subcmd:: server
    
    Manage the publication server
        
        .. subcmd:: init
        
        Initialize the publication server
        
        
        *OPTIONS*
        
            .. option:: --rrdp=<RRDP>

            The RRDP base URI for the repository (excluding notification.xml)
        
            .. option:: --rsync=<RSYNC>

            The rsync base URI for the repository
        
        .. subcmd:: stats
        
        Show publication server statistics
        
        .. subcmd:: session-reset
        
        Reset the RRDP session
        
        .. subcmd:: clear
        
        Clear the publication server so it can re-initialized

.. subcmd:: bulk

Manually trigger refresh/republish/resync for all CAs
    
    .. subcmd:: refresh
    
    Force all CAs to ask their parents for updated certificates
    
    .. subcmd:: publish
    
    Force all CAs to create new objects if needed (in which case they will also sync)
    
    .. subcmd:: sync
    
    Force all CAs to sync with their repo server


See also
--------

**krill**\ (1), **krill.conf**\ (5), **krillta**\ (1), **krillup**\ (1)

