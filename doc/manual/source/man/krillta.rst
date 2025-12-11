Krill trust anchor man page
===========================

Synopsis
--------

.. code-block:: bash

:program:`krillta` ``SUBCOMMAND`` [``options``]

Description
-----------

The krillta tool is used for managing a Krill based RPKI Trust Anchor.

Subcommands
-----------


.. subcmd:: proxy

Manage the Trust Anchor Proxy
    
    .. subcmd:: init
    
    Initialise the proxy
    
    .. subcmd:: id
    
    Get the proxy ID certificate details
    
    .. subcmd:: repo
    
    Manage the repository for proxy
        
        .. subcmd:: request
        
        Get RFC 8183 publisher request
        
        .. subcmd:: contact
        
        Show the configured repository for the proxy
        
        .. subcmd:: configure
        
        Configure (add) the repository for the proxy
        
        
        *OPTIONS*
        
            .. option:: -r <RESPONSE>, --response=<RESPONSE>

            Path to the Publisher Response XML file
    
    .. subcmd:: signer
    
    Manage interactions with the associated signer
        
        .. subcmd:: init
        
        Initialise signer association
        
        
        *OPTIONS*
        
            .. option:: -i <INFO>, --info=<INFO>

            Path to the the Trust Anchor Signer info file (as 'signer show')
        
        .. subcmd:: update
        
        Update signer association
        
        
        *OPTIONS*
        
            .. option:: -i <INFO>, --info=<INFO>

            Path to the the Trust Anchor Signer info file (as 'signer show')
        
        .. subcmd:: make-request
        
        Make a NEW request for the signer (fails if a request exists)
        
        .. subcmd:: show-request
        
        Show existing request for the signer (fails if there is no request)
        
        .. subcmd:: process-response
        
        Process a response from the signer. Fails it not for the open request
        
        
        *OPTIONS*
        
            .. option:: -r <RESPONSE>, --response=<RESPONSE>

            Path to the the Trust Anchor Signer info file (as 'signer show')
    
    .. subcmd:: children
    
    Manage children under the TA proxy
        
        .. subcmd:: add
        
        Add a child
        
        
        *OPTIONS*
        
            .. option:: -i <INFO>, --info=<INFO>

            Path to the child info JSON (from krillc show)
        
            .. option:: -a <ASN>, --asn=<ASN>

            The ASN resources for the child
        
            .. option:: -4 <IPV4>, --ipv4=<IPV4>

            The IPv4 resources for the child
        
            .. option:: -6 <IPV6>, --ipv6=<IPV6>

            The IPv6 resources for the child
        
        .. subcmd:: response
        
        Get parent response for child
        
        
        *OPTIONS*
        
            .. option:: --child=<CHILD>

            Name of the child CA


*OPTIONS*

    .. option:: -s <SERVER>, --server=<SERVER>

    The full URI to the Krill server

    .. option:: -t <TOKEN>, --token=<TOKEN>

    The secret token for the Krill server

    .. option:: -f <FORMAT>, --format=<FORMAT>

    Report format

    .. option:: --api=<API>

    Only show the API call and exit

.. subcmd:: signer

Manage the Trust Anchor Signer
    
    .. subcmd:: init
    
    Initialise the signer
    
    
    *OPTIONS*
    
        .. option:: -i <PROXY_ID>, --proxy-id=<PROXY_ID>

        Path to the proxy ID JSON file
    
        .. option:: -r <PROXY_REPOSITORY_CONTACT>, --proxy-repository-contact=<PROXY_REPOSITORY_CONTACT>

        Path to the proxy repository contact JSON file
    
        .. option:: --tal-rsync=<TAL_RSYNC>

        The rsync URI used for TA certificate on TAL and AIA
    
        .. option:: --tal-https=<TAL_HTTPS>

        The HTTPS URI used for the TAL
    
        .. option:: --private-key-pem=<PRIVATE_KEY_PEM>

        Import an existing private key in PEM format
    
        .. option:: --initial-manifest-number=<INITIAL_MANIFEST_NUMBER>

        Set the initial manifest number
    
    .. subcmd:: reissue
    
    Reissue the TA certificate
    
    
    *OPTIONS*
    
        .. option:: -i <PROXY_ID>, --proxy-id=<PROXY_ID>

        Path to the proxy ID JSON file
    
        .. option:: -r <PROXY_REPOSITORY_CONTACT>, --proxy-repository-contact=<PROXY_REPOSITORY_CONTACT>

        Path to the proxy repository contact JSON file
    
        .. option:: --tal-rsync=<TAL_RSYNC>

        The rsync URI used for TA certificate on TAL and AIA
    
        .. option:: --tal-https=<TAL_HTTPS>

        The HTTPS URI used for the TAL
    
    .. subcmd:: show
    
    Show the signer info
    
    .. subcmd:: process
    
    Process a proxy request
    
    
    *OPTIONS*
    
        .. option:: -r <REQUEST>, --request=<REQUEST>

        Path to TA proxy request JSON file
    
        .. option:: --ta-mft-number-override=<TA_MFT_NUMBER_OVERRIDE>

        Override the next manifest number
    
    .. subcmd:: last
    
    Show last response
    
    .. subcmd:: exchanges
    
    Show full history of proxy signer exchanges


*OPTIONS*

    .. option:: -c <CONFIG>, --config=<CONFIG>

    Path to config file

    .. option:: -f <FORMAT>, --format=<FORMAT>

    Report format


See also
--------

**krill**\ (1), **krill.conf**\ (5), **krillc**\ (1), **krillup**\ (1)

