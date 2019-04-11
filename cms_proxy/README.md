# Krill CMS Proxy

The communication protocols between a child and parent CA (RFC 6492), and
a publishing CA and a publication server (RFC8181) are both based on XML
messages which are wrapped in (signed) CMS objects. The exchange of identity
certificates used in these protocols is defined in RFC8183.

This module provides, and localizes, support for all this, so that the
core Krill code can be less complex. The 'native' Krill API relies on JSON
over HTTPS, using OAuth-v2 like "Bearer" tokens for authorisation. We may
seek standardisation of this in future.

That said, the Krill binary supports both the official and the 'native'
protocols. In future we may decide to extract support for the XML-CMS protocols
into a stand-alone proxy - dependent on what we will learn from operations.

## License

This software is distributed under the Mozilla Public License 2.0. See the LICENSE file included.
