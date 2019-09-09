# Change Log

## Unreleased features and issues

Please see [here](https://github.com/NLnetLabs/krill/projects?query=is%3Aopen+sort%3Aname-asc)
for planned releases. 

## 0.1.0 'A View to a Krill'

This is the first version of Krill that we are testing in the real world. Please note that the
API and data structures have not yet stabilized. 

Features:
* Run an embedded Trust Anchor for testing purposes
* Run a CA under an embedded Trust Anchor
* Run a CA under APNIC (Lacnic, RIPE NCC and other remote parents coming soon)
* Have multiple parent CAs for one logical CA
* Have multiple child CAs, embedded or remote
* Create ROAs based on intent
* Publish locally
* API and CLI

Known issues:
* Krill does not handle concurrent updates well. See this [issue](https://github.com/NLnetLabs/krill/issues/64).
* The UI is very basic and behind the CLI.
