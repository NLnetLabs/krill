[![GitHub Actions Build Status](https://github.com/NLnetLabs/routinator/workflows/ci/badge.svg)](https://github.com/NLnetLabs/krill/actions?query=workflow%3Aci)
[![Rust Crate Status](https://img.shields.io/crates/v/krill.svg?color=brightgreen)](https://crates.io/crates/krill)
[![Docker Build Status](https://img.shields.io/docker/cloud/build/nlnetlabs/krill.svg)](https://hub.docker.com/r/nlnetlabs/krill)
[![Documentation Status](https://readthedocs.org/projects/rpki/badge/?version=latest)](https://rpki.readthedocs.io/en/latest/?badge=latest)
[![E2E Test Status](https://github.com/nlnetlabs/krill/workflows/E2E%20Test/badge.svg)](https://github.com/NLnetLabs/krill/actions?query=workflow%3A%22E2E+Test%22)
[![](https://img.shields.io/twitter/follow/krillrpki.svg?label=Follow&style=social)](https://twitter.com/krillrpki)

# Krill

Krill is a Resource Public Key Infrastructure (RPKI) daemon, featuring 
a Certificate Authority and Publication Server, written in Rust. 

## Introduction

Krill lets organisations run RPKI on their own systems as a child of one or more Regional Internet Registries (RIRs). It can also run under a different parent, such as a National Internet Registry (NIR) or Enterprise and, in turn, act as a parent for other organisations.

To learn more about Krill and how it can benefit your organisation, please refer to the [NLnet Labs website](https://www.nlnetlabs.nl/projects/rpki/krill/). Extensive documentation on Krill and RPKI technology is available on [Read the Docs](https://rpki.readthedocs.io/). We wrote a [blog post](https://medium.com/nlnetlabs/krill-a-new-rpki-certificate-authority-a0acb374431f) with background information as well.

## Documentation

Background and technical documentation, including how to build and get started, is maintained on [Read the Docs](https://rpki.readthedocs.io/en/latest/krill/index.html).

## Development, features and bugs

Please have a look at the Changelog.md file, our 
[planned releases](https://github.com/NLnetLabs/krill/projects?query=is%3Aopen+sort%3Aname-asc
), and/or [issues](https://github.com/NLnetLabs/krill/issues). 

If you have any questions, comments or ideas, you are welcome
 to discuss them on our [RPKI mailing list](https://lists.nlnetlabs.nl/mailman/listinfo/rpki), or feel 
free to create an issue right here on GitHub.

## License

This software is distributed under the Mozilla Public License 2.0. See the LICENSE file included.
