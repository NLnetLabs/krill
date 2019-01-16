[![Travis Build Status](https://api.travis-ci.com/NLnetLabs/krill.svg?branch=master)](https://travis-ci.com/NLnetLabs/krill)
[![Documentation Status](https://readthedocs.org/projects/rpki/badge/?version=latest)](https://rpki.readthedocs.io/en/latest/?badge=latest)


# Krill

Krill is a Resource Public Key Infrastructure (RPKI) daemon, featuring 
a Certificate Authority and Publication Server, written in Rust. 

## Introduction

Krill lets organisations run RPKI on their own systems as a child of one or more Regional Internet Registries (RIRs). It can also run under a different parent, such as a National Internet Registry (NIR) or Enterprise and, in turn, act as a parent for other organisations.

To learn more about Krill and how it can benefit your organisation, please refer to the [NLnet Labs website](https://www.nlnetlabs.nl/projects/rpki/krill/). We wrote a [blog post](https://medium.com/nlnetlabs/krill-a-new-rpki-certificate-authority-a0acb374431f) with background information as well.

## Development

Because we believe in transparent development, this project is public while development is ongoing. We are committed to delivering a basic, production quality implementation of Krill by late 2019, with development continuing to offer a full-featured toolset throughout 2020. If you want to track the progress, learn more about the current status and project planning, please have a look at our 
[milestones](https://github.com/NLnetLabs/krill/milestones?direction=asc&sort=due_date&state=open). 

If you have any questions, comments or ideas, you are welcome
 to discuss them on our [RPKI mailing list](https://nlnetlabs.nl/mailman/listinfo/rpki), or feel 
free to create an issue right here on GitHub.

## Status

The Publication Server of Krill is functional. It means that at this point in time, and until a basic Certificate Authority is implemented, running Krill is interesting mostly for developers.

## Documentation

Background and technical documentation, including how to build and get started, is maintained on [Read the Docs](https://rpki.readthedocs.io/en/latest/krill/index.html).

## License

This software is distributed under the Mozilla Public License 2.0. See the LICENSE file included.
