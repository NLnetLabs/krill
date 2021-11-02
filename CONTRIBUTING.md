# Contributing to Krill

First off, thanks for taking the time to contribute! 🦐

This document is offers guidelines on how to best contribute to Krill, whether
it being new features or correcting flaws or bugs.

## Code of Conduct

This project and everyone participating in it is governed by the [NLnet Labs
Code of Conduct](https://www.nlnetlabs.nl/conduct/). By participating, you are
expected to uphold this code. 

## Learning RPKI

Krill is a Resource Public Key Infrastructure (RPKI) daemon, featuring a
Certificate Authority (CA) and publication server. It is based on open standards
developed in the Internet Engineering Task Force (IETF). 

Most of the original work on RPKI standardisation for both origin and path
validation was done in the Secure Inter-Domain Routing
([sidr](https://datatracker.ietf.org/wg/sidr/about/)) working group. After the
work was completed, the working group was concluded. Since then, the SIDR
Operations ([sidrops](https://datatracker.ietf.org/wg/sidrops/about/)) working
group was formed. This working group develops guidelines for the operation of
SIDR-aware networks, and provides operational guidance on how to deploy and
operate SIDR technologies in existing and new networks.

There are more than 40 RFCs about RPKI. You don't need to know all of by heart
to provide a meaningful contribution to Krill, but we feel it's good to
have some reference and context. The [MANRS](https://www.manrs.org/) initiative
has made an [easy to use tool](http://rpki-rfc.routingsecurity.net/) to view all
the relevant RFCs, and how they are related. 

## Learning Krill

### Join the Community

We invite you to join the [RPKI mailing
list](https://lists.nlnetlabs.nl/mailman/listinfo/rpki) and/or [Discord
server](https://discord.gg/8dvKB5Ykhy). Please don't open a GitHub issue for a
question. Instead, follow the discussion on the mailing list and Discord and ask
questions there before you start sending patches. We prefer public discussions
over private ones, so everyone in the community can participate and learn.

### License and copyright

When contributing with code, you agree to put your changes and new code under
the same license Krill and its associated libraries is already using.
When changing existing source code, do not alter the copyright of the original
file(s). The copyright will still be owned by the original creator(s) or those
who have been assigned copyright by the original author(s).

By submitting a patch to the Krill project, you are assumed to have the
right to the code and to be allowed by your employer or whatever to hand over
that patch/code to us. We will credit you for your changes as far as possible,
to give credit but also to keep a trace back to who made what changes.  

### What To Read

The source code, documentation, man page, [change
log](https://github.com/NLnetLabs/krill/blob/main/Changelog.md) and the
[most recent changes](https://github.com/NLnetLabs/krill/commits/main) in
git.

### Documentation

We know how painful it is to write good documentation. We went through great
lengths to write a proper [user manual](https://krill.docs.nlnetlabs.nl/)
for Krill. This documentation is edited via text files in the
[reStructuredText](http://www.sphinx-doc.org/en/stable/rest.html) markup
language and then compiled into a static website/offline document using the open
source [Sphinx](http://www.sphinx-doc.org) and
[ReadTheDocs](https://readthedocs.org/) tools. You can contribute to the
Krill user manual by sending patches via pull requests on the
[krill-manual](https://github.com/NLnetLabs/krill-manual) GitHub
source repository. 

You can contribute to the [man
page](https://github.com/NLnetLabs/krill/blob/main/doc/krill.1) by
sending nroff formatted patches.

## Sharing Your Changes

We would like you to submit a [pull request on
GitHub](https://github.com/NLnetLabs/krill/pulls). Please note that you can
create a draft pull request to indicate that you're still working on something
but still share it with the maintainers to get some early feedback.

Once final, your change will be reviewed and discussed on GitHub. You will be
expected to correct flaws pointed out and update accordingly. As a submitter of
a change, you are the owner of that change until it has been merged.
