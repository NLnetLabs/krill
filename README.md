[![GitHub Actions Build Status](https://github.com/NLnetLabs/routinator/workflows/ci/badge.svg)](https://github.com/NLnetLabs/krill/actions?query=workflow%3Aci)
[![Rust Crate Status](https://img.shields.io/crates/v/krill.svg?color=brightgreen)](https://crates.io/crates/krill)
[![Docker Build Status](https://img.shields.io/docker/cloud/build/nlnetlabs/krill.svg)](https://hub.docker.com/r/nlnetlabs/krill)
[![Documentation Status](https://readthedocs.org/projects/rpki/badge/?version=latest)](https://rpki.readthedocs.io/en/latest/?badge=latest)
[![E2E Test Status](https://github.com/nlnetlabs/krill/workflows/E2E%20Test/badge.svg)](https://github.com/NLnetLabs/krill/actions?query=workflow%3A%22E2E+Test%22)
[![](https://img.shields.io/twitter/follow/krillrpki.svg?label=Follow&style=social)](https://twitter.com/krillrpki)

# Krill

Krill is a Resource Public Key Infrastructure (RPKI) daemon, featuring a
Certificate Authority (CA) and publication server, written in Rust.  If you have
any feedback, we would love to hear from you. Don’t hesitate to [create an issue
on Github](https://github.com/NLnetLabs/krill/issues/new) or post a message on
our [RPKI mailing list](https://lists.nlnetlabs.nl/mailman/listinfo/rpki). You
can lean more about Krill and RPKI technology by reading our documentation on
[Read the Docs](https://rpki.readthedocs.io/).

## Quick Start

Assuming you have a newly installed Debian or Ubuntu machine, you will need to
install the C toolchain, OpenSSL, curl and Rust. You can then install Krill
using Cargo.

After the installation has completed, first create a data directory in a
location of your choice. Next, generate a basic configuration file specifying a
[secret token](https://xkcd.com/936/) and make sure to refer to the data
directory you just created. Finally, start Krill pointing to your configuration
file.

```bash
apt install build-essential libssl-dev openssl pkg-config curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo install krill
mkdir ~/data
krillc config simple --token correct-horse-battery-staple --data ~/data/ > ~/data/krill.conf
krill --config ~/data/krill.conf
```

Krill now exposes its user interface and API on `https://localhost:3000` using a
self-signed TLS certificate. You can go to this address in a web browser, accept
the certificate warning and start configuring your RPKI Certificate Authority. A
Prometheus endpoint is available at `/metrics`.

If you have an older version of Rust and Krill, you can update via:

```bash
rustup update
cargo install -f krill
```

If you want to try the master branch from the repository instead of a release
version, you can run:

```bash
cargo install --git https://github.com/NLnetLabs/krill.git
```

## Introduction

The Resource Public Key Infrastructure provides cryptographically signed
statements about the association of Internet routing resources. In
particular, it allows the holder of an IP address prefix to publish which
AS number will be the origin of BGP route announcements for it.

Krill lets organisations run RPKI on their own systems as a child of one or more
Regional Internet Registries (RIRs). It can also run under a different parent,
such as a National Internet Registry (NIR) or Enterprise and, in turn, act as a
parent for other organisations.

## System Requirements

The system requirements for Krill are quite minimal. We have successfully tested
it on a Raspberry Pi. Any dual core machine with 2GB RAM will suffice, as the
cryptographic operations that need to be performed by the Certificate Authority
have a negligible performance and memory impact on any modern day machine.

When you publish ROAs yourself using the Krill publication server in combination
with Rsyncd and a web server of your choice, you will see traffic from several
hundred relying party software tools querying every few minutes. The total
amount of traffic is also negligible for any modern day situation.

## Getting Started

There are three things you need for Krill: Rust, a C toolchain and OpenSSL. You
can install Krill on any Operating System where you can fulfil these
requirements, but we will assume that you will run this on a UNIX-like OS.

### Rust

The Rust compiler runs on, and compiles to, a great number of platforms.
The official [Rust Platform Support](https://forge.rust-lang.org/platform-support.html)
page provides an overview of the various platforms and support levels.

While some system distributions include Rust as system packages,
Krill relies on a relatively new version of Rust, currently 1.34 or
newer. We therefore suggest to use the canonical Rust installation via a
tool called ``rustup``.

To install ``rustup`` and Rust, simply do:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

or, alternatively, get the file, have a look and then run it manually.
Follow the instructions to get rustup and cargo, the rust build tool, into
your path.

You can update your Rust installation later by simply running

```bash
rustup update
```

To get started you need Cargo's bin directory ($HOME/.cargo/bin) in your PATH
environment variable. To configure your current shell, run

```bash
source $HOME/.cargo/env
```

### C Toolchain

Some of the libraries Krill depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum
set of packages to build from C sources. For example, `apt install
build-essential` will install everything you need on Debian/Ubuntu.

If you are unsure, try to run `cc` on a command line and if there’s a
complaint about missing input files, you are probably good to go.

### OpenSSL

Your system will likely have a package manager that will allow you to install
OpenSSL in a few easy steps. For Krill, you will need `libssl-dev`, sometimes
called `openssl-dev`. On Debian-like Linux distributions, this should be as
simple as running:

```bash
apt install libssl-dev openssl pkg-config
```

## Building

The easiest way to get Krill is to leave it to cargo by saying

```bash
cargo install krill
```

If you want to try the master branch from the repository instead of a
release version, you can run

```bash
cargo install --git https://github.com/NLnetLabs/krill.git
```

If you want to update an installed version, you run the same command but
add the `-f` flag (aka force) to approve overwriting the installed
version.

The command will build Krill and install it in the same directory
that cargo itself lives in (likely `$HOME/.cargo/bin`).
Which means Krill will be in your path, too.

## Configuration

The first step is to choose where your data directory is going to live and to
create it. Krill can then generate a basic configuration file for you, which
only have two required directives: a secret token and the path to the data
directory.

```bash
mkdir ~/data
krillc config simple --token correct-horse-battery-staple --data ~/data/ > ~/data/krill.conf
```

You can find a full example configuration file with defaults in the
[repository](defaults/krill.conf).

## Start and Stop the Daemon

There is currently no standard script to start and stop Krill. You could use the
following example script to start Krill. Make sure to update the `DATA_DIR`
variable to your real data directory, and make sure you saved your `krill.conf`
file there.

```bash
#!/bin/bash
KRILL="krill"
DATA_DIR="/path/to/data"
KRILL_PID="$DATA_DIR/krill.pid"
CONF="$DATA_DIR/krill.conf"
SCRIPT_OUT="$DATA_DIR/krill.log"

nohup $KRILL -c $CONF >$SCRIPT_OUT 2>&1 &
echo $! > $KRILL_PID
```

You can use the following sample script to stop Krill:

```bash
#!/bin/bash
DATA_DIR="/path/to/data"
KRILL_PID="$DATA_DIR/krill.pid"

kill `cat $KRILL_PID`
```

### Proxy and HTTPS

Krill uses HTTPS and refuses to do plain HTTP. By default Krill will generate a
2048 bit RSA key and self-signed certificate in `/ssl` in the data directory
when it is first started. Replacing the self-signed certificate with a TLS
certificate issued by a CA works, but has not been tested extensively.

For a robust solution, we recommend that you use a proxy server such as Nginx or
Apache if you intend to make Krill available to the Internet. Also, setting up a
widely accepted TLS certificate is well documented for these servers.

We recommend that you do not make Krill available publicly. You can use the
default where Krill will expose its CLI, API and UI on `https://localhost:3000/`
only. You do not need to have Krill available externally, unless you intend to
provide certificates or a publication server to third parties.

### Using the UI, CLI and API

There are three ways to interact with Krill: a user interface (UI), a command
line interface (CLI) and and application programming interface (API). For most
scenarios, the UI will be the most convenient way to interact with Krill. 

![Krill Welcome page](https://rpki.readthedocs.io/en/latest/_images/krill-ui-welome.png)

Please
refer to the
[documentation](https://rpki.readthedocs.io/en/latest/krill/index.html) to
determine what is best for you.
