# Krill

Krill is an RPKI daemon that is being developed by NLnet Labs.

At the moment it only features an RPKI Publication Server, and a 
publication client, but developing a full fledged RPKI Certificate Authority 
(CA) is next on the [roadmap](https://nlnetlabs.nl/projects/rpki/project-plan/).

We just started with the publication server, because:
* It's a prerequisite to running an RPKI CA, to have somewhere to publish
* It's a simpler challenge to start with, and because of the technical overlap, e.g. certificate signing, signing and validating CMS messages, starting and configuring a daemon and what not, provides a good basis implementing the CA.

Incidentally, Krill is what feeds the world's largest filter feeders. It's also 
mostly crustaceans. So, it's kind of fitting for a daemon that produces data for BGP 
filters, which happens to be written in Rust.

## Krill - Publication Server

Krill features a Publication Server for the RPKI, and conforms with IETF 
standards, most notably:
* [RFC8181 Publication Protocol](https://tools.ietf.org/html/rfc8181) 
* [RFC8183 Out-of-Band Setup Protocol](https://tools.ietf.org/html/rfc8183)

## Krill - Certificate Authority

Krill will feature an RPKI Certificate Authority which can:
* Publish using the built-in Publication Server, or a remote server.
* Operate under multiple parents, using the [provisioning protocol](https://tools.ietf.org/html/rfc6492)
* Delegate certificates to multiple children, using the [provisioning protocol](https://tools.ietf.org/html/rfc6492)
* Issue ROAs based on an operators intent to authorise BGP announcements

We hope to have a beta version of all this implemented around the third 
quarter of 2019. After which we will be looking at more advanced features, 
and e.g. robustness improvements. 

Please watch the [road map](https://nlnetlabs.nl/projects/rpki/project-plan/)
, [issues](https://github.com/NLnetLabs/krill/issues) and 
[milestones](https://github.com/NLnetLabs/krill/milestones?direction=asc&sort=due_date&state=open),
and feel free to create issues if you have any feature requests!

Please keep in mind that neither the road map, nor the milestones are cast in
stone. They give an indication to the planned work, and some idea of when 
thins will be delivered, but features may still be added, or removed and 
priorities may change. We plan to update the information if and when this 
happens.


## Quick start

At this point in time, and until a basic Certificate Authority is 
implemented, running Krill is interesting mostly for developers. So, the 
following instructions are somewhat developer centric.

That said, anyone who is interested is welcome to play around with this 
software as we are developing in it. And, yes, in future we will have more 
operator centric documentation, and we also have easier ways to install that 
do not require compiling the code (packages and/or docker).

For now though follow these steps:

#### Install RUST:
```bash
curl https://sh.rustup.rs -sSf | sh
```

#### Clone the repository

```
git clone git@github.com:NLnetLabs/krill.git
```

#### Build the binaries:
```bash
cd $project
cargo build
```

#### Run

To run the publication server with two example clients:
```bash
 ./target/debug/krilld
```

The server should start on localhost and port 3000. If you want to use a 
different configuration, please review the config file (./defaults/krill
.conf). Or use the '-c' option to specify another config file.

### API

This application uses a Json based REST (in the non-religious interpretation)
API for managing all administrative tasks, such as managing the configured
publishers.

The UI and CLI (to be) included with this application (will) use this API 
exclusively, i.e. there are no back doors being used. You can, of course, use
this API directly from your own applications, or wrap things in your own UI 
if you want.

The API path includes a version. The idea is that we may add functionality, but
will not introduce breaking changes to existing functionality. You may expect
additional resources, and you may see additional data (json members) within 
resources. So, please make sure that you ignore what you don't understand 
when using this API.

The base uri for the API is:
http://localhost:3000/api/v1/

### Publishers

Publishers are entities who are allowed to publish content using this 
publication server, as described in RFC 8181. Typically publishers will be 
RPKI Certificate  Authorities, however we also include a 'pubc' binary that can
act as a publisher, and that can synchronise any arbitrary directory with the
publication server.

Currently we only provide an API for view the current state:

| Resource                       | Method   | Action                          |
| ------------------------------ | -------- | ------------------------------- |
| /publishers                    | Get      | List all current publishers     |
| /publishers/{handle}           | Get      | Show publisher details           |
| /publishers/{handle}/id.cer    | Get      | Get publisher id certificate    |
| /publishers/{handle}/response.xml  | Get      | Get [repository response xml](https://tools.ietf.org/html/rfc8183#section-5.2.4)|
 

For the moment publishers are configured by adding the publisher's ['publisher 
request' XML file'](https://tools.ietf.org/html/rfc8183#section-5.2.3) to the 
directory defined by the 'pub_xml_dir' setting in the publication server 
configuration (krill.conf). The server will scan this directory at start 
up, and add/remove publishers as needed, or update their identity certificate
if needed. It is assumed that the 'publisher_handle' in these XML files is 
unique, and verified.

However, we plan to change this behaviour in the coming weeks in favor of using
the API for updates as well as displaying current state. We will then add a 
function to the CLI for your convenience that will allow you to continue
dropping these XML files in a directory - the CLI will implement the needed 
logic wrapping around the API to ensure that things are then synchronised.









