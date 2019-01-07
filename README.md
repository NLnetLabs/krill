# Krill

Krill is an RPKI daemon that is being developed by NLnet Labs.

If you want to know more about the project planning, have a look at the
high level [roadmap](https://nlnetlabs.nl/projects/rpki/project-plan/) on
our website, or get at a more detailed overview of
[milestones](https://github.com/NLnetLabs/krill/milestones?direction=asc&sort=due_date&state=open)
here on GitHub. If you have any questions, comments or ideas, you are welcome
 to discuss them
on the [mailing list](https://nlnetlabs.nl/mailman/listinfo/rpki), or feel 
free to create an issue right here on GitHub.


## Krill - Publication Server

Krill features a Publication Server for the RPKI, allowing RPKI Certificate 
Authorities to publish their signed data, so that it can be retrieved and 
validated by RPKI Validators, such as [routinator](https://github.com/nlnetlabs/routinator). 

The publication server is functional and conforms with the IETF standards, 
most notably:
* [RFC8181 Publication Protocol](https://tools.ietf.org/html/rfc8181) 
* [RFC8183 Out-of-Band Setup Protocol](https://tools.ietf.org/html/rfc8183)

This project also includes a publication client utility that can be used to 
synchronise the contents of any directory with a publication server.

## Krill - Certificate Authority

Krill will feature an RPKI Certificate Authority which can:
* Publish using the built-in Publication Server, or a remote server.
* Operate under multiple parents, using the [provisioning protocol](https://tools.ietf.org/html/rfc6492)
* Delegate certificates to multiple children, using the [provisioning protocol](https://tools.ietf.org/html/rfc6492)
* Issue ROAs based on an operators intent to authorise BGP announcements

We hope to have a beta version of all this implemented around the third 
quarter of 2019. After which we will be looking at more advanced features, 
and e.g. robustness improvements. 


## Quick start

At this point in time, and until a basic Certificate Authority is 
implemented, running Krill is interesting mostly for developers. So, the 
following instructions are somewhat developer centric.

We will do proper packaging, and a docker image, in future, but for now you 
will need to check out the (Rust) source code and compile a binary locally:

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

#### Make work directory and configure

```bash
mkdir data
mkdir publishers
cp defaults/krill.conf ./data
```

Then edit your 'krill.conf' file and, at least, set a secret token for the 
'auth_token' key, at the end of the file -- or -- set the KRILL_AUTH_TOKEN 
environment variable when you start 'krilld'. Other than that the defaults 
should be okay for local testing.

#### Run

To run the publication server with two example clients:
```bash
 ./target/debug/krilld -c ./data/krill.conf
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

NOTE: Calls to the API have to include the api token as an [OAuth 2.0 
Bearer token](https://tools.ietf.org/html/rfc6750#section-2.1) as a header, e.g.:

    Authorization: Bearer secret

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
| /publishers/{handle}           | Get      | Show publisher details          |
| /publishers/{handle}/id.cer    | Get      | Get publisher id certificate    |
| /publishers/{handle}/response.xml  | Get      | Get [repository response xml](https://tools.ietf.org/html/rfc8183#section-5.2.4)|
 
Example call:
```bash
curl -H "Authorization: Bearer secret" http://localhost:3000/api/v1/publishers
```


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









