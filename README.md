# Krill

Krill is a Resource Public Key Infrastructure (RPKI) daemon, featuring 
a Certificate Authority and Publication Server, written in Rust. 

If you want to know more about the project planning, please have a look at the
high level [roadmap](https://nlnetlabs.nl/projects/rpki/project-plan/) on
our website, or get at a more detailed overview of the 
[milestones](https://github.com/NLnetLabs/krill/milestones?direction=asc&sort=due_date&state=open)
here on GitHub. If you have any questions, comments or ideas, you are welcome
 to discuss them
on our [RPKI mailing list](https://nlnetlabs.nl/mailman/listinfo/rpki), or feel 
free to create an issue right here on GitHub.

## RPKI

The Resource Public Key Infrastructure provides cryptographically signed
statements about the association of Internet routing resources. In
particular, it allows the holder of an IP address prefix to publish which
AS number will be the origin of BGP route announcements for it. 

For more information on this technology, please refer to our [RPKI FAQ](https://github.com/NLnetLabs/rpki-faq).

## Krill - Publication Server

Krill features a Publication Server for the RPKI, allowing RPKI Certificate 
Authorities to publish their signed data, so that it can be retrieved and 
validated by RPKI Validators, such as the [Routinator](https://github.com/nlnetlabs/routinator). 

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

We plan to have an initial version implemented around the third 
quarter of 2019. After this we look at more advanced features, 
robustness improvements, and more...


## Quick start

At this point in time, and until a basic Certificate Authority is 
implemented, running Krill is interesting mostly for developers. This means the 
following instructions are somewhat developer centric.

We will do proper packaging and a Docker image in the future, but for now you 
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

After these steps, edit your `krill.conf` file and, at least, set a secret 
token for the `auth_token` key, at the end of the file — or — set the 
KRILL_AUTH_TOKEN environment variable when you start `krilld`. Other than 
that the defaults should be okay for local testing.

#### Run

To run the publication server with two example clients:
```bash
 ./target/debug/krilld -c ./data/krill.conf
```

The server should start on localhost and port 3000. If you want to use a 
different configuration, please review the config file (./defaults/krill.conf). 
Alternatively, you can use the `-c` option to specify another config file.



# API

This application uses a JSON based REST (in the non-religious interpretation)
API for managing all administrative tasks, such as managing the configured
publishers.

## General

The UI (to be) and CLI use this API exclusively, i.e. there are no back doors
being used. You can, of course, use this API directly from your own 
applications, or wrap things in your own UI if you want.

The API path includes a version. The idea is that we may add functionality, but
will not introduce breaking changes to existing functionality. You may expect
additional resources, and you may see additional data (json members) within 
resources. So, please make sure that you ignore what you don't understand 
when using this API.

The base uri for the API is:
http://localhost:3000/api/v1/

*NOTE:* Calls to the API have to include the api token as an [OAuth 2.0 
Bearer token](https://tools.ietf.org/html/rfc6750#section-2.1) as a header, e.g.:
```
Authorization: Bearer secret
```

## Error Responses

The API may have to return errors. When this happens the generic response 
will have an HTTP status code, and include a json message with the following 
generic structure:
```
{ "code": <int>, "msg": "Specific error message"}
```

There are three categories of errors, each with their own HTTP status code, 
and range of error codes:

| Category      | Code Range | HTTP  |
| ------------- | --------- | ----- |
| User Input    | 1000-1999 | 400   |
| Authorisation | 2000-2999 | 403   |
| Server Error  | 3000-3999 | 500   |

Note however that this applies only the "admin" API. The [publication 
procotol](https://tools.ietf.org/html/rfc8183), and (in future) [provisioning 
protocol](https://tools.ietf.org/html/rfc6492), have their own defined ways 
of dealing with errors. 

We will discuss all the API calls below, and we will mention which errors may
be expected for each.

## Krill - Command Line Interface

There is a command line interface (CLI) shipping with Krill for Krill admin 
tasks. This CLI provides a simple wrapper around the API. It does not use any
back doors. It may be more convenient that calling the API directly from your
favourite scripting language, but maybe even more importantly: it allows us 
to set up integration and regression testing when building this software.  
 
The binary is built as part of the normal 'cargo build' process, and can be 
used by running:
```bash
./target/debug krillc
```

To get an overview of all supported options run:
```bash
./target/debug krillc --help
```

Which will print something like this:
```bash
Krill admin client 0.2.0

USAGE:
    krillc [OPTIONS] --server <URI> --token <token-string> [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f, --format <type>           Specify the report format (none|json|text|xml). If left unspecified the format will
                                  match the corresponding server api response type.
    -s, --server <URI>            Specify the full URI to the krill server.
    -t, --token <token-string>    Specify the value of an admin token.

SUBCOMMANDS:
    health        Perform a health check. Exits with exit code 0 if all is well, exit code 1 in case of any issues
    help          Prints this message or the help of the given subcommand(s)
    publishers    Manage publishers

```

We will include an example CLI call wherever we document an API end-point.

## API End Points

### Health Check

#### Path

```
/api/v1/health
```

#### Success Reply

HTTP code 200, empty body

#### Possible Error Replies

| http | body | description  |
| -----| ---- | ------------ |
| 403  | -    | Forbidden (wrong token) |
| 500  | json | Some server issue       |    

#### CLI Example

```bash
krillc --server http://localhost:3000/ --token secret health
```

The exit code will be 0 if everything is okay, or 1 otherwise. There is no 
text output, except when errors occur.

### Publishers

Publishers are entities who are allowed to publish content using this 
publication server, as described in RFC 8181. Typically publishers will be 
RPKI Certificate  Authorities, however we also include a `pubc` binary that can
act as a publisher, and that can synchronise any arbitrary directory with the
publication server.

The following 'publishers' end points are defined:

| Resource                       | Method   | Action                          |
| ------------------------------ | -------- | ------------------------------- |
| /api/v1/publishers             | GET  | List all current publishers |
| /api/v1/publishers                    | POST | Submit a new [publisher request](https://tools.ietf.org/html/rfc8183#section-5.2.3)| 
| /api/v1/publishers/{handle}           | GET  | Show publisher details   |
| /api/v1//publishers/{handle}/id.cer    | GET  | Get publisher id certificate |
| /api/v1//publishers/{handle}/response.xml  | GET | Get [repository response.xml](https://tools.ietf.org/html/rfc8183#section-5.2.4)|

#### List Publishers

##### Path

```
/api/v1/publishers (GET)
```

#### Success Reply Example

```json
{
  "publishers": [
    {
      "id": "alice",
      "links": [
        {
          "rel": "response.xml",
          "link": "\/api\/v1\/publishers\/alice\/response.xml"
        },
        {
          "rel": "self",
          "link": "\/api\/v1\/publishers\/alice"
        }
      ]
    }
  ]
}
```

#### Possible Error Replies

| http | body | description  |
| -----| ---- | ------------ |
| 403  | -    | Forbidden (wrong token) |
| 500  | json | Some server issue       |

#### CLI Example
```
krillc --server http://localhost:3000/ --token secret publishers list
```

#### Add a Publisher

##### Path

```
/api/v1/publishers (POST)
```

Post body: ['publisher request' XML file'](https://tools.ietf.org/html/rfc8183#section-5.2.3)

##### Success Response

200 OK, empty body

##### Possible Error Replies

| http | body | description  |
| -----| ---- | ------------ |
| 400  | json | Issue with input        |
| 403  | -    | Forbidden (wrong token) |
| 500  | json | Some server issue       |

For the 400 errors you can expect the following error messages:

| Code  | Description                          |  Code Module          |
| ----- | ------------------------------------ | --------------------- |
| 1002  | Invalid RFC8183 Publisher Request    | PublisherRequestError |
| 1004  | Forward slash in publisher handle    | publishers::Error::ForwardSlashInHandle  |
| 1005  | Duplicate publisher handle           | publishers::Error::DuplicatePublisher  |

##### CLI Example

```
krillc --server http://localhost:3000/ --token secret publishers add --xml work/tmp/alice.xml
```

### Publisher Details

#### Path
```
/api/v1/publishers/{handle} (GET)  
```

#### Success Reply Example

TODO

#### Possible Error Replies

| http | body | description  |
| -----| ---- | ------------ |
| 403  | -    | Forbidden (wrong token) |
| 404  | -    | Unknown Publisher       |
| 500  | json | Some server issue       |

#### CLI Example

TODO

### Publisher Identity Certificate

#### Path

```
/api/v1//publishers/{handle}/id.cer  (GET)  
```

#### Success Reply

The X509 Identity Certificate this publisher uses to sign CMS messages used 
in the publication and provisioning protocol.

#### Possible Error Replies

| http | body | description  |
| -----| ---- | ------------ |
| 403  | -    | Forbidden (wrong token) |
| 404  | -    | Unknown Publisher       |
| 500  | json | Some server issue       |

#### CLI Example

TODO

### Publisher Response

Gets the [repository response.xml](https://tools.ietf.org/html/rfc8183#section-5.2.4)
for the specified publisher.

#### Path

```
/api/v1/publishers/{handle}/response.xml
```

#### Success Reply Example

TODO

#### Possible Error Replies

| http | body | description  |
| -----| ---- | ------------ |
| 403  | -    | Forbidden (wrong token) |
| 404  | -    | Unknown Publisher       |
| 500  | json | Some server issue       |

#### CLI Example

TODO

##### Appendix - Overview of API Errors

##### User Input Codes

The following user input errors may be returned:

| Code  | Description                          |  Code Module          |
| ----- | ------------------------------------ | --------------------- |
| 1001  | Submitted Json cannot be parsed      | serde_json::Error     |
| 1002  | Invalid RFC8183 Publisher Request    | PublisherRequestError |
| 1003  | Issue with submitted publication XML | pubmsg::MessageError  |
| 1004  | Forward slash in publisher handle    | publishers::Error::ForwardSlashInHandle  |
| 1005  | Duplicate publisher handle           | publishers::Error::DuplicatePublisher  |
| 1006  | Unknown publisher                    | publishers::Error::UnknownPublisher  |

##### Authorisation Codes

The following authorisation errors may be returned:

| Code  | Description                                |  Code Module          |
| ----- | ------------------------------------------ | --------------------- |
| 2001  | Submitted protocol CMS does not validate   | pubserver::Error::ValidationError     |


##### Server Error Codes

The following server errors may be returned. These errors indicate that there
 is a bug, or operational issue (e.g. a disk cannot be written to) at the 
 server side.

| Code  | Description                                |  Code Module          |
| ----- | ------------------------------------------ | --------------------- |
| 3001  | Issue with storing/retrieving publisher    | pubserver::Error::PublisherStoreError     |
| 3002  | Issue with updating repository             | pubserver::Error::RepositoryError     |
| 3003  | Issue with signing response CMS            | pubserver::Error::ResponderError     |





