# RPKI Publication Server

Publication Server for the RPKI

See:
* [RFC8181 Publication Protocol](https://tools.ietf.org/html/rfc8181) 
* [RFC8183 Out-of-Band Setup Protocol](https://tools.ietf.org/html/rfc8183)

## Dev quick start

Install RUST:
```bash
curl https://sh.rustup.rs -sSf | sh
```

Build the binaries:
```bash
cd $project
cargo build
```

To run the publication server with two example clients:
```bash
 ./target/debug/pubd
```

The server should start on localhost and port 3000.

## API

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
request' XML file](https://tools.ietf.org/html/rfc8183#section-5.2.3) to the 
directory defined by the 'pub_xml_dir' setting in the publication server 
configuration (pubserver.conf). The server will scan this directory at start 
up, and add/remove publishers as needed, or update their identity certificate
if needed. It is assumed that the 'publisher_handle' in these XML files is 
unique, and verified.

However, we plan to change this behaviour in the coming weeks in favor of using
the API for updates as well as displaying current state. We will then add a 
function to the CLI for your convenience that will allow you to continue
dropping these XML files in a directory - the CLI will implement the needed 
logic wrapping around the API to ensure that things are then synchronised.


## UI

To add static resources, add to the 'static' folder and include static 
mapping at the end of src/pubd/httpd.rs. You should be able to get to them if
you restart the server.








